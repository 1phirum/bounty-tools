use bugtools_core::http::{HttpRequest, HttpResponse};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use thiserror::Error;
use uuid::Uuid;

/// Query parameters whose values change per request (CSRF tokens,
/// nonces, cache busters) — excluded from request fingerprints so
/// repeated hits on the same logical endpoint dedupe correctly.
pub const VOLATILE_PARAMS: &[&str] = &["csrf", "csrf_token", "csrfmiddlewaretoken", "_", "nonce", "timestamp", "ts"];

#[derive(Debug, Error)]
pub enum TrafficStoreError {
    #[error("Entry not found: {0}")]
    EntryNotFound(Uuid),
}

/// A captured request/response exchange, ready for the traffic table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficEntry {
    pub id: Uuid,
    pub request: HttpRequest,
    pub response: Option<HttpResponse>,
    pub captured_at: chrono::DateTime<Utc>,
    /// SHA-256 over method|host|path|sorted-non-volatile-query-keys.
    pub fingerprint: String,
    /// Origin of the exchange: proxy capture, repeater replay, or fuzzer run.
    pub source: TrafficSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficSource {
    Proxy,
    Repeater,
    Fuzzer,
}

/// Bounded in-memory traffic ring buffer with exact-duplicate suppression.
///
/// Complements SQLite persistence (bugtools-storage): the UI reads pages
/// from this buffer for instant, lock-free-ish access to recent traffic,
/// while the database remains the durable audit trail.
#[derive(Debug)]
pub struct TrafficStore {
    capacity: usize,
    inner: Mutex<TrafficInner>,
}

#[derive(Debug)]
struct TrafficInner {
    entries: Vec<TrafficEntry>,
    /// id -> index into entries (rebuilt lazily after eviction shift).
    index: HashMap<Uuid, usize>,
    seen_fingerprints: HashSet<String>,
    evicted: usize,
}

impl TrafficStore {
    /// Panics if capacity is zero — a store that can hold nothing is a
    /// configuration bug, not a runtime condition.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "traffic store capacity must be positive");
        Self {
            capacity,
            inner: Mutex::new(TrafficInner {
                entries: Vec::new(),
                index: HashMap::new(),
                seen_fingerprints: HashSet::new(),
                evicted: 0,
            }),
        }
    }

    /// Fingerprint a request: method + host + path + sorted query keys,
    /// ignoring volatile parameter names. Deterministic across calls.
    pub fn fingerprint_request(req: &HttpRequest) -> String {
        use sha2::{Digest, Sha256};

        let parsed = match url::Url::parse(&req.url) {
            Ok(u) => u,
            Err(_) => {
                // Unparseable URL: fall back to hashing the raw string so
                // malformed captures still get a stable, unique-ish fingerprint.
                let mut h = Sha256::new();
                h.update(req.url.as_bytes());
                return format!("{:x}", h.finalize())[..32].to_string();
            }
        };

        let volatile: HashSet<&str> = VOLATILE_PARAMS.iter().copied().collect();
        let mut query_keys: Vec<String> = parsed
            .query_pairs()
            .map(|(k, _)| k.to_lowercase())
            .filter(|k| !volatile.contains(k.as_str()))
            .collect();
        query_keys.sort();
        query_keys.dedup();

        let mut hasher = Sha256::new();
        hasher.update(req.method.to_uppercase().as_bytes());
        hasher.update(b"|");
        hasher.update(parsed.host_str().unwrap_or("").as_bytes());
        hasher.update(b"|");
        hasher.update(parsed.path().as_bytes());
        hasher.update(b"|");
        hasher.update(query_keys.join(",").as_bytes());
        // Truncate: full SHA-256 is unnecessary for dedup; 32 hex chars is plenty.
        format!("{:x}", hasher.finalize())[..32].to_string()
    }

    /// Append an entry. Returns `false` (and stores nothing) when an
    /// identical fingerprint exists — the dedup pipeline.
    pub fn append(&self, entry: TrafficEntry) -> bool {
        let mut inner = self.lock_inner();
        if inner.seen_fingerprints.contains(&entry.fingerprint) {
            return false;
        }
        inner.seen_fingerprints.insert(entry.fingerprint.clone());
        inner.entries.push(entry);

        if inner.entries.len() > self.capacity {
            let removed = inner.entries.remove(0);
            inner.index.remove(&removed.id);
            inner.evicted += 1;
            // Full reindex after the shift. O(n) but amortized: runs once
            // per eviction, evictions happen only after capacity is hit.
            inner.index.clear();
            for i in 0..inner.entries.len() {
                let id = inner.entries[i].id;
                inner.index.insert(id, i);
            }
        } else {
            let last = inner.entries.len() - 1;
            let id = inner.entries[last].id;
            inner.index.insert(id, last);
        }
        true
    }

    /// Look up a single entry by ID.
    pub fn get(&self, id: Uuid) -> Option<TrafficEntry> {
        let inner = self.lock_inner();
        inner.index.get(&id).map(|&i| inner.entries[i].clone())
    }

    /// Newest-first page for the traffic table.
    pub fn page(&self, offset: usize, limit: usize) -> Vec<TrafficEntry> {
        let inner = self.lock_inner();
        let len = inner.entries.len();
        let start = len.saturating_sub(offset + limit);
        let end = len.saturating_sub(offset);
        if start >= end {
            return Vec::new();
        }
        let mut page: Vec<TrafficEntry> = inner.entries[start..end].to_vec();
        page.reverse(); // newest first
        page
    }

    /// Total retained entries + eviction count, for the status bar.
    pub fn stats(&self) -> (usize, usize) {
        let inner = self.lock_inner();
        (inner.entries.len(), inner.evicted)
    }

    /// Drop everything. The durable SQLite trail is untouched.
    pub fn clear(&self) {
        let mut inner = self.lock_inner();
        inner.entries.clear();
        inner.index.clear();
        inner.seen_fingerprints.clear();
        inner.evicted = 0;
    }

    fn lock_inner(&self) -> std::sync::MutexGuard<'_, TrafficInner> {
        match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_req(url: &str) -> HttpRequest {
        HttpRequest {
            id: Uuid::new_v4(),
            job_id: None,
            url: url.to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            body: None,
            timestamp: Utc::now(),
        }
    }

    fn make_entry(url: &str, source: TrafficSource) -> TrafficEntry {
        let req = make_req(url);
        let fingerprint = TrafficStore::fingerprint_request(&req);
        TrafficEntry {
            id: Uuid::new_v4(),
            request: req,
            response: None,
            captured_at: Utc::now(),
            fingerprint,
            source,
        }
    }

    #[test]
    fn dedups_identical_fingerprints() {
        let store = TrafficStore::new(10);
        let a = make_entry("https://x.test/a?id=1", TrafficSource::Proxy);
        let b = make_entry("https://x.test/a?id=2", TrafficSource::Proxy);
        assert!(store.append(a));
        // Same logical endpoint (id param value differs, query key same) — deduped.
        assert!(!store.append(b));
        let (len, _) = store.stats();
        assert_eq!(len, 1);
    }

    #[test]
    fn volatile_params_ignored_in_fingerprint() {
        let f1 = TrafficStore::fingerprint_request(&make_req("https://x.test/a?p=1&_=111"));
        let f2 = TrafficStore::fingerprint_request(&make_req("https://x.test/a?p=1&_=999"));
        assert_eq!(f1, f2);
    }

    #[test]
    fn different_paths_differ() {
        let f1 = TrafficStore::fingerprint_request(&make_req("https://x.test/a"));
        let f2 = TrafficStore::fingerprint_request(&make_req("https://x.test/b"));
        assert_ne!(f1, f2);
    }

    #[test]
    fn evicts_oldest_beyond_capacity() {
        let store = TrafficStore::new(2);
        assert!(store.append(make_entry("https://x.test/1", TrafficSource::Proxy)));
        assert!(store.append(make_entry("https://x.test/2", TrafficSource::Proxy)));
        assert!(store.append(make_entry("https://x.test/3", TrafficSource::Proxy)));
        let (len, evicted) = store.stats();
        assert_eq!(len, 2);
        assert_eq!(evicted, 1);
        // Newest-first: /3 must be the head of page 0.
        let page = store.page(0, 10);
        assert_eq!(page.len(), 2);
        assert!(page[0].request.url.ends_with("/3"));
    }

    #[test]
    fn get_by_id_survives_eviction_of_others() {
        let store = TrafficStore::new(2);
        let keep = make_entry("https://x.test/keep", TrafficSource::Repeater);
        let id = keep.id;
        assert!(store.append(make_entry("https://x.test/1", TrafficSource::Proxy)));
        assert!(store.append(keep));
        assert!(store.append(make_entry("https://x.test/2", TrafficSource::Proxy)));
        assert!(store.get(id).is_some());
    }
}
