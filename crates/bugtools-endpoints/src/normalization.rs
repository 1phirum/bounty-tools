//! Reference resolution and route templating.
//!
//! Two jobs the extractors deliberately don't do, so the logic lives in one
//! tested place:
//!   1. Resolve a raw reference against an optional base URL, splitting it
//!      into a path and its query-parameter *names* (values are noise).
//!   2. Templatize a path so `/user/1` and `/user/9` collapse to `/user/{id}`,
//!      which is what makes the endpoint list a route list rather than a hit
//!      log.

use url::Url;

/// A resolved reference, ready to key and merge on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedRef {
    /// Path only, no query/fragment. Absolute-host refs keep their origin so
    /// distinct third-party hosts don't collide when no base is given.
    pub path: String,
    /// Query parameter names, in first-seen order.
    pub query_params: Vec<String>,
    /// A concrete representative reference for display.
    pub display: String,
    /// True when a base host was given and this ref points at another host.
    pub external: bool,
}

/// Schemes we never treat as endpoints.
fn is_ignorable(raw: &str) -> bool {
    let t = raw.trim();
    if t.is_empty() || t == "#" {
        return true;
    }
    let lower = t.to_ascii_lowercase();
    lower.starts_with("javascript:")
        || lower.starts_with("mailto:")
        || lower.starts_with("tel:")
        || lower.starts_with("data:")
        || lower.starts_with("about:")
        || lower.starts_with("blob:")
        || lower.starts_with('#')
}

/// Resolve `raw` against `base` (if any). Returns `None` for references that
/// aren't real endpoints (empty, fragment-only, `javascript:` …).
pub fn normalize(base: Option<&Url>, raw: &str) -> Option<NormalizedRef> {
    if is_ignorable(raw) {
        return None;
    }
    let raw = raw.trim();

    match base {
        Some(base) => {
            let joined = base.join(raw).ok()?;
            let external = joined.host_str() != base.host_str();
            let path = joined.path().to_string();
            let query_params = query_names(&joined);
            Some(NormalizedRef {
                path,
                query_params,
                display: joined.as_str().to_string(),
                external,
            })
        }
        None => normalize_without_base(raw),
    }
}

/// Best-effort split when no base URL is available.
fn normalize_without_base(raw: &str) -> Option<NormalizedRef> {
    // A fully-qualified URL: parse and keep its origin in the path key so two
    // different hosts remain distinct.
    if let Ok(u) = Url::parse(raw) {
        if u.scheme() == "http" || u.scheme() == "https" || u.scheme() == "ws" || u.scheme() == "wss"
        {
            let origin = u.host_str().map(|h| format!("//{h}")).unwrap_or_default();
            return Some(NormalizedRef {
                path: format!("{origin}{}", u.path()),
                query_params: query_names(&u),
                display: u.as_str().to_string(),
                external: false,
            });
        }
        // Some other scheme slipped past is_ignorable — drop it.
        return None;
    }

    // A relative/absolute path string. Keep only path-like references.
    if !raw.starts_with('/') {
        return None;
    }
    let (path, query) = match raw.split_once('?') {
        Some((p, q)) => (p.to_string(), q),
        None => (raw.split('#').next().unwrap_or(raw).to_string(), ""),
    };
    let query_params = query_names_from_str(query);
    Some(NormalizedRef {
        path,
        query_params,
        display: raw.to_string(),
        external: false,
    })
}

fn query_names(u: &Url) -> Vec<String> {
    let mut names = Vec::new();
    for (k, _) in u.query_pairs() {
        let k = k.to_string();
        if !k.is_empty() && !names.contains(&k) {
            names.push(k);
        }
    }
    names
}

fn query_names_from_str(query: &str) -> Vec<String> {
    let mut names = Vec::new();
    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let name = pair.split('=').next().unwrap_or(pair);
        let name = name.split('#').next().unwrap_or(name).to_string();
        if !name.is_empty() && !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

/// Collapse volatile path segments into placeholders so concrete instances of
/// the same route share one key. A leading `//host` origin (added when no base
/// is known) is preserved verbatim.
pub fn templatize(path: &str) -> String {
    let (origin, rest) = match path.strip_prefix("//") {
        Some(after) => match after.split_once('/') {
            Some((host, tail)) => (format!("//{host}"), format!("/{tail}")),
            None => (format!("//{after}"), String::new()),
        },
        None => (String::new(), path.to_string()),
    };

    let templated: Vec<String> = rest
        .split('/')
        .map(|seg| if seg.is_empty() { seg.to_string() } else { templatize_segment(seg) })
        .collect();

    format!("{origin}{}", templated.join("/"))
}

fn templatize_segment(seg: &str) -> String {
    if seg.chars().all(|c| c.is_ascii_digit()) {
        return "{id}".to_string();
    }
    if is_uuid(seg) {
        return "{uuid}".to_string();
    }
    if seg.len() >= 16 && seg.chars().all(|c| c.is_ascii_hexdigit()) {
        return "{hash}".to_string();
    }
    // A `name.HASH.ext` filename: replace only the content-hash token so
    // `app.4f3a2b1c.js` and `app.9d0e1f2a.js` collapse to `app.{hash}.js`.
    if seg.contains('.') {
        let parts: Vec<&str> = seg.split('.').collect();
        if parts.len() >= 3 {
            let rebuilt: Vec<String> = parts
                .iter()
                .map(|p| {
                    if p.len() >= 8 && p.chars().all(|c| c.is_ascii_hexdigit()) {
                        "{hash}".to_string()
                    } else {
                        p.to_string()
                    }
                })
                .collect();
            return rebuilt.join(".");
        }
    }
    seg.to_string()
}

fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    b.iter().enumerate().all(|(i, &c)| {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            c == b'-'
        } else {
            (c as char).is_ascii_hexdigit()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Url {
        Url::parse("https://target.test/app/").unwrap()
    }

    #[test]
    fn resolves_relative_against_base() {
        let r = normalize(Some(&base()), "users?id=1&full=true").unwrap();
        assert_eq!(r.path, "/app/users");
        assert_eq!(r.query_params, vec!["id", "full"]);
        assert!(!r.external);
    }

    #[test]
    fn absolute_same_host_is_not_external() {
        let r = normalize(Some(&base()), "https://target.test/x").unwrap();
        assert!(!r.external);
        assert_eq!(r.path, "/x");
    }

    #[test]
    fn other_host_is_external() {
        let r = normalize(Some(&base()), "https://cdn.other.test/lib.js").unwrap();
        assert!(r.external);
    }

    #[test]
    fn ignores_non_endpoint_schemes() {
        assert!(normalize(Some(&base()), "javascript:void(0)").is_none());
        assert!(normalize(Some(&base()), "mailto:a@b.test").is_none());
        assert!(normalize(Some(&base()), "#section").is_none());
        assert!(normalize(None, "   ").is_none());
    }

    #[test]
    fn without_base_keeps_paths_and_absolute_urls() {
        let p = normalize(None, "/api/v1/users?q=1").unwrap();
        assert_eq!(p.path, "/api/v1/users");
        assert_eq!(p.query_params, vec!["q"]);

        let a = normalize(None, "https://api.test/v2/orders").unwrap();
        assert_eq!(a.path, "//api.test/v2/orders");

        // Bare relative words are not endpoints without a base to anchor them.
        assert!(normalize(None, "just text").is_none());
    }

    #[test]
    fn templatize_collapses_ids_uuids_hashes() {
        assert_eq!(templatize("/user/1042/orders"), "/user/{id}/orders");
        assert_eq!(
            templatize("/o/9f8e7d6c-1234-4a2b-8c3d-abcdefabcdef"),
            "/o/{uuid}"
        );
        assert_eq!(templatize("/static/app.4f3a2b1c.js"), "/static/app.{hash}.js");
        assert_eq!(
            templatize("/blob/0123456789abcdef0123"),
            "/blob/{hash}"
        );
    }

    #[test]
    fn templatize_preserves_origin_prefix() {
        assert_eq!(templatize("//api.test/v2/orders/7"), "//api.test/v2/orders/{id}");
    }

    #[test]
    fn templatize_leaves_ordinary_segments() {
        assert_eq!(templatize("/api/v1/users"), "/api/v1/users");
    }
}
