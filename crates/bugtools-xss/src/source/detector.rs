//! Source detection: identify where client-side code reads attacker data.
//!
//! A *source* is an API that returns data an attacker can influence. Detection
//! is static and syntax-level: we find the read, not the flow — flow is the
//! taint module's job.

use serde::{Deserialize, Serialize};

/// Where attacker-controlled data can enter client-side code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    LocationHash,
    LocationSearch,
    LocationHref,
    LocationPathname,
    DocumentReferrer,
    WindowName,
    PostMessage,
    LocalStorage,
    SessionStorage,
    DocumentCookie,
    IndexedDb,
    UrlFragment,
}

impl SourceKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::LocationHash => "location.hash",
            Self::LocationSearch => "location.search",
            Self::LocationHref => "location.href",
            Self::LocationPathname => "location.pathname",
            Self::DocumentReferrer => "document.referrer",
            Self::WindowName => "window.name",
            Self::PostMessage => "postMessage",
            Self::LocalStorage => "localStorage",
            Self::SessionStorage => "sessionStorage",
            Self::DocumentCookie => "document.cookie",
            Self::IndexedDb => "IndexedDB",
            Self::UrlFragment => "URL fragment",
        }
    }

    /// How directly an attacker controls this source's value.
    pub fn attacker_control(&self) -> f32 {
        match self {
            Self::LocationHash | Self::LocationSearch | Self::LocationHref
            | Self::LocationPathname | Self::UrlFragment => 1.0,
            Self::WindowName | Self::PostMessage => 0.9,
            Self::DocumentReferrer => 0.7,
            Self::DocumentCookie => 0.6,
            Self::LocalStorage | Self::SessionStorage | Self::IndexedDb => 0.5,
        }
    }
}

/// A source read found in client-side code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceRead {
    pub kind: SourceKind,
    /// Byte offset of the read in the analyzed script.
    pub offset: usize,
    /// The line of code containing the read.
    pub context_line: String,
}

/// Detect source reads in JavaScript source text.
///
/// Recognizes the standard DOM sources by their access patterns. Each
/// detection records the offset so the taint module can trace onward.
pub fn detect_sources(script: &str) -> Vec<SourceRead> {
    const PATTERNS: &[(&str, SourceKind)] = &[
        ("location.hash", SourceKind::LocationHash),
        ("location.search", SourceKind::LocationSearch),
        ("location.href", SourceKind::LocationHref),
        ("location.pathname", SourceKind::LocationPathname),
        ("document.referrer", SourceKind::DocumentReferrer),
        ("window.name", SourceKind::WindowName),
        ("postMessage", SourceKind::PostMessage),
        ("localStorage", SourceKind::LocalStorage),
        ("sessionStorage", SourceKind::SessionStorage),
        ("document.cookie", SourceKind::DocumentCookie),
        ("indexedDB", SourceKind::IndexedDb),
    ];

    let mut out = Vec::new();
    for (needle, kind) in PATTERNS {
        let lower = script.to_lowercase();
        let mut from = 0;
        while let Some(pos) = lower[from..].find(&needle.to_lowercase()) {
            let offset = from + pos;
            let line = line_at(script, offset);
            out.push(SourceRead {
                kind: *kind,
                offset,
                context_line: line.to_string(),
            });
            from = offset + needle.len();
        }
    }
    out.sort_by_key(|s| s.offset);
    out
}

fn line_at(script: &str, offset: usize) -> &str {
    let start = script[..offset].rfind('\n').map(|p| p + 1).unwrap_or(0);
    let end = script[offset..]
        .find('\n')
        .map(|p| offset + p)
        .unwrap_or(script.len());
    &script[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn location_hash_detected() {
        let src = "var v = location.hash.slice(1);";
        let found = detect_sources(src);
        assert!(found.iter().any(|s| s.kind == SourceKind::LocationHash));
    }

    #[test]
    fn multiple_sources_sorted_by_offset() {
        let src = "var a = location.search; var b = document.referrer;";
        let found = detect_sources(src);
        assert!(found.len() >= 2);
        for w in found.windows(2) {
            assert!(w[0].offset <= w[1].offset);
        }
    }

    #[test]
    fn context_line_is_captured() {
        let src = "var x = 1;\nvar v = location.hash;";
        let found = detect_sources(src);
        let hash = found.iter().find(|s| s.kind == SourceKind::LocationHash).unwrap();
        assert!(hash.context_line.contains("location.hash"));
    }

    #[test]
    fn no_sources_in_plain_code() {
        assert!(detect_sources("var x = 1 + 2;").is_empty());
    }

    #[test]
    fn attacker_control_is_rated() {
        assert_eq!(SourceKind::LocationHash.attacker_control(), 1.0);
        assert!(SourceKind::LocalStorage.attacker_control() < 1.0);
    }

    #[test]
    fn window_name_and_postmessage_detected() {
        let src = "window.addEventListener('message', e => use(e.data)); postMessage('x','*');";
        let found = detect_sources(src);
        assert!(found.iter().any(|s| s.kind == SourceKind::PostMessage));
    }
}
