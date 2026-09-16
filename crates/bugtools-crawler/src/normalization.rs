//! URL normalization and canonicalization.
//!
//! Comparison is structural, never raw string equality. Trailing slashes,
//! default ports, case, fragments, and duplicate query parameters are
//! handled according to explicit rules.

use url::Url;

/// Canonicalize a URL for deduplication.
///
/// Rules:
/// - scheme + host lowercased
/// - default ports (80/http, 443/https) removed
/// - fragment removed
/// - path `""` becomes `/`
/// - a single trailing slash on a non-root path is stripped by default
/// - query parameters sorted by name, duplicates preserved in order
pub fn canonicalize(raw: &str) -> Option<String> {
    let mut url = Url::parse(raw).ok()?;
    url.set_fragment(None);

    // Sort query parameters by name for stable ordering.
    if url.query().is_some() {
        let mut pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        pairs.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        url.set_query(None);
        if !pairs.is_empty() {
            let mut qp = url.query_pairs_mut();
            for (k, v) in pairs {
                qp.append_pair(&k, &v);
            }
        }
    }

    // Normalize the path.
    let path = url.path().to_string();
    if path.is_empty() {
        url.set_path("/");
    } else if path.len() > 1 && path.ends_with('/') {
        url.set_path(path.trim_end_matches('/'));
    }

    // url crate already lowercases scheme/host and strips default ports.
    Some(url.to_string())
}

/// Whether two URLs refer to the same resource under our rules.
pub fn same_resource(a: &str, b: &str) -> bool {
    match (canonicalize(a), canonicalize(b)) {
        (Some(ca), Some(cb)) => ca == cb,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailing_slash_normalized() {
        assert_eq!(
            canonicalize("https://example.com/a/").unwrap(),
            "https://example.com/a"
        );
    }

    #[test]
    fn root_path_preserved() {
        assert_eq!(canonicalize("https://example.com").unwrap(), "https://example.com/");
    }

    #[test]
    fn default_port_stripped() {
        assert_eq!(
            canonicalize("https://example.com:443/a").unwrap(),
            "https://example.com/a"
        );
        assert_eq!(
            canonicalize("http://example.com:80/a").unwrap(),
            "http://example.com/a"
        );
    }

    #[test]
    fn non_default_port_kept() {
        assert_eq!(
            canonicalize("https://example.com:8443/a").unwrap(),
            "https://example.com:8443/a"
        );
    }

    #[test]
    fn fragment_removed() {
        assert_eq!(
            canonicalize("https://example.com/a#section").unwrap(),
            "https://example.com/a"
        );
    }

    #[test]
    fn query_sorted_for_stability() {
        let a = canonicalize("https://example.com/x?b=2&a=1").unwrap();
        let b = canonicalize("https://example.com/x?a=1&b=2").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn host_case_insensitive() {
        assert!(same_resource("https://EXAMPLE.com/a", "https://example.com/a"));
    }

    #[test]
    fn different_paths_not_same() {
        assert!(!same_resource("https://example.com/a", "https://example.com/b"));
    }

    #[test]
    fn invalid_url_returns_none() {
        assert!(canonicalize("not a url").is_none());
    }
}
