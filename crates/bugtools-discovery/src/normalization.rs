//! Hostname normalization and domain-part helpers.

/// Normalize a hostname: lowercase, strip a trailing dot, strip a scheme or
/// path if one slipped in, and trim whitespace.
pub fn normalize_hostname(input: &str) -> String {
    let mut host = input.trim().to_lowercase();
    if let Some(rest) = host.strip_prefix("http://") {
        host = rest.to_string();
    } else if let Some(rest) = host.strip_prefix("https://") {
        host = rest.to_string();
    }
    // Strip any path/query.
    if let Some(idx) = host.find('/') {
        host.truncate(idx);
    }
    // Strip a port suffix.
    if let Some(idx) = host.rfind(':') {
        if host[idx + 1..].chars().all(|c| c.is_ascii_digit()) {
            host.truncate(idx);
        }
    }
    if let Some(stripped) = host.strip_suffix('.') {
        host = stripped.to_string();
    }
    host
}

/// Return the registrable-ish parent: the last two labels. This is a
/// heuristic (it does not consult the public-suffix list) and is used only
/// for wildcard probing and permutation, never for scope decisions.
pub fn parent_domain(hostname: &str) -> String {
    let host = normalize_hostname(hostname);
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() <= 2 {
        return host;
    }
    parts[parts.len() - 2..].join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowercase_and_trim() {
        assert_eq!(normalize_hostname("  API.Example.COM "), "api.example.com");
    }

    #[test]
    fn strips_scheme_path_port() {
        assert_eq!(normalize_hostname("https://api.example.com/v1/x"), "api.example.com");
        assert_eq!(normalize_hostname("http://api.example.com:8080"), "api.example.com");
    }

    #[test]
    fn strips_trailing_dot() {
        assert_eq!(normalize_hostname("api.example.com."), "api.example.com");
    }

    #[test]
    fn parent_of_subdomain() {
        assert_eq!(parent_domain("api.staging.example.com"), "example.com");
        assert_eq!(parent_domain("example.com"), "example.com");
    }
}
