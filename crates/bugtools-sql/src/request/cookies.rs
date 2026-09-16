//! Cookie / session subsystem.
//!
//! Provides a proper cookie jar with parsing of both request `Cookie`
//! headers and response `Set-Cookie` headers, attribute handling, and
//! masking so credentials are never logged or displayed by default.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single cookie with its attributes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: bool,
    pub http_only: bool,
    /// Session cookies have no expiry and are discarded at session end.
    pub session: bool,
    /// Unix timestamp (seconds) for persistent cookies.
    pub expires_at: Option<i64>,
    pub same_site: Option<String>,
}

impl Cookie {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            domain: None,
            path: None,
            secure: false,
            http_only: false,
            session: true,
            expires_at: None,
            same_site: None,
        }
    }

    /// Render this cookie for a request `Cookie:` header (name=value only;
    /// attributes are never sent back to the server).
    pub fn to_header_pair(&self) -> String {
        format!("{}={}", self.name, self.value)
    }
}

/// Why a Set-Cookie header could not be parsed.
#[derive(Debug, thiserror::Error)]
pub enum CookieError {
    #[error("cookie has no name=value pair")]
    MissingPair,
}

/// Parse a response `Set-Cookie` header into a Cookie.
///
/// Handles the standard attribute set: Domain, Path, Secure, HttpOnly,
/// SameSite, Max-Age, Expires. Unknown attributes are ignored.
pub fn parse_set_cookie(header: &str) -> Result<Cookie, CookieError> {
    let mut parts = header.split(';');
    let first = parts.next().ok_or(CookieError::MissingPair)?;
    let (name, value) = first
        .split_once('=')
        .ok_or(CookieError::MissingPair)?;

    let mut cookie = Cookie::new(name.trim(), value.trim());

    for attr in parts {
        let attr = attr.trim();
        if attr.is_empty() {
            continue;
        }
        match attr.split_once('=') {
            Some((key, val)) => {
                let key_lower = key.trim().to_lowercase();
                let val = val.trim();
                match key_lower.as_str() {
                    "domain" => cookie.domain = Some(val.trim_start_matches('.').to_string()),
                    "path" => cookie.path = Some(val.to_string()),
                    "samesite" => cookie.same_site = Some(val.to_string()),
                    "max-age" => {
                        if let Ok(secs) = val.parse::<i64>() {
                            cookie.session = false;
                            cookie.expires_at = Some(chrono::Utc::now().timestamp() + secs);
                        }
                    }
                    "expires" => {
                        // Expiry parsing is intentionally conservative: we mark
                        // the cookie persistent but only trust Max-Age for the
                        // exact timestamp. Expires date parsing varies by format.
                        cookie.session = false;
                    }
                    _ => {}
                }
            }
            None => {
                if attr.eq_ignore_ascii_case("secure") {
                    cookie.secure = true;
                } else if attr.eq_ignore_ascii_case("httponly") {
                    cookie.http_only = true;
                }
            }
        }
    }

    Ok(cookie)
}

/// Parse a request `Cookie:` header into name/value pairs.
/// Returns the individual cookies in the order they appeared.
pub fn parse_cookie_header(header: &str) -> Vec<Cookie> {
    header
        .split(';')
        .filter_map(|pair| {
            let pair = pair.trim();
            if pair.is_empty() {
                return None;
            }
            pair.split_once('=')
                .map(|(k, v)| Cookie::new(k.trim(), v.trim()))
        })
        .collect()
}

/// Merge a parsed Set-Cookie into a jar's cookie list, replacing an
/// existing cookie with the same name+domain+path, or removing it when the
/// value is empty (deletion semantics).
pub fn upsert_cookie(jar: &mut Vec<Cookie>, cookie: Cookie) {
    if cookie.value.is_empty() {
        jar.retain(|c| !(c.name == cookie.name && c.domain == cookie.domain && c.path == cookie.path));
        return;
    }
    if let Some(existing) = jar.iter_mut().find(|c| {
        c.name == cookie.name && c.domain == cookie.domain && c.path == cookie.path
    }) {
        *existing = cookie;
    } else {
        jar.push(cookie);
    }
}

/// A per-target (or per-scan) cookie jar.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CookieJar {
    /// Profile name this jar belongs to (e.g. "anonymous", "authenticated").
    pub profile: String,
    pub cookies: Vec<Cookie>,
}

impl CookieJar {
    pub fn new(profile: impl Into<String>) -> Self {
        Self {
            profile: profile.into(),
            cookies: Vec::new(),
        }
    }

    /// Apply all cookies from a `Cookie:` request header.
    pub fn apply_request_header(&mut self, header: &str) {
        for cookie in parse_cookie_header(header) {
            upsert_cookie(&mut self.cookies, cookie);
        }
    }

    /// Record cookies from response `Set-Cookie` headers.
    pub fn apply_set_cookie(&mut self, header: &str) -> Result<(), CookieError> {
        let cookie = parse_set_cookie(header)?;
        upsert_cookie(&mut self.cookies, cookie);
        Ok(())
    }

    /// Render the `Cookie:` header value for the next request.
    pub fn to_header_value(&self) -> String {
        self.cookies
            .iter()
            .map(|c| c.to_header_pair())
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// Remove expired persistent cookies. `now` is a unix timestamp.
    pub fn prune_expired(&mut self, now: i64) {
        self.cookies.retain(|c| match c.expires_at {
            Some(exp) => exp > now,
            None => true,
        });
    }

    /// Mask a cookie's value for display: show a fixed-length redaction.
    /// Never returns the real value — callers that need the real value must
    /// access the field directly and are responsible for its handling.
    pub fn masked_value(cookie: &Cookie) -> String {
        if cookie.value.is_empty() {
            String::new()
        } else {
            "*".repeat(cookie.value.len().min(12))
        }
    }

    /// Export as a simple name=value map for the researcher's clipboard.
    /// This intentionally exposes real values — only call on explicit user action.
    pub fn export_pairs(&self) -> Vec<(String, String)> {
        self.cookies
            .iter()
            .map(|c| (c.name.clone(), c.value.clone()))
            .collect()
    }

    /// Import name=value pairs, replacing same-named cookies.
    pub fn import_pairs(&mut self, pairs: &[(String, String)]) {
        for (name, value) in pairs {
            upsert_cookie(&mut self.cookies, Cookie::new(name.clone(), value.clone()));
        }
    }
}

/// A named group of jars so one scan can hold anonymous + authenticated
/// profiles concurrently.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CookieProfiles {
    pub jars: HashMap<String, CookieJar>,
}

impl CookieProfiles {
    pub fn jar(&mut self, profile: &str) -> &mut CookieJar {
        self.jars
            .entry(profile.to_string())
            .or_insert_with(|| CookieJar::new(profile))
    }

    pub fn get(&self, profile: &str) -> Option<&CookieJar> {
        self.jars.get(profile)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_cookie_parses_attributes() {
        let c = parse_set_cookie("session=abc123; Path=/; Domain=.example.com; Secure; HttpOnly; SameSite=Lax").unwrap();
        assert_eq!(c.name, "session");
        assert_eq!(c.value, "abc123");
        assert_eq!(c.path.as_deref(), Some("/"));
        assert_eq!(c.domain.as_deref(), Some("example.com"));
        assert!(c.secure);
        assert!(c.http_only);
        assert_eq!(c.same_site.as_deref(), Some("Lax"));
    }

    #[test]
    fn set_cookie_max_age_marks_persistent() {
        let c = parse_set_cookie("tok=x; Max-Age=3600").unwrap();
        assert!(!c.session);
        assert!(c.expires_at.is_some());
    }

    #[test]
    fn request_cookie_header_parses_multiple() {
        let cookies = parse_cookie_header("a=1; b=2; c=3");
        assert_eq!(cookies.len(), 3);
        assert_eq!(cookies[1].name, "b");
        assert_eq!(cookies[1].value, "2");
    }

    #[test]
    fn jar_roundtrips_header() {
        let mut jar = CookieJar::new("default");
        jar.apply_request_header("session=abc; tenant=42");
        assert_eq!(jar.to_header_value(), "session=abc; tenant=42");
    }

    #[test]
    fn set_cookie_updates_jar() {
        let mut jar = CookieJar::new("auth");
        jar.apply_set_cookie("session=first; Path=/").unwrap();
        jar.apply_set_cookie("session=second; Path=/").unwrap();
        assert_eq!(jar.cookies.len(), 1, "same name+path should replace");
        assert_eq!(jar.cookies[0].value, "second");
    }

    #[test]
    fn empty_value_deletes_cookie() {
        let mut jar = CookieJar::new("x");
        jar.apply_set_cookie("session=abc; Path=/").unwrap();
        jar.apply_set_cookie("session=; Path=/").unwrap();
        assert!(jar.cookies.is_empty());
    }

    #[test]
    fn masking_hides_value() {
        let c = Cookie::new("session", "supersecretvalue");
        let masked = CookieJar::masked_value(&c);
        assert!(!masked.contains("secret"));
        assert_eq!(masked.chars().count(), 12);
    }

    #[test]
    fn expired_cookies_pruned() {
        let mut jar = CookieJar::new("x");
        let mut c = Cookie::new("old", "v");
        c.session = false;
        c.expires_at = Some(1000);
        jar.cookies.push(c);
        jar.cookies.push(Cookie::new("session", "v"));
        jar.prune_expired(2000);
        assert_eq!(jar.cookies.len(), 1);
        assert_eq!(jar.cookies[0].name, "session");
    }

    #[test]
    fn profiles_isolate_jars() {
        let mut profiles = CookieProfiles::default();
        profiles.jar("anon").apply_request_header("a=1");
        profiles.jar("auth").apply_request_header("b=2");
        assert_eq!(profiles.get("anon").unwrap().cookies.len(), 1);
        assert_eq!(profiles.get("auth").unwrap().cookies.len(), 1);
        assert_eq!(profiles.get("anon").unwrap().cookies[0].name, "a");
    }

    #[test]
    fn import_export_roundtrip() {
        let mut jar = CookieJar::new("x");
        jar.import_pairs(&[("a".into(), "1".into()), ("b".into(), "2".into())]);
        let exported = jar.export_pairs();
        assert_eq!(exported.len(), 2);
    }
}
