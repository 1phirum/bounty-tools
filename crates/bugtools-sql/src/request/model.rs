//! Complete HTTP request model for the SQL research engine.
//!
//! Unlike the minimal `bugtools_core::http::HttpRequest`, this template
//! preserves every input location the engine must be able to reason about:
//! query, path, headers, cookies, and typed bodies. Each individual input
//! carries a stable ID so evidence can reference it across the pipeline.

use crate::context::InputLocation;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// How the request body should be interpreted when rebuilding it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyType {
    None,
    FormUrlEncoded,
    Multipart,
    Json,
    Xml,
    Raw,
}

impl Default for BodyType {
    fn default() -> Self {
        Self::None
    }
}

/// Authentication material attached to a request template.
///
/// Secrets are stored as-is for request construction but are never written
/// to logs or reports by this crate — renderers must mask them.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthContext {
    /// Cookies are managed by the cookie jar; this is a snapshot reference.
    pub cookie_names: Vec<String>,
    /// Bearer token, if the request uses one.
    pub bearer_token: Option<String>,
    /// Basic-auth username/password pair.
    pub basic: Option<(String, String)>,
    /// Arbitrary authentication headers supplied by the researcher.
    pub headers: HashMap<String, String>,
    /// Whether the template is expected to require authentication.
    pub authenticated: bool,
}

impl AuthContext {
    pub fn is_empty(&self) -> bool {
        self.cookie_names.is_empty()
            && self.bearer_token.is_none()
            && self.basic.is_none()
            && self.headers.is_empty()
    }
}

/// A single named input discovered within a request, at a known location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputSlot {
    pub id: Uuid,
    pub location: InputLocation,
    /// Dotted path for nested inputs, e.g. `filter.name` for JSON bodies.
    pub name: String,
    pub original_value: String,
}

impl InputSlot {
    pub fn new(location: InputLocation, name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            location,
            name: name.into(),
            original_value: value.into(),
        }
    }
}

/// A complete, reconstructable HTTP request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestTemplate {
    pub id: Uuid,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub query_parameters: Vec<(String, String)>,
    /// Path segments that look like parameters, e.g. `/users/{id}`.
    pub path_parameters: Vec<(String, String)>,
    pub headers: HashMap<String, String>,
    pub cookies: Vec<(String, String)>,
    pub body: Option<String>,
    pub body_type: BodyType,
    pub authentication: AuthContext,
    /// Where this request came from (manual, raw import, crawler, proxy).
    pub source: RequestSource,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestSource {
    Manual,
    RawImport,
    Proxy,
    Crawler,
    Unknown,
}

impl RequestTemplate {
    /// Build a template from a URL and method, parsing out query parameters.
    pub fn from_url(method: &str, url: &str) -> Result<Self, RequestModelError> {
        let parsed = url::Url::parse(url)
            .map_err(|e| RequestModelError::InvalidUrl(e.to_string()))?;
        let scheme = parsed.scheme().to_string();
        if scheme != "http" && scheme != "https" {
            return Err(RequestModelError::InvalidUrl(format!(
                "unsupported scheme: {scheme}"
            )));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| RequestModelError::InvalidUrl("missing host".into()))?
            .to_string();
        let port = parsed.port_or_known_default().unwrap_or(if scheme == "https" { 443 } else { 80 });
        let path = parsed.path().to_string();
        let query_parameters = parsed
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        Ok(Self {
            id: Uuid::new_v4(),
            method: method.trim().to_uppercase(),
            scheme,
            host,
            port,
            path,
            query_parameters,
            path_parameters: Vec::new(),
            headers: HashMap::new(),
            cookies: Vec::new(),
            body: None,
            body_type: BodyType::None,
            authentication: AuthContext::default(),
            source: RequestSource::Manual,
            created_at: chrono::Utc::now(),
        })
    }

    /// Reconstruct the full request URL including query string.
    pub fn url(&self) -> String {
        let mut url = format!("{}://{}", self.scheme, self.host);
        let default_port = (self.scheme == "https" && self.port == 443)
            || (self.scheme == "http" && self.port == 80);
        if !default_port {
            url.push_str(&format!(":{}", self.port));
        }
        url.push_str(&self.path);
        if !self.query_parameters.is_empty() {
            let qs: Vec<String> = self
                .query_parameters
                .iter()
                .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
                .collect();
            url.push('?');
            url.push_str(&qs.join("&"));
        }
        url
    }

    /// Set (or replace) a query parameter, returning the previous value.
    pub fn set_query_parameter(&mut self, name: &str, value: &str) -> Option<String> {
        if let Some(entry) = self.query_parameters.iter_mut().find(|(k, _)| k == name) {
            let old = entry.1.clone();
            entry.1 = value.to_string();
            return Some(old);
        }
        self.query_parameters
            .push((name.to_string(), value.to_string()));
        None
    }

    /// Every input slot this request exposes, across all locations.
    ///
    /// This is the single source of truth for "what can be tested" — the
    /// scanner never invents inputs that are not enumerated here.
    pub fn inputs(&self) -> Vec<InputSlot> {
        let mut slots = Vec::new();
        for (name, value) in &self.query_parameters {
            slots.push(InputSlot::new(InputLocation::Query, name, value));
        }
        for (name, value) in &self.path_parameters {
            slots.push(InputSlot::new(InputLocation::Path, name, value));
        }
        for (name, value) in &self.cookies {
            slots.push(InputSlot::new(InputLocation::Cookie, name, value));
        }
        for (name, value) in &self.headers {
            // Skip framing/transport headers that are never application inputs.
            if is_framing_header(name) {
                continue;
            }
            slots.push(InputSlot::new(InputLocation::Header, name, value));
        }
        if let Some(body) = &self.body {
            match self.body_type {
                BodyType::Json => {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                        collect_json_inputs("", &json, &mut slots);
                    }
                }
                BodyType::FormUrlEncoded => {
                    for (k, v) in url::form_urlencoded::parse(body.as_bytes()) {
                        slots.push(InputSlot::new(InputLocation::Form, k.to_string(), v.to_string()));
                    }
                }
                _ => {}
            }
        }
        slots
    }
}

/// Headers that describe the message itself rather than application input.
fn is_framing_header(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "host"
            | "content-length"
            | "content-type"
            | "connection"
            | "accept-encoding"
            | "user-agent"
            | "cookie" // cookies are enumerated separately
    )
}

/// Recursively collect inputs from a JSON value, building dotted paths for
/// nested objects and `[i]` indices for arrays.
fn collect_json_inputs(prefix: &str, value: &serde_json::Value, out: &mut Vec<InputSlot>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                collect_json_inputs(&path, child, out);
            }
        }
        serde_json::Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                let path = format!("{prefix}[{i}]");
                collect_json_inputs(&path, child, out);
            }
        }
        serde_json::Value::String(s) => {
            out.push(InputSlot::new(InputLocation::Json, prefix, s));
        }
        serde_json::Value::Number(n) => {
            out.push(InputSlot::new(InputLocation::Json, prefix, n.to_string()));
        }
        serde_json::Value::Bool(b) => {
            out.push(InputSlot::new(InputLocation::Json, prefix, b.to_string()));
        }
        serde_json::Value::Null => {
            out.push(InputSlot::new(InputLocation::Json, prefix, ""));
        }
    }
}

/// Minimal percent-encoding for query reconstruction. Encodes only the
/// characters that would otherwise break the query string.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[derive(Debug, thiserror::Error)]
pub enum RequestModelError {
    #[error("invalid URL: {0}")]
    InvalidUrl(String),
    #[error("malformed raw request: {0}")]
    MalformedRaw(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parsing_extracts_query_parameters() {
        let t = RequestTemplate::from_url("get", "https://example.test/products?id=42&sort=price")
            .unwrap();
        assert_eq!(t.method, "GET");
        assert_eq!(t.host, "example.test");
        assert_eq!(t.port, 443);
        assert_eq!(t.path, "/products");
        assert_eq!(t.query_parameters.len(), 2);
        assert_eq!(t.query_parameters[0], ("id".into(), "42".into()));
    }

    #[test]
    fn url_reconstruction_roundtrips() {
        let t = RequestTemplate::from_url("GET", "https://example.test/a/b?x=1&y=2").unwrap();
        assert_eq!(t.url(), "https://example.test/a/b?x=1&y=2");
    }

    #[test]
    fn non_default_port_preserved() {
        let t = RequestTemplate::from_url("GET", "http://example.test:8080/x").unwrap();
        assert_eq!(t.port, 8080);
        assert_eq!(t.url(), "http://example.test:8080/x");
    }

    #[test]
    fn rejects_non_http_scheme() {
        assert!(RequestTemplate::from_url("GET", "ftp://example.test/x").is_err());
    }

    #[test]
    fn json_inputs_are_flattened_with_paths() {
        let mut t = RequestTemplate::from_url("POST", "https://api.test/search").unwrap();
        t.body = Some(r#"{"filter":{"name":"phone"},"page":1,"tags":["a","b"]}"#.into());
        t.body_type = BodyType::Json;
        let inputs = t.inputs();
        let names: Vec<&str> = inputs.iter().map(|i| i.name.as_str()).collect();
        assert!(names.contains(&"filter.name"), "nested JSON path missing: {names:?}");
        assert!(names.contains(&"page"));
        assert!(names.contains(&"tags[0]"));
        assert!(names.contains(&"tags[1]"));
        // Location must be Json for all of these.
        assert!(inputs.iter().all(|i| i.location == InputLocation::Json));
    }

    #[test]
    fn form_body_inputs_are_extracted() {
        let mut t = RequestTemplate::from_url("POST", "https://api.test/login").unwrap();
        t.body = Some("user=admin&pass=secret".into());
        t.body_type = BodyType::FormUrlEncoded;
        let inputs = t.inputs();
        assert_eq!(inputs.len(), 2);
        assert!(inputs.iter().all(|i| i.location == InputLocation::Form));
    }

    #[test]
    fn framing_headers_are_not_inputs() {
        let mut t = RequestTemplate::from_url("GET", "https://x.test/y").unwrap();
        t.headers.insert("Host".into(), "x.test".into());
        t.headers.insert("User-Agent".into(), "curl".into());
        t.headers.insert("X-Account-ID".into(), "42".into());
        let inputs = t.inputs();
        assert_eq!(inputs.len(), 1, "only X-Account-ID should be an input");
        assert_eq!(inputs[0].name, "X-Account-ID");
        assert_eq!(inputs[0].location, InputLocation::Header);
    }

    #[test]
    fn cookies_are_inputs() {
        let mut t = RequestTemplate::from_url("GET", "https://x.test/y").unwrap();
        t.cookies.push(("tenant_id".into(), "42".into()));
        let inputs = t.inputs();
        assert!(inputs.iter().any(|i| i.location == InputLocation::Cookie && i.name == "tenant_id"));
    }

    #[test]
    fn set_query_parameter_replaces_in_place() {
        let mut t = RequestTemplate::from_url("GET", "https://x.test/y?a=1&b=2").unwrap();
        let old = t.set_query_parameter("a", "9");
        assert_eq!(old, Some("1".into()));
        assert_eq!(t.query_parameters.len(), 2);
        assert_eq!(t.set_query_parameter("c", "3"), None);
        assert_eq!(t.query_parameters.len(), 3);
    }
}
