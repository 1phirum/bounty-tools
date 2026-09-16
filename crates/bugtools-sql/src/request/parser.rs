//! Raw HTTP request import / export (Burp-style).
//!
//! Parses a pasted raw request into a `RequestTemplate` and can render a
//! template back to raw form. This is the primary way a researcher brings
//! an authenticated, complex request into the engine.

use super::model::{AuthContext, BodyType, RequestModelError, RequestSource, RequestTemplate};
use std::collections::HashMap;

/// Parse a raw HTTP request (as copied from Burp / a proxy / devtools).
///
/// Expects a request line, headers, a blank line, then an optional body.
/// The `Host` header is required to build an absolute URL; a full URL in
/// the request line is also accepted.
pub fn parse_raw_request(raw: &str) -> Result<RequestTemplate, RequestModelError> {
    // Normalize line endings; some tools paste CRLF.
    let normalized = raw.replace("\r\n", "\n");
    let mut sections = normalized.splitn(2, "\n\n");
    let head = sections.next().unwrap_or("");
    let body = sections.next().map(|s| s.to_string());

    let mut lines = head.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| RequestModelError::MalformedRaw("empty request".into()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| RequestModelError::MalformedRaw("missing method".into()))?
        .to_string();
    let target = parts
        .next()
        .ok_or_else(|| RequestModelError::MalformedRaw("missing request target".into()))?
        .to_string();

    let mut headers: HashMap<String, String> = HashMap::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(key.trim().to_string(), value.trim().to_string());
        }
    }

    let host = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.clone())
        .ok_or_else(|| RequestModelError::MalformedRaw("missing Host header".into()))?;

    // Determine scheme: honor an absolute URL, else infer from an
    // X-Forwarded-Proto hint, else default to https.
    let (scheme, host, port, path_and_query) = if target.starts_with("http://")
        || target.starts_with("https://")
    {
        let parsed = url::Url::parse(&target)
            .map_err(|e| RequestModelError::MalformedRaw(e.to_string()))?;
        let scheme = parsed.scheme().to_string();
        let host = parsed
            .host_str()
            .ok_or_else(|| RequestModelError::MalformedRaw("missing host in URL".into()))?
            .to_string();
        let port = parsed
            .port_or_known_default()
            .unwrap_or(if scheme == "https" { 443 } else { 80 });
        let pq = format!("{}{}", parsed.path(), if parsed.query().is_some() { format!("?{}", parsed.query().unwrap()) } else { String::new() });
        (scheme, host, port, pq)
    } else {
        let proto = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-forwarded-proto"))
            .map(|(_, v)| v.clone());
        let scheme = proto.unwrap_or_else(|| if host.ends_with(":443") { "https".into() } else { "https".into() });
        // Split host:port if present in the Host header.
        let (clean_host, port) = match host.split_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse::<u16>().unwrap_or(if scheme == "https" { 443 } else { 80 }),
            ),
            None => (
                host.clone(),
                if scheme == "https" { 443 } else { 80 },
            ),
        };
        (scheme, clean_host, port, target.clone())
    };

    // Separate path and query.
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (path_and_query.clone(), None),
    };
    let query_parameters: Vec<(String, String)> = query
        .map(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Extract cookies from the Cookie header and remove it from headers so
    // cookies are modeled once, in the dedicated field.
    let mut cookies = Vec::new();
    if let Some(cookie_header) = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
        .map(|(_, v)| v.clone())
    {
        cookies = super::cookies::parse_cookie_header(&cookie_header)
            .into_iter()
            .map(|c| (c.name, c.value))
            .collect();
    }
    headers.retain(|k, _| !k.eq_ignore_ascii_case("cookie"));

    // Extract authentication material into the AuthContext so it is
    // centrally managed and maskable.
    let mut authentication = AuthContext::default();
    authentication.cookie_names = cookies.iter().map(|(n, _)| n.clone()).collect();
    if let Some((_, bearer)) = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .filter(|(_, v)| v.to_lowercase().starts_with("bearer "))
        .map(|(k, v)| (k.clone(), v["bearer ".len()..].to_string()))
    {
        authentication.bearer_token = Some(bearer);
    }
    authentication.authenticated = !cookies.is_empty() || authentication.bearer_token.is_some();

    // Infer body type from Content-Type.
    let body_type = if body.is_none() || body.as_deref() == Some("") {
        BodyType::None
    } else {
        let ct = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.to_lowercase())
            .unwrap_or_default();
        if ct.contains("application/json") {
            BodyType::Json
        } else if ct.contains("application/x-www-form-urlencoded") {
            BodyType::FormUrlEncoded
        } else if ct.contains("multipart/form-data") {
            BodyType::Multipart
        } else if ct.contains("xml") {
            BodyType::Xml
        } else {
            BodyType::Raw
        }
    };

    Ok(RequestTemplate {
        id: uuid::Uuid::new_v4(),
        method: method.to_uppercase(),
        scheme,
        host,
        port,
        path,
        query_parameters,
        path_parameters: Vec::new(),
        headers,
        cookies,
        body,
        body_type,
        authentication,
        source: RequestSource::RawImport,
        created_at: chrono::Utc::now(),
    })
}

/// Render a template back to raw HTTP form for export/clipboard.
pub fn to_raw_request(template: &RequestTemplate) -> String {
    let mut out = String::new();
    let target = if template.query_parameters.is_empty() {
        template.path.clone()
    } else {
        let qs: Vec<String> = template
            .query_parameters
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        format!("{}?{}", template.path, qs.join("&"))
    };
    out.push_str(&format!("{} {} HTTP/1.1\n", template.method, target));

    // Host first, then the rest.
    let host_line = if (template.scheme == "https" && template.port == 443)
        || (template.scheme == "http" && template.port == 80)
    {
        template.host.clone()
    } else {
        format!("{}:{}", template.host, template.port)
    };
    out.push_str(&format!("Host: {host_line}\n"));

    for (k, v) in &template.headers {
        if k.eq_ignore_ascii_case("host") {
            continue;
        }
        out.push_str(&format!("{k}: {v}\n"));
    }
    if !template.cookies.is_empty() {
        let cookie_value = template
            .cookies
            .iter()
            .map(|(n, v)| format!("{n}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        out.push_str(&format!("Cookie: {cookie_value}\n"));
    }
    if let Some(token) = &template.authentication.bearer_token {
        out.push_str(&format!("Authorization: Bearer {token}\n"));
    }

    if let Some(body) = &template.body {
        out.push('\n');
        out.push_str(body);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::InputLocation;

    const SAMPLE: &str = "POST /api/search HTTP/1.1\nHost: api.example.test\nContent-Type: application/json\nAuthorization: Bearer tok123\nCookie: session=abc; tenant_id=42\nX-Account-ID: 42\n\n{\"query\":\"phone\",\"page\":1}";

    #[test]
    fn parses_method_target_and_host() {
        let t = parse_raw_request(SAMPLE).unwrap();
        assert_eq!(t.method, "POST");
        assert_eq!(t.host, "api.example.test");
        assert_eq!(t.path, "/api/search");
        assert_eq!(t.port, 443);
    }

    #[test]
    fn extracts_cookies_into_dedicated_field() {
        let t = parse_raw_request(SAMPLE).unwrap();
        assert_eq!(t.cookies.len(), 2);
        assert_eq!(t.cookies[0], ("session".into(), "abc".into()));
        // Cookie header must not survive in headers map.
        assert!(!t.headers.keys().any(|k| k.eq_ignore_ascii_case("cookie")));
    }

    #[test]
    fn extracts_bearer_token() {
        let t = parse_raw_request(SAMPLE).unwrap();
        assert_eq!(t.authentication.bearer_token.as_deref(), Some("tok123"));
        assert!(t.authentication.authenticated);
    }

    #[test]
    fn detects_json_body_type() {
        let t = parse_raw_request(SAMPLE).unwrap();
        assert_eq!(t.body_type, BodyType::Json);
        assert!(t.body.is_some());
    }

    #[test]
    fn discovers_inputs_across_all_locations() {
        let t = parse_raw_request(SAMPLE).unwrap();
        let inputs = t.inputs();
        let locs: Vec<InputLocation> = inputs.iter().map(|i| i.location).collect();
        assert!(locs.contains(&InputLocation::Json), "JSON body inputs missing");
        assert!(locs.contains(&InputLocation::Cookie), "cookie inputs missing");
        assert!(locs.contains(&InputLocation::Header), "header input missing");
    }

    #[test]
    fn roundtrip_export_reimport() {
        let t = parse_raw_request(SAMPLE).unwrap();
        let raw = to_raw_request(&t);
        let t2 = parse_raw_request(&raw).unwrap();
        assert_eq!(t2.method, t.method);
        assert_eq!(t2.path, t.path);
        assert_eq!(t2.cookies.len(), t.cookies.len());
        assert_eq!(t2.body, t.body);
    }

    #[test]
    fn absolute_url_in_request_line() {
        let raw = "GET https://api.example.test/v1/items?id=9 HTTP/1.1\nHost: api.example.test\n\n";
        let t = parse_raw_request(raw).unwrap();
        assert_eq!(t.scheme, "https");
        assert_eq!(t.host, "api.example.test");
        assert_eq!(t.query_parameters.len(), 1);
    }

    #[test]
    fn missing_host_is_error() {
        let raw = "GET /x HTTP/1.1\nUser-Agent: curl\n\n";
        assert!(parse_raw_request(raw).is_err());
    }

    #[test]
    fn crlf_line_endings_handled() {
        let raw = "GET /a?x=1 HTTP/1.1\r\nHost: h.test\r\n\r\n";
        let t = parse_raw_request(raw).unwrap();
        assert_eq!(t.host, "h.test");
        assert_eq!(t.query_parameters.len(), 1);
    }
}
