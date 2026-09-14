use regex::Regex;
use std::collections::HashSet;
use url::Url;

pub struct EndpointParser {
    url_pattern: Regex,
    js_endpoint_pattern: Regex,
}

impl Default for EndpointParser {
    fn default() -> Self {
        Self {
            url_pattern: Regex::new(r#"https?://[a-zA-Z0-9.-]+(?::[0-9]+)?(?:/[a-zA-Z0-9_./?%&=-]*)?"#).unwrap(),
            js_endpoint_pattern: Regex::new(r#"["'](/(?:api|v[0-9]+)/[a-zA-Z0-9_./?%&=-]*)["']"#).unwrap(),
        }
    }
}

impl EndpointParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn extract_urls(&self, text: &str) -> Vec<String> {
        let mut results = HashSet::new();
        for m in self.url_pattern.find_iter(text) {
            if let Ok(u) = Url::parse(m.as_str()) {
                results.insert(u.to_string());
            }
        }
        results.into_iter().collect()
    }

    pub fn extract_endpoints(&self, js_source: &str) -> Vec<String> {
        let mut results = HashSet::new();
        for cap in self.js_endpoint_pattern.captures_iter(js_source) {
            if let Some(endpoint) = cap.get(1) {
                results.insert(endpoint.as_str().to_string());
            }
        }
        results.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_endpoints() {
        let parser = EndpointParser::new();
        let js = r#"const api = "/api/v1/users"; fetch('/api/v2/orders')"#;
        let endpoints = parser.extract_endpoints(js);
        assert_eq!(endpoints.len(), 2);
    }
}
