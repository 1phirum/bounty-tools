//! Certificate Transparency discovery source.
//!
//! Queries public CT logs (crt.sh) for certificates naming the target
//! domain. This is a direct HTTP query implemented with our own client —
//! no external tool is invoked.

use super::super::models::{AssetSource, DiscoveredAsset, DiscoveryError, DiscoverySource, Target};
use async_trait::async_trait;
use std::time::Duration;

pub struct CertificateTransparencySource {
    client: reqwest::Client,
    endpoint: String,
}

impl Default for CertificateTransparencySource {
    fn default() -> Self {
        Self::new()
    }
}

impl CertificateTransparencySource {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .user_agent("BugTools/0.1 (native discovery engine)")
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            client,
            endpoint: "https://crt.sh/".to_string(),
        }
    }

    /// Override the CT endpoint (used by tests with a local fixture server).
    pub fn with_endpoint(endpoint: impl Into<String>) -> Self {
        let mut s = Self::new();
        s.endpoint = endpoint.into();
        s
    }

    /// Parse a crt.sh JSON response into hostnames.
    ///
    /// Split out from the network call so it is unit-testable without I/O.
    pub fn parse_response(&self, body: &str, domain: &str) -> Vec<String> {
        #[derive(serde::Deserialize)]
        struct Entry {
            name_value: String,
        }
        let entries: Vec<Entry> = match serde_json::from_str(body) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };
        let mut hosts = Vec::new();
        for entry in entries {
            for name in entry.name_value.split('\n') {
                let clean = name.trim().trim_start_matches("*.").to_lowercase();
                if clean.is_empty() {
                    continue;
                }
                // Only keep names under the requested domain.
                if clean == domain || clean.ends_with(&format!(".{domain}")) {
                    hosts.push(clean);
                }
            }
        }
        hosts.sort();
        hosts.dedup();
        hosts
    }
}

#[async_trait]
impl DiscoverySource for CertificateTransparencySource {
    fn name(&self) -> &'static str {
        "certificate-transparency"
    }

    fn asset_source(&self) -> AssetSource {
        AssetSource::CertificateTransparency
    }

    async fn discover(&self, target: &Target) -> Result<Vec<DiscoveredAsset>, DiscoveryError> {
        let url = format!("{}?q=%25.{}&output=json", self.endpoint, target.domain);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| DiscoveryError::Network(e.to_string()))?;
        if !response.status().is_success() {
            return Err(DiscoveryError::SourceUnavailable(format!(
                "crt.sh returned {}",
                response.status()
            )));
        }
        let body = response
            .text()
            .await
            .map_err(|e| DiscoveryError::Network(e.to_string()))?;
        Ok(self
            .parse_response(&body, &target.domain)
            .into_iter()
            .map(|hostname| DiscoveredAsset {
                hostname,
                source: AssetSource::CertificateTransparency,
                detail: Some("crt.sh".into()),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_filters_ct_response() {
        let source = CertificateTransparencySource::new();
        let body = r#"[
            {"name_value": "api.example.com\nwww.example.com"},
            {"name_value": "*.example.com"},
            {"name_value": "unrelated.other.test"}
        ]"#;
        let hosts = source.parse_response(body, "example.com");
        assert!(hosts.contains(&"api.example.com".to_string()));
        assert!(hosts.contains(&"www.example.com".to_string()));
        assert!(hosts.contains(&"example.com".to_string()), "wildcard should strip *. to apex");
        assert!(!hosts.iter().any(|h| h.contains("other.test")));
    }

    #[test]
    fn invalid_json_yields_no_hosts() {
        let source = CertificateTransparencySource::new();
        assert!(source.parse_response("<html>error</html>", "example.com").is_empty());
    }

    #[test]
    fn deduplicates_repeated_names() {
        let source = CertificateTransparencySource::new();
        let body = r#"[{"name_value":"api.example.com"},{"name_value":"api.example.com"}]"#;
        assert_eq!(source.parse_response(body, "example.com").len(), 1);
    }
}
