//! Bring-your-own-collector provider.
//!
//! The operator already runs a callback listener — Burp Collaborator, a custom
//! authoritative DNS logger, an interactsh instance fronted by their own API —
//! and gives us two things: the callback domain, and a way to read the
//! interactions it recorded (an HTTP endpoint returning JSON, or a file that
//! endpoint writes). We never assume anything about the collector beyond that
//! it emits `OobInteraction` records.

use super::correlator::OobInteraction;
use super::provider::{OobProvider, OobResult};
use async_trait::async_trait;
use std::path::PathBuf;

/// Where a `ByocProvider` reads its interactions from.
#[derive(Debug, Clone)]
pub enum PollSource {
    /// An HTTP(S) endpoint returning a JSON array of `OobInteraction`.
    Url(String),
    /// A local file the collector appends interactions to as JSON.
    File(PathBuf),
}

/// A collector the operator owns and configures explicitly.
pub struct ByocProvider {
    domain: String,
    source: PollSource,
    /// A PLAIN client — the collector is the operator's own host, deliberately
    /// off-target, so it must NOT go through the scoped `SafeHttpClient`.
    client: reqwest::Client,
}

impl ByocProvider {
    pub fn new(domain: impl Into<String>, source: PollSource) -> Self {
        Self {
            domain: domain.into(),
            source,
            client: reqwest::Client::new(),
        }
    }
}

/// Normalize a logged identifier for containment correlation.
///
/// A collector records the full queried FQDN. Our OOB exfil payloads produce
/// `<leaked-data>.<planted-token>.<collector-id>.<collector-domain>`, so the
/// planted token is an *interior* label — never reliably the leftmost one.
/// We therefore keep the whole identifier (case-folded) and let
/// [`OobCorrelator::correlate_contains`] find the planted token inside it,
/// rather than chopping to a single label and risking dropping the token.
pub(crate) fn normalize_token(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

#[async_trait]
impl OobProvider for ByocProvider {
    async fn register(&mut self) -> OobResult<String> {
        // Nothing to negotiate: the operator supplied the domain.
        Ok(self.domain.clone())
    }

    async fn poll(&mut self) -> OobResult<Vec<OobInteraction>> {
        let raw = match &self.source {
            PollSource::Url(url) => {
                let resp = self.client.get(url).send().await?;
                let status = resp.status();
                if !status.is_success() {
                    return Err(format!("collector poll returned HTTP {status}").into());
                }
                resp.text().await?
            }
            PollSource::File(path) => match std::fs::read_to_string(path) {
                Ok(s) => s,
                // A collector that has not written anything yet is not an error.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
                Err(e) => return Err(e.into()),
            },
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(Vec::new());
        }
        let mut parsed: Vec<OobInteraction> = serde_json::from_str(trimmed)?;
        for i in &mut parsed {
            i.token = normalize_token(&i.token);
        }
        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oob::correlator::{OobCorrelator, OobToken};
    use std::io::Write;

    #[tokio::test]
    async fn file_poll_parses_and_correlates_planted_token() {
        // A planted token, and a collector fixture that logged the full FQDN.
        let token = OobToken::mint("bt", "example.test", "/api", "q", "query", 300);
        let observed = token.planted_at + 5;
        let fqdn = token.callback_host("c0abc.oast.example");
        let fixture = format!(
            r#"[{{"token":"{fqdn}","interaction_type":"dns","observed_at":{observed},"source":"203.0.113.9"}}]"#
        );
        let mut f = tempfile();
        f.write_all(fixture.as_bytes()).unwrap();
        let path = f.path();

        let mut provider = ByocProvider::new("c0abc.oast.example", PollSource::File(path.clone()));
        let interactions = provider.poll().await.unwrap();
        assert_eq!(interactions.len(), 1);
        // The full FQDN is retained (case-folded); the planted token is an
        // interior label the correlator locates by containment.
        assert!(interactions[0].token.contains(&token.token));

        let mut correlator = OobCorrelator::new();
        correlator.plant(token.clone());
        let (matched, unmatched) = correlator.correlate_batch_contains(&interactions);
        assert_eq!(matched.len(), 1, "planted token should correlate");
        assert!(unmatched.is_empty());
        assert_eq!(matched[0].parameter, "q");
    }

    #[tokio::test]
    async fn file_poll_rejects_foreign_token() {
        let observed = chrono::Utc::now().timestamp();
        let fixture = format!(
            r#"[{{"token":"someone-else.oast.example","interaction_type":"http","observed_at":{observed},"source":"9.9.9.9"}}]"#
        );
        let mut f = tempfile();
        f.write_all(fixture.as_bytes()).unwrap();

        let mut provider = ByocProvider::new("oast.example", PollSource::File(f.path()));
        let interactions = provider.poll().await.unwrap();

        // Nothing planted → nothing correlates. Stray traffic is never evidence.
        let correlator = OobCorrelator::new();
        let (matched, unmatched) = correlator.correlate_batch_contains(&interactions);
        assert!(matched.is_empty());
        assert_eq!(unmatched.len(), 1);
        
    }

    #[tokio::test]
    async fn missing_file_is_empty_not_error() {
        let mut provider = ByocProvider::new(
            "oast.example",
            PollSource::File(PathBuf::from("does-not-exist-oob.json")),
        );
        assert!(provider.poll().await.unwrap().is_empty());
    }

    /// A throwaway temp file that cleans itself up.
    struct TempFile {
        path: PathBuf,
    }
    impl TempFile {
        fn path(&self) -> PathBuf {
            self.path.clone()
        }
    }
    impl std::io::Write for TempFile {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
            f.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
    fn tempfile() -> TempFile {
        let path = std::env::temp_dir().join(format!("oob-byoc-{}.json", uuid::Uuid::new_v4()));
        TempFile { path }
    }
}
