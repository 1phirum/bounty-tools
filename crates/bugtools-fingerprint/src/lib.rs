use bugtools_core::http::{HttpResponse, ResponseFingerprint};
use regex::Regex;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub struct ResponseFingerprinter {
    ts_regex: Regex,
    hex_id_regex: Regex,
}

impl Default for ResponseFingerprinter {
    fn default() -> Self {
        Self {
            ts_regex: Regex::new(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?\b").unwrap(),
            hex_id_regex: Regex::new(r"\b[0-9a-fA-F]{16,64}\b").unwrap(),
        }
    }
}

impl ResponseFingerprinter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn normalize_body(&self, body: &str) -> String {
        let step1 = self.ts_regex.replace_all(body, "[NORMALIZED_TIMESTAMP]");
        let step2 = self.hex_id_regex.replace_all(&step1, "[NORMALIZED_ID]");
        step2.to_string()
    }

    pub fn compute_hash(&self, content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub fn fingerprint(&self, resp: &HttpResponse) -> ResponseFingerprint {
        let raw_hash = self.compute_hash(&resp.body);
        let normalized = self.normalize_body(&resp.body);
        let normalized_hash = self.compute_hash(&normalized);

        let content_type = resp
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.clone());

        let redirect_location = resp
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("location"))
            .map(|(_, v)| v.clone());

        let structural_sig = format!(
            "STATUS:{};TYPE:{};LEN_BUCKET:{};LINES:{}",
            resp.status_code,
            content_type.as_deref().unwrap_or("unknown"),
            resp.size_bytes / 100 * 100,
            resp.body.lines().count()
        );

        ResponseFingerprint {
            id: Uuid::new_v4(),
            response_id: resp.id,
            status: resp.status_code,
            content_type,
            content_length: resp.size_bytes,
            body_hash: raw_hash,
            normalized_body_hash: normalized_hash,
            redirect_location,
            response_time_ms: resp.duration_ms,
            structural_signature: structural_sig,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_normalization() {
        let fingerprinter = ResponseFingerprinter::new();
        let body1 = r#"{"time": "2026-09-14T23:59:00Z", "token": "a1b2c3d4e5f60718293a4b5c6d7e8f90", "error": "None"}"#;
        let body2 = r#"{"time": "2026-09-15T00:00:00Z", "token": "f9e8d7c6b5a43210f9e8d7c6b5a43210", "error": "None"}"#;

        let norm1 = fingerprinter.normalize_body(body1);
        let norm2 = fingerprinter.normalize_body(body2);

        assert_eq!(norm1, norm2);
        assert_eq!(fingerprinter.compute_hash(&norm1), fingerprinter.compute_hash(&norm2));
    }
}
