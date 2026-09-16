//! Response similarity and differential analysis (brief §13/§14).
//!
//! Compares a normalized test response against a baseline and reports the
//! structural, semantic, and timing differences. Normalization strips
//! volatile values (timestamps, IDs, CSRF tokens) so dynamic pages do not
//! produce false "differences".

use serde::{Deserialize, Serialize};

/// A lightweight response representation for comparison.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResponseSample {
    pub status: u16,
    pub body: String,
    pub duration_ms: u64,
}

/// Volatile-value patterns stripped during normalization.
const VOLATILE_PATTERNS: &[&str] = &[
    "csrf", "nonce", "token", "request_id", "trace_id", "session_id", "timestamp",
];

/// Normalize a body for comparison: collapse whitespace, strip obvious
/// volatile values, and drop hex-ish IDs. Deterministic and pure.
pub fn normalize_body(body: &str) -> String {
    // Collapse runs of whitespace so indentation differences do not count.
    let collapsed: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
    // Replace long hex/base64-ish runs (>=16 chars) with a placeholder.
    let mut normalized = String::with_capacity(collapsed.len());
    let mut run = String::new();
    for ch in collapsed.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            run.push(ch);
        } else {
            flush_run(&mut run, &mut normalized);
            normalized.push(ch);
        }
    }
    flush_run(&mut run, &mut normalized);
    normalized
}

fn flush_run(run: &mut String, out: &mut String) {
    if run.is_empty() {
        return;
    }
    // A token that is long and looks like an opaque ID → placeholder.
    let looks_opaque = run.len() >= 16
        && run.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && (run.chars().any(|c| c.is_ascii_digit()) || run.chars().all(|c| c.is_ascii_hexdigit()));
    if looks_opaque {
        out.push_str("[ID]");
    } else {
        out.push_str(run);
    }
    run.clear();
}

/// Token-level Jaccard similarity between two normalized bodies (0.0–1.0).
pub fn similarity(a: &str, b: &str) -> f32 {
    let set_a: std::collections::HashSet<&str> = a.split_whitespace().collect();
    let set_b: std::collections::HashSet<&str> = b.split_whitespace().collect();
    if set_a.is_empty() && set_b.is_empty() {
        return 1.0;
    }
    let intersection = set_a.intersection(&set_b).count() as f32;
    let union = set_a.union(&set_b).count() as f32;
    if union == 0.0 {
        1.0
    } else {
        intersection / union
    }
}

/// A structured comparison between baseline and test responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseDifference {
    pub status_changed: bool,
    /// 0.0 = identical, 1.0 = entirely different.
    pub body_dissimilarity: f32,
    pub length_delta: i64,
    pub timing_delta_ms: i64,
    /// Whether the difference is large enough to be meaningful (> 0.1).
    pub significant: bool,
}

impl ResponseDifference {
    /// Compare a baseline and test response. `None` only when timing stats
    /// cannot be formed (never — both samples carry a duration).
    pub fn compute(baseline: &ResponseSample, test: &ResponseSample) -> Self {
        let nb = normalize_body(&baseline.body);
        let nt = normalize_body(&test.body);
        let sim = similarity(&nb, &nt);
        let dissimilarity = 1.0 - sim;
        Self {
            status_changed: baseline.status != test.status,
            body_dissimilarity: dissimilarity,
            length_delta: test.body.len() as i64 - baseline.body.len() as i64,
            timing_delta_ms: test.duration_ms as i64 - baseline.duration_ms as i64,
            significant: dissimilarity > 0.1 || baseline.status != test.status,
        }
    }

    /// Human summary for the UI.
    pub fn summary(&self) -> String {
        if !self.significant {
            return "No meaningful difference from baseline.".to_string();
        }
        let mut parts = Vec::new();
        if self.status_changed {
            parts.push("status changed".to_string());
        }
        if self.body_dissimilarity > 0.1 {
            parts.push(format!("body {:.0}% different", self.body_dissimilarity * 100.0));
        }
        if self.length_delta != 0 {
            parts.push(format!("length {:+} bytes", self.length_delta));
        }
        if self.timing_delta_ms.abs() > 200 {
            parts.push(format!("timing {:+}ms", self.timing_delta_ms));
        }
        parts.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(status: u16, body: &str, ms: u64) -> ResponseSample {
        ResponseSample {
            status,
            body: body.to_string(),
            duration_ms: ms,
        }
    }

    #[test]
    fn identical_bodies_have_zero_dissimilarity() {
        let d = ResponseDifference::compute(&sample(200, "hello world", 100), &sample(200, "hello world", 105));
        assert_eq!(d.body_dissimilarity, 0.0);
        assert!(!d.significant);
    }

    #[test]
    fn volatile_ids_are_normalized_away() {
        // Two responses differing only in an opaque ID must look identical.
        let a = sample(200, "record 550e8400e29b41d4a716446655440000 found", 100);
        let b = sample(200, "record ffffeeee111122223333444455556666 found", 100);
        let d = ResponseDifference::compute(&a, &b);
        assert!(!d.significant, "ID-only difference must not be significant: {d:?}");
    }

    #[test]
    fn real_content_difference_detected() {
        let d = ResponseDifference::compute(
            &sample(200, "product found name phone price 100", 100),
            &sample(200, "no results available for query", 100),
        );
        assert!(d.significant);
        assert!(d.body_dissimilarity > 0.5);
    }

    #[test]
    fn status_change_is_always_significant() {
        let d = ResponseDifference::compute(&sample(200, "same", 100), &sample(500, "same", 100));
        assert!(d.status_changed);
        assert!(d.significant);
    }

    #[test]
    fn whitespace_differences_ignored() {
        let d = ResponseDifference::compute(
            &sample(200, "<div>\n  <p>hi</p>\n</div>", 100),
            &sample(200, "<div> <p>hi</p> </div>", 100),
        );
        assert_eq!(d.body_dissimilarity, 0.0);
    }

    #[test]
    fn length_and_timing_deltas_reported() {
        let d = ResponseDifference::compute(&sample(200, "abc", 100), &sample(200, "abcdef", 900));
        assert_eq!(d.length_delta, 3);
        assert_eq!(d.timing_delta_ms, 800);
        assert!(d.summary().contains("length"));
    }

    #[test]
    fn empty_bodies_are_identical() {
        assert_eq!(similarity("", ""), 1.0);
    }
}
