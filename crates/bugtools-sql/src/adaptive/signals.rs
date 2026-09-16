//! Response signal extraction (brief §3).
//!
//! The root cause of `signals = []`: the engine only recorded a signal when
//! it matched a DBMS error string. This module extracts *typed observations*
//! from every response comparison, so a scan that finds no SQLi still reports
//! what it actually saw.

use crate::analysis::environment::{classify_environment, EnvironmentClass};
use serde::{Deserialize, Serialize};

/// A typed signal extracted from a response comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    StatusChanged,
    BodyStructureChanged,
    BodySimilarityChanged,
    LengthChanged,
    JsonStructureChanged,
    ErrorSignatureChanged,
    RedirectChanged,
    HeaderChanged,
    CookieChanged,
    TimingShift,
    TimingVariance,
    ReflectionChanged,
    ValidationChanged,
    WafBlock,
    WafChallenge,
    RateLimit,
    AuthenticationFailure,
    ApplicationError,
    BackendError,
    /// No difference was observed — itself a meaningful observation.
    NoDifference,
}

impl SignalKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::StatusChanged => "status_changed",
            Self::BodyStructureChanged => "body_structure_changed",
            Self::BodySimilarityChanged => "body_similarity_changed",
            Self::LengthChanged => "length_changed",
            Self::JsonStructureChanged => "json_structure_changed",
            Self::ErrorSignatureChanged => "error_signature_changed",
            Self::RedirectChanged => "redirect_changed",
            Self::HeaderChanged => "header_changed",
            Self::CookieChanged => "cookie_changed",
            Self::TimingShift => "timing_shift",
            Self::TimingVariance => "timing_variance",
            Self::ReflectionChanged => "reflection_changed",
            Self::ValidationChanged => "validation_changed",
            Self::WafBlock => "waf_block",
            Self::WafChallenge => "waf_challenge",
            Self::RateLimit => "rate_limit",
            Self::AuthenticationFailure => "authentication_failure",
            Self::ApplicationError => "application_error",
            Self::BackendError => "backend_error",
            Self::NoDifference => "no_difference",
        }
    }

    /// Whether this signal can support a SQL-interaction hypothesis. Edge and
    /// auth signals explicitly cannot.
    pub fn supports_sql_hypothesis(&self) -> bool {
        matches!(
            self,
            Self::StatusChanged
                | Self::BodyStructureChanged
                | Self::BodySimilarityChanged
                | Self::LengthChanged
                | Self::JsonStructureChanged
                | Self::ErrorSignatureChanged
                | Self::ReflectionChanged
                | Self::TimingShift
        )
    }

    /// Whether this signal indicates the environment blocked us.
    pub fn is_environmental(&self) -> bool {
        matches!(
            self,
            Self::WafBlock
                | Self::WafChallenge
                | Self::RateLimit
                | Self::AuthenticationFailure
                | Self::BackendError
        )
    }
}

/// A signal with its strength and provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    pub kind: SignalKind,
    /// 0.0–1.0. A weak signal stays weak — this is not inflated.
    pub strength: f32,
    /// Which baseline this was compared against.
    pub baseline_reference: String,
    /// Which observation produced it.
    pub observation_reference: String,
    pub confidence: f32,
}

impl Signal {
    pub fn new(
        kind: SignalKind,
        strength: f32,
        baseline_reference: impl Into<String>,
        observation_reference: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            strength: strength.clamp(0.0, 1.0),
            baseline_reference: baseline_reference.into(),
            observation_reference: observation_reference.into(),
            confidence: strength.clamp(0.0, 1.0),
        }
    }

    pub fn label(&self) -> &'static str {
        self.kind.label()
    }
}

/// A minimal response view the extractor reasons over. Keeps this module
/// decoupled from the full HTTP type so it is unit-testable.
#[derive(Debug, Clone, PartialEq)]
pub struct ResponseView {
    pub status: u16,
    pub body: String,
    pub body_len: usize,
    pub content_type: Option<String>,
    pub location: Option<String>,
    pub duration_ms: u64,
    /// Header names+values, lowercased names.
    pub headers: Vec<(String, String)>,
    /// A stable hash of the normalized body.
    pub normalized_hash: String,
}

impl ResponseView {
    pub fn simple(status: u16, body: &str, duration_ms: u64) -> Self {
        Self {
            status,
            body: body.to_string(),
            body_len: body.len(),
            content_type: None,
            location: None,
            duration_ms,
            headers: Vec::new(),
            normalized_hash: normalize(body),
        }
    }
}

/// Normalize a body for comparison: collapse whitespace, blank opaque IDs.
pub fn normalize(body: &str) -> String {
    let collapsed: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut out = String::with_capacity(collapsed.len());
    let mut run = String::new();
    for ch in collapsed.chars() {
        if ch.is_ascii_alphanumeric() {
            run.push(ch);
        } else {
            flush(&mut run, &mut out);
            out.push(ch);
        }
    }
    flush(&mut run, &mut out);
    out
}

fn flush(run: &mut String, out: &mut String) {
    if run.is_empty() {
        return;
    }
    if run.len() >= 16 && run.chars().any(|c| c.is_ascii_digit()) {
        out.push_str("[ID]");
    } else {
        out.push_str(run);
    }
    run.clear();
}

/// Token-level Jaccard similarity over normalized bodies.
pub fn similarity(a: &str, b: &str) -> f32 {
    let sa: std::collections::HashSet<&str> = a.split_whitespace().collect();
    let sb: std::collections::HashSet<&str> = b.split_whitespace().collect();
    if sa.is_empty() && sb.is_empty() {
        return 1.0;
    }
    let inter = sa.intersection(&sb).count() as f32;
    let union = sa.union(&sb).count() as f32;
    if union == 0.0 { 1.0 } else { inter / union }
}

/// Extract every signal from comparing a baseline against an observation.
///
/// Always returns at least one signal: `NoDifference` when nothing changed.
/// This is the guarantee that `signals` is never empty.
pub fn extract_signals(
    baseline: &ResponseView,
    observed: &ResponseView,
    baseline_ref: &str,
    observation_ref: &str,
) -> Vec<Signal> {
    let mut signals = Vec::new();

    // ── Database error text takes precedence over a generic backend error:
    //    a 500 whose body carries a DBMS signature is *evidence*, not
    //    environmental noise.
    let error_detection = crate::detection::analyze_error_body(&observed.body);
    let has_dbms_signature = error_detection.detected_dbms.is_some();
    if has_dbms_signature {
        signals.push(Signal::new(
            SignalKind::ErrorSignatureChanged,
            0.8,
            baseline_ref,
            observation_ref,
        ));
    }

    // ── Environment classification. A database signature means the request
    //    reached the application, so we do not label it a backend error.
    let env = if has_dbms_signature {
        crate::analysis::environment::EnvironmentClass::Normal
    } else {
        classify_environment(
        observed.status,
        &observed
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect::<Vec<_>>(),
            &observed.body,
        )
    };
    match env {
        EnvironmentClass::WafChallenge => {
            // Distinguish an outright block from an interactive challenge:
            // a block returns a denial body; a challenge returns a page that
            // asks the client to prove itself.
            let body_lower = observed.body.to_lowercase();
            let looks_like_block = body_lower.contains("blocked")
                || body_lower.contains("access denied")
                || body_lower.contains("modsecurity");
            signals.push(Signal::new(
                if looks_like_block {
                    SignalKind::WafBlock
                } else {
                    SignalKind::WafChallenge
                },
                0.9,
                baseline_ref,
                observation_ref,
            ));
        }
        EnvironmentClass::Forbidden => signals.push(Signal::new(
            SignalKind::WafBlock,
            0.7,
            baseline_ref,
            observation_ref,
        )),
        EnvironmentClass::BotProtection => signals.push(Signal::new(
            SignalKind::WafChallenge,
            0.9,
            baseline_ref,
            observation_ref,
        )),
        EnvironmentClass::RateLimited => signals.push(Signal::new(
            SignalKind::RateLimit,
            0.9,
            baseline_ref,
            observation_ref,
        )),
        EnvironmentClass::AuthFailure => signals.push(Signal::new(
            SignalKind::AuthenticationFailure,
            0.9,
            baseline_ref,
            observation_ref,
        )),
        EnvironmentClass::ServerError => signals.push(Signal::new(
            SignalKind::BackendError,
            0.6,
            baseline_ref,
            observation_ref,
        )),
        EnvironmentClass::ApplicationError => signals.push(Signal::new(
            SignalKind::ApplicationError,
            0.5,
            baseline_ref,
            observation_ref,
        )),
        _ => {}
    }

    // ── Status.
    if baseline.status != observed.status {
        signals.push(Signal::new(
            SignalKind::StatusChanged,
            0.7,
            baseline_ref,
            observation_ref,
        ));
    }

    // ── Body similarity and structure.
    let sim = similarity(&baseline.normalized_hash, &observed.normalized_hash);
    if sim < 0.999 {
        let strength = (1.0 - sim).clamp(0.0, 1.0);
        signals.push(Signal::new(
            SignalKind::BodySimilarityChanged,
            strength,
            baseline_ref,
            observation_ref,
        ));
    }

    // ── Length (secondary to similarity, never the sole signal).
    if baseline.body_len != observed.body_len {
        let delta = (baseline.body_len as i64 - observed.body_len as i64).unsigned_abs() as f32;
        let strength = (delta / 200.0).clamp(0.05, 0.6);
        signals.push(Signal::new(
            SignalKind::LengthChanged,
            strength,
            baseline_ref,
            observation_ref,
        ));
    }

    // ── JSON structure.
    let base_json = serde_json::from_str::<serde_json::Value>(&baseline.body).ok();
    let obs_json = serde_json::from_str::<serde_json::Value>(&observed.body).ok();
    if let (Some(b), Some(o)) = (&base_json, &obs_json) {
        if json_shape(b) != json_shape(o) {
            signals.push(Signal::new(
                SignalKind::JsonStructureChanged,
                0.6,
                baseline_ref,
                observation_ref,
            ));
        }
    }

    // ── Content type / redirect / headers.
    if baseline.content_type != observed.content_type {
        signals.push(Signal::new(
            SignalKind::HeaderChanged,
            0.4,
            baseline_ref,
            observation_ref,
        ));
    }
    if baseline.location != observed.location {
        signals.push(Signal::new(
            SignalKind::RedirectChanged,
            0.5,
            baseline_ref,
            observation_ref,
        ));
    }

    // ── Timing: a shift beyond a modest threshold, reported as weak unless
    //    large. Statistical separation is decided by the timing engine, not
    //    here — this is a raw observation.
    let base_ms = baseline.duration_ms.max(1) as f32;
    let obs_ms = observed.duration_ms as f32;
    let ratio = obs_ms / base_ms;
    if ratio > 1.5 {
        signals.push(Signal::new(
            SignalKind::TimingShift,
            ((ratio - 1.5) / 5.0).clamp(0.1, 0.7),
            baseline_ref,
            observation_ref,
        ));
    }

    // ── Nothing at all?
    if signals.is_empty() {
        signals.push(Signal::new(
            SignalKind::NoDifference,
            0.0,
            baseline_ref,
            observation_ref,
        ));
    }

    signals
}

/// A coarse JSON shape signature (keys and nesting types, not values).
fn json_shape(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<String> = map
                .iter()
                .map(|(k, v)| format!("{k}:{}", json_shape(v)))
                .collect();
            keys.sort();
            format!("{{{}}}", keys.join(","))
        }
        serde_json::Value::Array(items) => {
            format!("[{}]", items.first().map(json_shape).unwrap_or_default())
        }
        serde_json::Value::String(_) => "s".into(),
        serde_json::Value::Number(_) => "n".into(),
        serde_json::Value::Bool(_) => "b".into(),
        serde_json::Value::Null => "z".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_responses_yield_no_difference() {
        let base = ResponseView::simple(200, "same body", 100);
        let signals = extract_signals(&base, &base, "b1", "o1");
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].kind, SignalKind::NoDifference);
    }

    #[test]
    fn signals_are_never_empty_even_without_sqli() {
        // The core fix: a clean comparison still produces a typed signal.
        let base = ResponseView::simple(200, "hello", 50);
        let obs = ResponseView::simple(200, "hello", 52);
        let signals = extract_signals(&base, &obs, "b", "o");
        assert!(!signals.is_empty(), "signals must never be empty");
    }

    #[test]
    fn status_change_produces_signal() {
        let base = ResponseView::simple(200, "ok", 50);
        let obs = ResponseView::simple(500, "ok", 50);
        let signals = extract_signals(&base, &obs, "b", "o");
        assert!(signals.iter().any(|s| s.kind == SignalKind::StatusChanged));
    }

    #[test]
    fn body_change_produces_similarity_signal() {
        let base = ResponseView::simple(200, "product found name phone price", 50);
        let obs = ResponseView::simple(200, "no results available", 50);
        let signals = extract_signals(&base, &obs, "b", "o");
        assert!(signals
            .iter()
            .any(|s| s.kind == SignalKind::BodySimilarityChanged));
    }

    #[test]
    fn waf_block_is_classified_not_read_as_sql() {
        let base = ResponseView::simple(200, "ok", 50);
        let mut obs = ResponseView::simple(403, "Request blocked by ModSecurity", 50);
        obs.headers.push(("server".into(), "cloudflare".into()));
        let signals = extract_signals(&base, &obs, "b", "o");
        let waf = signals.iter().find(|s| s.kind == SignalKind::WafBlock);
        assert!(waf.is_some(), "WAF block not classified");
        assert!(!waf.unwrap().kind.supports_sql_hypothesis());
    }

    #[test]
    fn timing_shift_only_on_significant_ratio() {
        let base = ResponseView::simple(200, "x", 100);
        let fast = ResponseView::simple(200, "x", 110);
        assert!(!extract_signals(&base, &fast, "b", "o")
            .iter()
            .any(|s| s.kind == SignalKind::TimingShift));

        let slow = ResponseView::simple(200, "x", 5000);
        assert!(extract_signals(&base, &slow, "b", "o")
            .iter()
            .any(|s| s.kind == SignalKind::TimingShift));
    }

    #[test]
    fn json_shape_change_detected() {
        let base = ResponseView::simple(200, r#"{"a":1,"b":2}"#, 50);
        let obs = ResponseView::simple(200, r#"{"a":1}"#, 50);
        let signals = extract_signals(&base, &obs, "b", "o");
        assert!(signals.iter().any(|s| s.kind == SignalKind::JsonStructureChanged));
    }

    #[test]
    fn weak_signal_stays_weak() {
        let base = ResponseView::simple(200, "a b c d e f g h", 50);
        let obs = ResponseView::simple(200, "a b c d e f g h i", 50);
        let signals = extract_signals(&base, &obs, "b", "o");
        let length = signals.iter().find(|s| s.kind == SignalKind::LengthChanged);
        if let Some(sig) = length {
            assert!(sig.strength <= 0.6, "a tiny length change was over-weighted");
        }
    }

    #[test]
    fn opaque_ids_normalized_for_comparison() {
        let a = normalize("record 550e8400e29b41d4a716446655440000 found");
        let b = normalize("record ffffeeee111122223333444455556666 found");
        assert_eq!(a, b, "opaque IDs should normalize away");
    }

    #[test]
    fn signal_labels_are_stable() {
        assert_eq!(SignalKind::StatusChanged.label(), "status_changed");
        assert_eq!(SignalKind::NoDifference.label(), "no_difference");
    }
}
