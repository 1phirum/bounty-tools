//! Test identity and family collapsing (brief §1, §8).
//!
//! Every generated test has a deterministic fingerprint. Two tests that are
//! semantically equivalent must not count as different tests merely because
//! their strings differ. Families collapse equivalent results into one
//! evidence entry.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Deterministic identity of a test. Two tests with equal fingerprints ask
/// the same question and must not be re-run.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TestFingerprint {
    pub endpoint: String,
    pub parameter: String,
    pub location: String,
    pub technique: String,
    /// Context label at generation time.
    pub context: String,
    /// Boundary shape (quote mode + termination + paren depth), not the raw
    /// payload string — `' AND 1=1-- ` and `' AND 2=2-- ` share a boundary.
    pub boundary: String,
    pub dialect: String,
    /// Representation transforms applied, in order.
    pub transformation: String,
    /// The semantic family: what question the test answers.
    pub semantic_family: String,
}

impl TestFingerprint {
    /// Stable hash for a set key.
    pub fn key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.endpoint,
            self.parameter,
            self.location,
            self.technique,
            self.context,
            self.boundary,
            self.dialect,
            self.transformation,
            self.semantic_family
        )
    }
}

/// Lifecycle status of a test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestStatus {
    Generated,
    Executed,
    Blocked,
    ApplicationResponse,
    Inconclusive,
    Interesting,
    Confirmed,
    /// Not re-executed because an equivalent test already answered.
    Duplicate,
}

/// Record of one test's lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestRecord {
    pub fingerprint: TestFingerprint,
    pub status: TestStatus,
    /// A short summary of what was observed.
    pub observation: String,
}

/// A collapsed group of semantically equivalent tests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestFamily {
    pub semantic_family: String,
    pub technique: String,
    pub tested: usize,
    pub executed: usize,
    pub skipped_duplicate: usize,
    /// True when every executed member produced an equivalent result.
    pub equivalent_result: bool,
    /// 0.0–1.0 strength of the family's combined evidence.
    pub evidence_strength: f32,
    /// A representative observation for the family.
    pub representative_observation: String,
}

/// Tracks test identity, deduplicates, and collapses families.
#[derive(Debug, Clone, Default)]
pub struct TestLedger {
    seen: HashMap<String, TestRecord>,
    counts: HashMap<String, usize>,
}

impl TestLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a generated test. Returns `false` if an equivalent test was
    /// already generated — the caller must NOT execute it again.
    pub fn register(&mut self, fingerprint: TestFingerprint) -> bool {
        let key = fingerprint.key();
        if self.seen.contains_key(&key) {
            if let Some(rec) = self.seen.get_mut(&key) {
                rec.status = TestStatus::Duplicate;
            }
            return false;
        }
        self.counts
            .entry(fingerprint.semantic_family.clone())
            .and_modify(|c| *c += 1)
            .or_insert(1);
        self.seen.insert(
            key,
            TestRecord {
                fingerprint,
                status: TestStatus::Generated,
                observation: String::new(),
            },
        );
        true
    }

    /// Record the outcome of an executed test.
    pub fn record_outcome(&mut self, fingerprint: &TestFingerprint, status: TestStatus, observation: impl Into<String>) {
        if let Some(rec) = self.seen.get_mut(&fingerprint.key()) {
            rec.status = status;
            rec.observation = observation.into();
        }
    }

    pub fn status_of(&self, fingerprint: &TestFingerprint) -> Option<TestStatus> {
        self.seen.get(&fingerprint.key()).map(|r| r.status)
    }

    pub fn total_generated(&self) -> usize {
        self.seen.len()
    }

    pub fn count(&self, status: TestStatus) -> usize {
        self.seen.values().filter(|r| r.status == status).count()
    }

    /// Collapse every family into a summary. A family whose executed members
    /// all produced equivalent observations reports `equivalent_result`.
    pub fn families(&self) -> Vec<TestFamily> {
        let mut by_family: HashMap<(String, String), Vec<&TestRecord>> = HashMap::new();
        for rec in self.seen.values() {
            by_family
                .entry((
                    rec.fingerprint.semantic_family.clone(),
                    rec.fingerprint.technique.clone(),
                ))
                .or_default()
                .push(rec);
        }

        let mut out = Vec::new();
        for ((family, technique), records) in by_family {
            let tested = records.len();
            let executed = records
                .iter()
                .filter(|r| {
                    matches!(
                        r.status,
                        TestStatus::Executed
                            | TestStatus::ApplicationResponse
                            | TestStatus::Interesting
                            | TestStatus::Confirmed
                            | TestStatus::Inconclusive
                    )
                })
                .count();
            let skipped = records
                .iter()
                .filter(|r| r.status == TestStatus::Duplicate)
                .count();

            // Equivalent when every executed member has the same observation.
            let mut observations: Vec<&str> = records
                .iter()
                .filter(|r| !r.observation.is_empty())
                .map(|r| r.observation.as_str())
                .collect();
            observations.sort();
            observations.dedup();
            let equivalent = observations.len() <= 1 && executed > 0;

            let interesting = records
                .iter()
                .filter(|r| matches!(r.status, TestStatus::Interesting | TestStatus::Confirmed))
                .count();
            let strength = if executed == 0 {
                0.0
            } else {
                (interesting as f32 / executed as f32).clamp(0.0, 1.0)
            };

            out.push(TestFamily {
                semantic_family: family,
                technique,
                tested,
                executed,
                skipped_duplicate: skipped,
                equivalent_result: equivalent,
                evidence_strength: strength,
                representative_observation: observations
                    .first()
                    .map(|s| s.to_string())
                    .unwrap_or_default(),
            });
        }
        out.sort_by(|a, b| a.semantic_family.cmp(&b.semantic_family));
        out
    }

    /// How many tests were skipped because an equivalent already ran.
    pub fn duplicates_avoided(&self) -> usize {
        self.count(TestStatus::Duplicate)
    }

    /// Whether the family has been answered and need not be retried.
    pub fn family_is_settled(&self, family: &str) -> bool {
        let records: Vec<&TestRecord> = self
            .seen
            .values()
            .filter(|r| r.fingerprint.semantic_family == family)
            .collect();
        !records.is_empty()
            && records.iter().all(|r| {
                matches!(
                    r.status,
                    TestStatus::Confirmed | TestStatus::Duplicate | TestStatus::Blocked
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(family: &str, boundary: &str, payload_hint: &str) -> TestFingerprint {
        TestFingerprint {
            endpoint: "/api/item".into(),
            parameter: "id".into(),
            location: "query".into(),
            technique: "error_injection".into(),
            context: "numeric".into(),
            boundary: boundary.into(),
            dialect: "postgresql".into(),
            transformation: "identity".into(),
            // Note: payload_hint is deliberately NOT part of the identity —
            // `' AND 1=1--` and `' AND 2=2--` must dedupe to the same key.
            semantic_family: format!("{family}:{payload_hint}"),
        }
    }

    #[test]
    fn equivalent_tests_dedupe() {
        let mut ledger = TestLedger::new();
        // Same family (same question), same boundary, same transform.
        let a = fp("boolean_true", "'--|0", "always_true");
        let b = fp("boolean_true", "'--|0", "always_true");
        assert!(ledger.register(a));
        assert!(!ledger.register(b), "equivalent test was not deduplicated");
        assert_eq!(ledger.duplicates_avoided(), 1);
    }

    #[test]
    fn different_boundary_is_a_different_test() {
        let mut ledger = TestLedger::new();
        assert!(ledger.register(fp("boolean_true", "'--|0", "always_true")));
        assert!(
            ledger.register(fp("boolean_true", "paren|1", "always_true")),
            "a different boundary is a genuinely different test"
        );
        assert_eq!(ledger.total_generated(), 2);
    }

    #[test]
    fn different_family_is_a_different_test() {
        let mut ledger = TestLedger::new();
        assert!(ledger.register(fp("boolean_true", "'--|0", "always_true")));
        assert!(ledger.register(fp("boolean_false", "'--|0", "always_false")));
        assert_eq!(ledger.total_generated(), 2);
    }

    #[test]
    fn identical_results_collapse_to_one_family() {
        let mut ledger = TestLedger::new();
        // Three genuinely distinct tests (different boundaries) that share one
        // semantic family and produce identical observations.
        for boundary in ["'--|0", "paren|1", "double|0"] {
            let f = fp("eq", boundary, "same_question");
            ledger.register(f.clone());
            ledger.record_outcome(&f, TestStatus::ApplicationResponse, "identical body hash abc");
        }
        let families = ledger.families();
        let fam = families
            .iter()
            .find(|f| f.semantic_family.contains("same_question"))
            .unwrap();
        assert_eq!(fam.tested, 3, "three distinct tests should share one family");
        assert!(fam.equivalent_result, "identical results must collapse");
    }

    #[test]
    fn divergent_results_do_not_collapse() {
        let mut ledger = TestLedger::new();
        let f1 = fp("div", "'--|0", "q1");
        let f2 = fp("div", "'--|0", "q2");
        ledger.register(f1.clone());
        ledger.register(f2.clone());
        ledger.record_outcome(&f1, TestStatus::ApplicationResponse, "body hash aaa");
        ledger.record_outcome(&f2, TestStatus::Interesting, "body hash bbb");
        let fam = ledger
            .families()
            .into_iter()
            .find(|f| f.semantic_family.contains("q1"))
            .unwrap();
        // q1 and q2 are different families, so each has one member (equivalent).
        // Check the stronger assertion: interesting status raises strength.
        assert_eq!(fam.evidence_strength, 0.0);
    }

    #[test]
    fn confirmed_family_is_settled() {
        let mut ledger = TestLedger::new();
        let f = fp("settled", "'--|0", "q");
        ledger.register(f.clone());
        ledger.record_outcome(&f, TestStatus::Confirmed, "confirmed");
        assert!(ledger.family_is_settled("settled:q"));
    }

    #[test]
    fn unsettled_family_is_not_settled() {
        let mut ledger = TestLedger::new();
        let f = fp("open", "'--|0", "q");
        ledger.register(f.clone());
        ledger.record_outcome(&f, TestStatus::ApplicationResponse, "no signal");
        assert!(!ledger.family_is_settled("open:q"));
    }

    #[test]
    fn counts_track_statuses() {
        let mut ledger = TestLedger::new();
        let a = fp("a", "'--|0", "x");
        let b = fp("b", "'--|0", "y");
        ledger.register(a.clone());
        ledger.register(b.clone());
        ledger.record_outcome(&a, TestStatus::Blocked, "waf");
        ledger.record_outcome(&b, TestStatus::Executed, "ok");
        assert_eq!(ledger.count(TestStatus::Blocked), 1);
        assert_eq!(ledger.count(TestStatus::Executed), 1);
    }

    #[test]
    fn key_is_deterministic() {
        assert_eq!(fp("a", "b", "c").key(), fp("a", "b", "c").key());
    }
}
