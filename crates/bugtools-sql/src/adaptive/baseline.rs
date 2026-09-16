//! Baseline as a first-class object (brief §2).
//!
//! The engine must never compare one mutated response against one arbitrary
//! baseline sample. A `BaselineProfile` is collected from several samples
//! and separates *stable* fields (safe to diff) from *dynamic* fields (which
//! must be normalized away to avoid false positives).

use crate::adaptive::signals::{similarity, ResponseView};
use serde::{Deserialize, Serialize};

/// One baseline sample.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaselineSample {
    pub status: u16,
    pub body_len: usize,
    pub normalized_hash: String,
    pub duration_ms: u64,
    pub content_type: Option<String>,
    pub location: Option<String>,
    pub header_fingerprint: String,
}

impl BaselineSample {
    pub fn from_view(view: &ResponseView) -> Self {
        let mut headers = view.headers.clone();
        headers.sort();
        let header_fingerprint = headers
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(";");
        Self {
            status: view.status,
            body_len: view.body_len,
            normalized_hash: view.normalized_hash.clone(),
            duration_ms: view.duration_ms,
            content_type: view.content_type.clone(),
            location: view.location.clone(),
            header_fingerprint,
        }
    }
}

/// A profile built from several samples of the unmodified request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineProfile {
    pub responses: Vec<BaselineSample>,
    /// Fields that did not vary across samples.
    pub stable_fields: Vec<String>,
    /// Fields that varied — diffs on these are not evidence.
    pub dynamic_fields: Vec<String>,
    pub timing_median_ms: u64,
    pub timing_mad_ms: u64,
    pub timing_samples: Vec<u64>,
    /// Mean pairwise similarity across samples (1.0 = identical).
    pub body_similarity: f32,
    pub status_distribution: Vec<(u16, usize)>,
    pub header_fingerprint: String,
    /// Whether the baseline is stable enough to reason from.
    pub stable: bool,
    /// Why the baseline is considered unstable, when it is.
    pub instability_reason: Option<String>,
}

/// Minimum samples before stability is judged. Below this, the baseline is
/// provisional and the planner must not draw conclusions from diffs.
pub const MIN_BASELINE_SAMPLES: usize = 3;

impl BaselineProfile {
    /// Build a profile from samples. Fewer than `MIN_BASELINE_SAMPLES` yields
    /// an explicitly *provisional* (unstable) profile rather than a guess.
    pub fn from_samples(samples: Vec<BaselineSample>) -> Self {
        let sample_count = samples.len();
        if sample_count < MIN_BASELINE_SAMPLES {
            return Self {
                responses: samples,
                stable_fields: Vec::new(),
                dynamic_fields: Vec::new(),
                timing_median_ms: 0,
                timing_mad_ms: 0,
                timing_samples: Vec::new(),
                body_similarity: 0.0,
                status_distribution: Vec::new(),
                header_fingerprint: String::new(),
                stable: false,
                instability_reason: Some(format!(
                    "only {sample_count} sample(s); {MIN_BASELINE_SAMPLES} required before diffs are trustworthy"
                )),
            };
        }

        let mut stable_fields = Vec::new();
        let mut dynamic_fields = Vec::new();

        let status_stable = samples.iter().all(|s| s.status == samples[0].status);
        let len_stable = samples.iter().all(|s| s.body_len == samples[0].body_len);
        let hash_stable = samples
            .iter()
            .all(|s| s.normalized_hash == samples[0].normalized_hash);
        let header_stable = samples
            .iter()
            .all(|s| s.header_fingerprint == samples[0].header_fingerprint);
        let location_stable = samples.iter().all(|s| s.location == samples[0].location);

        for (name, ok) in [
            ("status", status_stable),
            ("body_len", len_stable),
            ("normalized_body", hash_stable),
            ("headers", header_stable),
            ("location", location_stable),
        ] {
            if ok {
                stable_fields.push(name.to_string());
            } else {
                dynamic_fields.push(name.to_string());
            }
        }

        // Timing statistics.
        let mut timings: Vec<u64> = samples.iter().map(|s| s.duration_ms).collect();
        timings.sort_unstable();
        let n = timings.len();
        let median = if n % 2 == 1 {
            timings[n / 2]
        } else {
            (timings[n / 2 - 1] + timings[n / 2]) / 2
        };
        let mut deviations: Vec<u64> = timings
            .iter()
            .map(|t| (*t as i64 - median as i64).unsigned_abs())
            .collect();
        deviations.sort_unstable();
        let mad = if n % 2 == 1 {
            deviations[n / 2]
        } else {
            (deviations[n / 2 - 1] + deviations[n / 2]) / 2
        };

        // Mean pairwise body similarity.
        let mut sim_total = 0.0;
        let mut pairs = 0;
        for i in 0..samples.len() {
            for j in (i + 1)..samples.len() {
                sim_total += similarity(&samples[i].normalized_hash, &samples[j].normalized_hash);
                pairs += 1;
            }
        }
        let body_similarity = if pairs == 0 { 1.0 } else { sim_total / pairs as f32 };

        // Status distribution.
        let mut dist: std::collections::HashMap<u16, usize> = std::collections::HashMap::new();
        for s in &samples {
            *dist.entry(s.status).or_insert(0) += 1;
        }
        let mut status_distribution: Vec<(u16, usize)> = dist.into_iter().collect();
        status_distribution.sort();

        // Stability verdict.
        let body_variance = body_similarity < 0.98;
        let mut reasons = Vec::new();
        if !status_stable {
            reasons.push("status varies across identical requests".to_string());
        }
        if body_variance {
            reasons.push(format!(
                "body similarity {:.2} across identical requests",
                body_similarity
            ));
        }
        // Timing noise counts as instability only when it is both relatively
        // large AND absolutely meaningful. A 2ms spread on a 2ms baseline is
        // jitter, not instability.
        const MIN_ABSOLUTE_MAD_MS: u64 = 40;
        let timing_noisy = median > 0
            && mad >= MIN_ABSOLUTE_MAD_MS
            && (mad as f32 / median as f32) > 0.4;
        if timing_noisy {
            reasons.push(format!(
                "timing MAD {mad}ms is {:.0}% of median {median}ms",
                (mad as f32 / median.max(1) as f32) * 100.0
            ));
        }

        let (method_stable, instability_reason) = if reasons.is_empty() {
            (true, None)
        } else {
            (false, Some(reasons.join("; ")))
        };

        let header_fingerprint = self0_header(&samples);
        Self {
            responses: samples,
            stable_fields,
            dynamic_fields,
            timing_median_ms: median,
            timing_mad_ms: mad,
            timing_samples: timings,
            body_similarity,
            status_distribution,
            header_fingerprint,
            stable: method_stable,
            instability_reason,
        }
    }

    /// Whether a field is safe to diff against.
    pub fn field_is_stable(&self, field: &str) -> bool {
        self.stable_fields.iter().any(|f| f == field)
    }

    /// A conservative timing threshold: median + 5×MAD, floored so tiny
    /// baselines do not make everything look like a shift.
    pub fn timing_threshold_ms(&self) -> u64 {
        let margin = (self.timing_mad_ms * 5).max(250);
        self.timing_median_ms + margin
    }

    /// Human summary for the CLI/GUI.
    pub fn summary(&self) -> String {
        if !self.stable {
            return format!(
                "unstable/provisional — {}",
                self.instability_reason.as_deref().unwrap_or("insufficient samples")
            );
        }
        format!(
            "stable ({} samples, median {}ms, MAD {}ms, similarity {:.2})",
            self.responses.len(),
            self.timing_median_ms,
            self.timing_mad_ms,
            self.body_similarity
        )
    }
}

fn self0_header(samples: &[BaselineSample]) -> String {
    samples
        .first()
        .map(|s| s.header_fingerprint.clone())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(status: u16, body: &str, ms: u64) -> BaselineSample {
        BaselineSample::from_view(&ResponseView::simple(status, body, ms))
    }

    #[test]
    fn too_few_samples_is_provisional() {
        let profile = BaselineProfile::from_samples(vec![sample(200, "x", 100)]);
        assert!(!profile.stable);
        assert!(profile.instability_reason.unwrap().contains("required"));
    }

    #[test]
    fn stable_baseline_detected() {
        let profile = BaselineProfile::from_samples(vec![
            sample(200, "same body here", 100),
            sample(200, "same body here", 102),
            sample(200, "same body here", 98),
        ]);
        assert!(profile.stable, "reason: {:?}", profile.instability_reason);
        assert!(profile.field_is_stable("status"));
        assert!(profile.field_is_stable("normalized_body"));
    }

    #[test]
    fn varying_status_marks_unstable() {
        let profile = BaselineProfile::from_samples(vec![
            sample(200, "x", 100),
            sample(500, "x", 100),
            sample(200, "x", 100),
        ]);
        assert!(!profile.stable);
        assert!(profile.field_is_stable("body_len"));
        assert!(!profile.field_is_stable("status"));
    }

    #[test]
    fn dynamic_body_marks_unstable() {
        let profile = BaselineProfile::from_samples(vec![
            sample(200, "content alpha", 100),
            sample(200, "totally different beta", 100),
            sample(200, "yet another gamma", 100),
        ]);
        assert!(!profile.stable);
        assert!(profile.instability_reason.unwrap().contains("similarity"));
    }

    #[test]
    fn noisy_timing_marks_unstable() {
        let profile = BaselineProfile::from_samples(vec![
            sample(200, "x", 50),
            sample(200, "x", 900),
            sample(200, "x", 100),
        ]);
        assert!(!profile.stable);
    }

    #[test]
    fn mad_computed_correctly() {
        let profile = BaselineProfile::from_samples(vec![
            sample(200, "x", 100),
            sample(200, "x", 100),
            sample(200, "x", 100),
        ]);
        assert_eq!(profile.timing_mad_ms, 0);
    }

    #[test]
    fn timing_threshold_has_a_floor() {
        let profile = BaselineProfile::from_samples(vec![
            sample(200, "x", 100),
            sample(200, "x", 100),
            sample(200, "x", 100),
        ]);
        // median 100, MAD 0 -> floor of 250 margin applies.
        assert!(profile.timing_threshold_ms() >= 350);
    }

    #[test]
    fn summary_reports_stability() {
        let stable = BaselineProfile::from_samples(vec![
            sample(200, "x", 100),
            sample(200, "x", 100),
            sample(200, "x", 100),
        ]);
        assert!(stable.summary().contains("stable"));

        let unstable = BaselineProfile::from_samples(vec![sample(200, "x", 1)]);
        assert!(unstable.summary().contains("unstable") || unstable.summary().contains("provisional"));
    }

    #[test]
    fn dynamic_fields_listed() {
        let profile = BaselineProfile::from_samples(vec![
            sample(200, "x", 100),
            sample(500, "x", 100),
            sample(200, "x", 100),
        ]);
        assert!(profile.dynamic_fields.contains(&"status".to_string()));
    }
}
