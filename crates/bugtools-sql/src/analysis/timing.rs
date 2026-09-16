//! Statistical timing analysis (brief §15).
//!
//! A single slow request is never a timing signal. This module maintains
//! baseline samples and only classifies a timing difference when it is
//! statistically meaningful given the observed variance.

use serde::{Deserialize, Serialize};

/// Summary statistics over a set of timing samples (milliseconds).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingStats {
    pub count: usize,
    pub mean_ms: f64,
    pub median_ms: f64,
    pub stddev_ms: f64,
    pub min_ms: u64,
    pub max_ms: u64,
    pub p95_ms: f64,
}

impl TimingStats {
    /// Compute statistics over the samples. Returns `None` when there are no
    /// samples — the caller must not invent defaults.
    pub fn compute(samples: &[u64]) -> Option<Self> {
        if samples.is_empty() {
            return None;
        }
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let count = sorted.len();
        let sum: u64 = sorted.iter().sum();
        let mean = sum as f64 / count as f64;
        let median = if count % 2 == 1 {
            sorted[count / 2] as f64
        } else {
            (sorted[count / 2 - 1] + sorted[count / 2]) as f64 / 2.0
        };
        let variance = sorted
            .iter()
            .map(|&x| {
                let d = x as f64 - mean;
                d * d
            })
            .sum::<f64>()
            / count as f64;
        let stddev = variance.sqrt();
        // Nearest-rank P95.
        let rank = ((95.0 / 100.0) * count as f64).ceil() as usize;
        let p95 = sorted[(rank.saturating_sub(1)).min(count - 1)] as f64;

        Some(Self {
            count,
            mean_ms: mean,
            median_ms: median,
            stddev_ms: stddev,
            min_ms: sorted[0],
            max_ms: sorted[count - 1],
            p95_ms: p95,
        })
    }

    /// Coefficient of variation — how noisy the samples are relative to
    /// their mean. Used to decide whether the endpoint is stable enough to
    /// trust a timing probe at all.
    pub fn coefficient_of_variation(&self) -> f64 {
        if self.mean_ms <= 0.0 {
            0.0
        } else {
            self.stddev_ms / self.mean_ms
        }
    }
}

/// The verdict of a timing comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimingVerdict {
    /// Baseline is too noisy to conclude anything.
    NetworkNoise,
    /// Endpoint response time is unstable; timing probes are unreliable.
    UnstableEndpoint,
    /// A statistically meaningful delay was observed.
    LikelyTimingSignal,
    /// Not enough evidence either way.
    Inconclusive,
}

/// A timing comparison between baseline and test sample sets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingAnalysis {
    pub baseline: TimingStats,
    pub test: TimingStats,
    /// Median difference (test - baseline), in milliseconds.
    pub median_delta_ms: f64,
    /// Minimum samples required per group before any verdict other than
    /// Inconclusive may be issued.
    pub required_samples: usize,
    pub verdict: TimingVerdict,
    pub reason: String,
}

/// Minimum samples per group. Below this, timing evidence is not credible.
pub const MIN_TIMING_SAMPLES: usize = 3;

impl TimingAnalysis {
    /// Compare baseline and test samples.
    ///
    /// A `LikelyTimingSignal` requires: enough samples in both groups, a
    /// stable baseline (low coefficient of variation), and a median delta
    /// that exceeds several times the baseline standard deviation. This is
    /// deliberately strict — false timing positives are worse than misses.
    pub fn compare(baseline: &[u64], test: &[u64]) -> Option<Self> {
        let base = TimingStats::compute(baseline)?;
        let tst = TimingStats::compute(test)?;
        let delta = tst.median_ms - base.median_ms;

        let (verdict, reason) = if base.count < MIN_TIMING_SAMPLES || tst.count < MIN_TIMING_SAMPLES {
            (
                TimingVerdict::Inconclusive,
                format!(
                    "need at least {MIN_TIMING_SAMPLES} samples per group (have {}/{})",
                    base.count, tst.count
                ),
            )
        } else if base.coefficient_of_variation() > 0.5 {
            (
                TimingVerdict::NetworkNoise,
                format!(
                    "baseline coefficient of variation {:.2} is too high",
                    base.coefficient_of_variation()
                ),
            )
        } else if tst.coefficient_of_variation() > 0.5 {
            (
                TimingVerdict::UnstableEndpoint,
                format!(
                    "test coefficient of variation {:.2} is too high",
                    tst.coefficient_of_variation()
                ),
            )
        } else if delta > (base.stddev_ms.max(20.0) * 4.0) && delta > 500.0 {
            (
                TimingVerdict::LikelyTimingSignal,
                format!(
                    "median delta {:.0}ms exceeds 4x baseline stddev ({:.0}ms)",
                    delta, base.stddev_ms
                ),
            )
        } else {
            (
                TimingVerdict::Inconclusive,
                format!("median delta {:.0}ms is within normal variance", delta),
            )
        };

        Some(Self {
            baseline: base,
            test: tst,
            median_delta_ms: delta,
            required_samples: MIN_TIMING_SAMPLES,
            verdict,
            reason,
        })
    }

    /// Whether this analysis may contribute SQL-interaction evidence.
    pub fn supports_sql_signal(&self) -> bool {
        self.verdict == TimingVerdict::LikelyTimingSignal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_samples_have_no_stats() {
        assert!(TimingStats::compute(&[]).is_none());
    }

    #[test]
    fn median_and_stddev() {
        let stats = TimingStats::compute(&[100, 102, 98, 104, 96]).unwrap();
        assert_eq!(stats.count, 5);
        assert_eq!(stats.median_ms, 100.0);
        assert!(stats.stddev_ms > 0.0);
        assert_eq!(stats.min_ms, 96);
        assert_eq!(stats.max_ms, 104);
    }

    #[test]
    fn one_slow_request_is_not_a_signal() {
        // 2 baseline samples, 1 test — below the sample gate.
        let analysis = TimingAnalysis::compare(&[180, 182], &[5100]).unwrap();
        assert_eq!(analysis.verdict, TimingVerdict::Inconclusive);
        assert!(!analysis.supports_sql_signal());
    }

    #[test]
    fn clean_delay_is_a_signal() {
        let analysis =
            TimingAnalysis::compare(&[180, 182, 179, 181], &[5100, 5150, 5080, 5120]).unwrap();
        assert_eq!(analysis.verdict, TimingVerdict::LikelyTimingSignal);
        assert!(analysis.supports_sql_signal());
        assert!(analysis.median_delta_ms > 4000.0);
    }

    #[test]
    fn noisy_baseline_is_rejected() {
        // Baseline ranges 100..900 → high CV.
        let analysis =
            TimingAnalysis::compare(&[100, 500, 900, 200], &[5100, 5200, 5150, 5180]).unwrap();
        assert_eq!(analysis.verdict, TimingVerdict::NetworkNoise);
        assert!(!analysis.supports_sql_signal());
    }

    #[test]
    fn unstable_test_group_flagged() {
        let analysis =
            TimingAnalysis::compare(&[180, 182, 179, 181], &[500, 9000, 400, 8000]).unwrap();
        assert_eq!(analysis.verdict, TimingVerdict::UnstableEndpoint);
    }

    #[test]
    fn small_delta_is_inconclusive() {
        let analysis =
            TimingAnalysis::compare(&[180, 182, 179, 181], &[195, 198, 193, 196]).unwrap();
        assert_eq!(analysis.verdict, TimingVerdict::Inconclusive);
    }

    #[test]
    fn percentile_p95() {
        let stats = TimingStats::compute(&[10, 20, 30, 40, 50, 60, 70, 80, 90, 100]).unwrap();
        // Nearest-rank P95 of 10 values is the 10th value.
        assert_eq!(stats.p95_ms, 100.0);
    }
}
