use crate::types::ProbeResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BaselineStability {
    Stable,
    Noisy,
    Unstable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineProfile {
    pub samples: Vec<ProbeResult>,
    pub stability: BaselineStability,
    pub median_duration_ms: u64,
}

impl BaselineProfile {
    pub fn new(samples: Vec<ProbeResult>) -> Self {
        let stability = Self::calculate_stability(&samples);
        let median_duration_ms = Self::calculate_median_duration(&samples);
        
        Self {
            samples,
            stability,
            median_duration_ms,
        }
    }

    fn calculate_stability(samples: &[ProbeResult]) -> BaselineStability {
        if samples.is_empty() {
            return BaselineStability::Unstable;
        }
        
        let first_status = samples[0].response_status;
        let first_hash = &samples[0].response_body_hash;
        
        let mut all_match = true;
        let mut status_match = true;

        for sample in samples.iter().skip(1) {
            if sample.response_status != first_status {
                status_match = false;
                all_match = false;
            }
            if &sample.response_body_hash != first_hash {
                all_match = false;
            }
        }

        if all_match {
            BaselineStability::Stable
        } else if status_match {
            BaselineStability::Noisy
        } else {
            BaselineStability::Unstable
        }
    }

    fn calculate_median_duration(samples: &[ProbeResult]) -> u64 {
        if samples.is_empty() {
            return 0;
        }
        let mut durations: Vec<u64> = samples.iter().map(|s| s.response_duration_ms).collect();
        durations.sort_unstable();
        durations[durations.len() / 2]
    }
}
