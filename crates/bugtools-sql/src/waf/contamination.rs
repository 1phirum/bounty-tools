use crate::waf::models::{ResponseOrigin, WafAction, WafContamination, WafObservation};

pub fn calculate_contamination(observations: &[WafObservation]) -> WafContamination {
    if observations.is_empty() {
        return WafContamination {
            score: 0.0,
            reasons: vec!["No WAF observations available".to_string()],
        };
    }

    let mut score = 0.0;
    let mut reasons = Vec::new();

    let blocks = observations.iter().filter(|o| o.action == WafAction::Block).count();
    let challenges = observations.iter().filter(|o| o.action == WafAction::Challenge).count();
    
    let total = observations.len() as f32;
    let block_ratio = blocks as f32 / total;
    let challenge_ratio = challenges as f32 / total;

    if block_ratio > 0.0 {
        score += block_ratio * 0.5; // Up to 50% penalty for constant blocking
        reasons.push(format!("WAF intercepted {}/{} requests with a block", blocks, observations.len()));
    }

    if challenge_ratio > 0.0 {
        score += challenge_ratio * 0.3; // Up to 30% penalty for challenges
        reasons.push(format!("WAF intercepted {}/{} requests with a challenge", challenges, observations.len()));
    }

    let origin_responses = observations.iter().filter(|o| o.origin == ResponseOrigin::OriginApplication).count();
    if origin_responses == 0 {
        score += 0.4;
        reasons.push("No origin responses observed across the test family".to_string());
    }

    // Cap the score at 1.0 (100% contaminated)
    if score > 1.0 {
        score = 1.0;
    }

    WafContamination {
        score,
        reasons,
    }
}
