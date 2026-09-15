use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseOrigin {
    OriginApplication,
    CloudflareWaf,
    CloudflareChallenge,
    CloudflareRateLimit,
    CDNCache,
    AuthenticationLayer,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WafAction {
    Allow,
    Block,
    Challenge,
    Log,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafObservation {
    pub origin: ResponseOrigin,
    pub confidence: f32,
    pub action: WafAction,
    pub fingerprint: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OriginAssessment {
    pub reached_origin: bool,
    pub confidence: f32,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafContamination {
    pub score: f32,
    pub reasons: Vec<String>,
}

/// Models the probability that a response behavior originated from a specific layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerHypothesis {
    pub waf: f32,
    pub application: f32,
    pub database: f32,
    pub evidence: Vec<String>,
}

impl Default for LayerHypothesis {
    fn default() -> Self {
        Self {
            waf: 0.0,
            application: 0.0,
            database: 0.0,
            evidence: vec![],
        }
    }
}
