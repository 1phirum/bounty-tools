use crate::waf::models::{ResponseOrigin, WafObservation};
use bugtools_core::http::HttpResponse;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReachabilityState {
    LikelyOrigin,
    LikelyEdge,
    Indeterminate,
    Mixed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachabilityAssessment {
    pub state: ReachabilityState,
    pub origin_confidence: f32,
    pub edge_confidence: f32,
    pub evidence: Vec<String>,
}

pub struct OriginReachabilityEngine;

impl OriginReachabilityEngine {
    pub fn assess(
        waf_obs: &WafObservation,
        raw_resp: &HttpResponse,
    ) -> ReachabilityAssessment {
        let mut origin_confidence: f32 = 0.0;
        let mut edge_confidence: f32 = 0.0;
        let mut evidence = Vec::new();

        // 1. Analyze WAF Observations
        match waf_obs.origin {
            ResponseOrigin::OriginApplication => {
                origin_confidence += 0.5;
                evidence.push("WAF classifier strongly suspects origin".to_string());
            }
            ResponseOrigin::CloudflareWaf
            | ResponseOrigin::CloudflareChallenge
            | ResponseOrigin::CloudflareRateLimit => {
                edge_confidence += 0.7;
                evidence.push(format!("WAF intercepted request: {:?}", waf_obs.origin));
            }
            _ => {}
        }

        // 2. Analyze Header Signatures for Origin
        let mut origin_headers = 0;
        let mut edge_headers = 0;

        for (k, v) in &raw_resp.headers {
            let key = k.to_lowercase();
            let val = v.to_lowercase();

            // Edge indicators
            if key == "server" && val.contains("cloudflare") {
                edge_headers += 1;
            }
            if key == "cf-ray" || key == "cf-cache-status" || key == "x-cache" {
                edge_headers += 1;
            }
            
            // Origin indicators
            if key == "set-cookie" && (val.contains("session") || val.contains("phpsessid") || val.contains("jsessionid") || val.contains("x-auth")) {
                origin_headers += 1;
                evidence.push("Origin session cookie detected".to_string());
            }
            if key == "x-powered-by" || key == "x-aspnet-version" || key == "x-generator" {
                origin_headers += 1;
                evidence.push("Origin technology header detected".to_string());
            }
        }

        if edge_headers > 0 && origin_headers == 0 {
            edge_confidence += 0.2;
        }
        if origin_headers > 0 {
            origin_confidence += 0.4;
        }

        // 3. Analyze Body for application-specific markers
        if raw_resp.body.contains("SQL syntax") || raw_resp.body.contains("ORA-") || raw_resp.body.contains("PostgreSQL") {
            origin_confidence += 0.8;
            evidence.push("Database error signature found in body".to_string());
        }

        // Determine final state
        let state = if origin_confidence > 0.6 && edge_confidence < 0.5 {
            ReachabilityState::LikelyOrigin
        } else if edge_confidence > 0.6 && origin_confidence < 0.3 {
            ReachabilityState::LikelyEdge
        } else if origin_confidence > 0.4 && edge_confidence > 0.4 {
            ReachabilityState::Mixed
        } else {
            ReachabilityState::Indeterminate
        };

        ReachabilityAssessment {
            state,
            origin_confidence: origin_confidence.min(1.0),
            edge_confidence: edge_confidence.min(1.0),
            evidence,
        }
    }
}
