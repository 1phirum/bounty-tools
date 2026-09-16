//! Layer classification: where did the request actually stop?
//!
//! The brief's §6 requirement. A response change does NOT mean the
//! application processed the request — it may have been blocked at the edge.
//! This module answers that question explicitly, and the SQLi engine must
//! consult it before treating any response as a SQL signal.

use serde::{Deserialize, Serialize};

/// Which layer produced the response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LayerClass {
    /// The edge blocked the request outright.
    EdgeBlock,
    /// The edge issued a challenge (CAPTCHA, JS challenge).
    EdgeChallenge,
    /// The edge rate-limited us.
    EdgeRateLimit,
    /// A reverse proxy returned an error before reaching the application.
    ProxyError,
    /// The application produced the response normally.
    ApplicationResponse,
    /// The application produced an error response.
    ApplicationError,
    /// The backend timed out behind the proxy.
    BackendTimeout,
    /// Not enough evidence to classify.
    Unknown,
}

impl LayerClass {
    /// Whether the application is believed to have processed the request.
    /// Only these classes may contribute SQL evidence.
    pub fn reached_application(&self) -> bool {
        matches!(self, Self::ApplicationResponse | Self::ApplicationError)
    }

    /// Whether the response is edge-generated (and therefore unusable as
    /// SQL evidence regardless of its content).
    pub fn is_edge_generated(&self) -> bool {
        matches!(
            self,
            Self::EdgeBlock | Self::EdgeChallenge | Self::EdgeRateLimit | Self::ProxyError
        )
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::EdgeBlock => "EDGE_BLOCK",
            Self::EdgeChallenge => "EDGE_CHALLENGE",
            Self::EdgeRateLimit => "EDGE_RATE_LIMIT",
            Self::ProxyError => "PROXY_ERROR",
            Self::ApplicationResponse => "APPLICATION_RESPONSE",
            Self::ApplicationError => "APPLICATION_ERROR",
            Self::BackendTimeout => "BACKEND_TIMEOUT",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// The classification with its supporting evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerClassification {
    pub class: LayerClass,
    pub confidence: f32,
    pub evidence: Vec<String>,
}

/// Classify a response against a known baseline.
///
/// `vendor_present` indicates a WAF/CDN was detected for this target, which
/// raises the prior for edge-generated responses.
pub fn classify_layer(
    status: u16,
    body_lower: &str,
    has_challenge_headers: bool,
    vendor_present: bool,
    baseline_status: Option<u16>,
) -> LayerClassification {
    let mut evidence = Vec::new();

    // Rate limiting is unambiguous.
    if status == 429 {
        evidence.push("status 429 indicates rate limiting".to_string());
        return LayerClassification {
            class: LayerClass::EdgeRateLimit,
            confidence: 0.95,
            evidence,
        };
    }

    // Challenge indicators.
    if has_challenge_headers
        || body_lower.contains("checking your browser")
        || body_lower.contains("cf-browser-verification")
        || body_lower.contains("captcha")
        || body_lower.contains("challenge-platform")
    {
        evidence.push("challenge indicators present in headers/body".to_string());
        return LayerClassification {
            class: LayerClass::EdgeChallenge,
            confidence: 0.9,
            evidence,
        };
    }

    // Edge block: a WAF body or a 403 with vendor present.
    if body_lower.contains("access denied")
        || body_lower.contains("request blocked")
        || body_lower.contains("mod_security")
        || body_lower.contains("modsecurity")
    {
        evidence.push("WAF block phrasing in body".to_string());
        return LayerClassification {
            class: LayerClass::EdgeBlock,
            confidence: 0.85,
            evidence,
        };
    }

    if let Some(base) = baseline_status {
        if base < 400 && status == 403 {
            if vendor_present {
                evidence.push(format!(
                    "status changed {base} -> 403 with a WAF/CDN present"
                ));
                return LayerClassification {
                    class: LayerClass::EdgeBlock,
                    confidence: 0.8,
                    evidence,
                };
            }
            evidence.push(format!("status changed {base} -> 403 without a detected WAF"));
            return LayerClassification {
                class: LayerClass::ApplicationError,
                confidence: 0.55,
                evidence,
            };
        }
    }

    // Proxy / gateway errors.
    if status == 502 || status == 503 || status == 504 {
        if body_lower.contains("gateway") || body_lower.contains("proxy") {
            evidence.push(format!("status {status} with proxy phrasing"));
            return LayerClassification {
                class: LayerClass::ProxyError,
                confidence: 0.8,
                evidence,
            };
        }
        evidence.push(format!("status {status} indicates backend unavailability"));
        return LayerClassification {
            class: LayerClass::BackendTimeout,
            confidence: 0.7,
            evidence,
        };
    }

    // 5xx from the application itself.
    if (500..600).contains(&status) {
        evidence.push(format!("status {status} is an application-side error"));
        return LayerClassification {
            class: LayerClass::ApplicationError,
            confidence: 0.7,
            evidence,
        };
    }

    // Everything else is assumed to have reached the application, but the
    // confidence is lower when a WAF is present because we cannot always
    // distinguish a proxied 200 from an origin 200.
    if vendor_present {
        evidence.push(
            "response passed through a WAF/CDN; origin processing inferred from status class"
                .to_string(),
        );
        return LayerClassification {
            class: LayerClass::ApplicationResponse,
            confidence: 0.6,
            evidence,
        };
    }

    evidence.push(format!("status {status} with no edge indicators"));
    LayerClassification {
        class: if (400..500).contains(&status) {
            LayerClass::ApplicationError
        } else {
            LayerClass::ApplicationResponse
        },
        confidence: 0.8,
        evidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_classified() {
        let c = classify_layer(429, "", false, true, Some(200));
        assert_eq!(c.class, LayerClass::EdgeRateLimit);
        assert!(c.class.is_edge_generated());
    }

    #[test]
    fn cloudflare_challenge_classified_as_edge() {
        let c = classify_layer(
            403,
            "checking your browser before accessing",
            true,
            true,
            Some(200),
        );
        assert_eq!(c.class, LayerClass::EdgeChallenge);
        assert!(!c.class.reached_application());
    }

    #[test]
    fn waf_block_phrasing_is_edge_block() {
        let c = classify_layer(403, "request blocked by modsecurity", false, true, Some(200));
        assert_eq!(c.class, LayerClass::EdgeBlock);
    }

    #[test]
    fn the_critical_case_403_from_waf_is_not_sql_evidence() {
        // The brief's core example: Cloudflare 403 must never be read as SQL.
        let c = classify_layer(403, "", true, true, Some(200));
        assert!(c.class.is_edge_generated());
        assert!(!c.class.reached_application(), "edge 403 must not be SQL evidence");
    }

    #[test]
    fn application_500_reached_application() {
        let c = classify_layer(500, "internal error", false, false, Some(200));
        assert_eq!(c.class, LayerClass::ApplicationError);
        assert!(c.class.reached_application());
    }

    #[test]
    fn normal_200_is_application_response() {
        let c = classify_layer(200, "<html>ok</html>", false, false, Some(200));
        assert_eq!(c.class, LayerClass::ApplicationResponse);
        assert!(c.class.reached_application());
    }

    #[test]
    fn gateway_error_classified_as_proxy() {
        let c = classify_layer(502, "502 bad gateway", false, true, Some(200));
        assert_eq!(c.class, LayerClass::ProxyError);
    }

    #[test]
    fn classification_always_carries_evidence() {
        for (status, body, challenge) in [
            (200, "ok", false),
            (429, "", false),
            (500, "err", false),
            (403, "", true),
        ] {
            let c = classify_layer(status, body, challenge, true, Some(200));
            assert!(!c.evidence.is_empty(), "no evidence for status {status}");
            assert!(c.confidence > 0.0);
        }
    }

    #[test]
    fn forbidden_without_waf_is_application_error_not_edge() {
        let c = classify_layer(403, "", false, false, Some(200));
        assert_eq!(c.class, LayerClass::ApplicationError);
    }
}
