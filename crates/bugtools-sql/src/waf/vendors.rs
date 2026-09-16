//! WAF/CDN vendor signatures.
//!
//! Extends the existing Cloudflare-only classifier with AWS, Akamai, Fastly
//! and a generic header/cookie heuristic. Vendor detection is *evidence*,
//! not proof — every match reports the specific indicator that fired.

use serde::{Deserialize, Serialize};

/// A detected vendor signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VendorSignal {
    pub vendor: &'static str,
    /// The specific indicator that matched.
    pub indicator: String,
    pub weight: u8,
}

/// Headers (name, value-substring) that implicate a vendor.
/// An empty value-substring matches on header presence alone.
const VENDOR_HEADERS: &[(&str, &str, &str, u8)] = &[
    // Cloudflare
    ("cloudflare", "cf-ray", "", 50),
    ("cloudflare", "cf-mitigated", "", 55),
    ("cloudflare", "server", "cloudflare", 45),
    ("cloudflare", "cf-cache-status", "", 30),
    // AWS
    ("aws", "x-amz-cf-id", "", 50),
    ("aws", "x-amz-cf-pop", "", 45),
    ("aws", "server", "cloudfront", 45),
    ("aws", "x-amzn-requestid", "", 35),
    ("aws", "x-amz-apigw-id", "", 40),
    // Akamai
    ("akamai", "x-akamai-transformed", "", 50),
    ("akamai", "server", "akamaighost", 45),
    ("akamai", "x-akamai-request-id", "", 45),
    ("akamai", "akamai-grn", "", 45),
    // Fastly
    ("fastly", "x-served-by", "cache-", 40),
    ("fastly", "x-fastly-request-id", "", 50),
    ("fastly", "fastly-io-info", "", 45),
    ("fastly", "server", "fastly", 45),
    // Generic reverse-proxy/WAF indicators
    ("generic-waf", "x-sucuri-id", "", 45),
    ("generic-waf", "x-mod-security", "", 45),
    ("generic-waf", "x-protected-by", "", 40),
    ("generic-waf", "server", "sucuri", 40),
    ("generic-waf", "x-iinfo", "", 35), // Imperva/Incapsula
    ("generic-proxy", "via", "", 20),
    ("generic-proxy", "x-forwarded-server", "", 25),
    ("generic-proxy", "x-cache", "", 20),
];

/// Cookies that implicate a vendor.
const VENDOR_COOKIES: &[(&str, &str, u8)] = &[
    ("cloudflare", "__cfduid", 45),
    ("cloudflare", "__cf_bm", 50),
    ("cloudflare", "cf_clearance", 50),
    ("aws", "awsalb", 40),
    ("aws", "aws-elb", 35),
    ("akamai", "ak_bmsc", 45),
    ("generic-waf", "incap_ses", 45),
    ("generic-waf", "visid_incap", 45),
];

/// Body substrings that implicate a vendor.
const VENDOR_BODY: &[(&str, &str, u8)] = &[
    ("cloudflare", "checking your browser", 50),
    ("cloudflare", "cf-browser-verification", 45),
    ("aws", "request blocked", 30),
    ("akamai", "reference #18", 40),
    ("generic-waf", "mod_security", 45),
    ("generic-waf", "modsecurity", 45),
    ("generic-waf", "access denied by", 40),
    ("generic-waf", "captcha", 25),
];

/// Detect vendor signals from a response.
///
/// Returns every signal that fired, strongest first. An empty result means
/// no vendor evidence was found — it does NOT mean no WAF is present.
pub fn detect_vendors(
    headers: &[(String, String)],
    cookies: &[String],
    body: &str,
) -> Vec<VendorSignal> {
    let mut signals = Vec::new();
    let body_lower = body.to_lowercase();

    for (vendor, header_name, value_substr, weight) in VENDOR_HEADERS {
        for (k, v) in headers {
            if k.eq_ignore_ascii_case(header_name) {
                if value_substr.is_empty() || v.to_lowercase().contains(value_substr) {
                    signals.push(VendorSignal {
                        vendor,
                        indicator: format!(
                            "header {header_name}{}",
                            if value_substr.is_empty() {
                                String::new()
                            } else {
                                format!(" contains \"{value_substr}\"")
                            }
                        ),
                        weight: *weight,
                    });
                }
            }
        }
    }

    for (vendor, cookie_name, weight) in VENDOR_COOKIES {
        for cookie in cookies {
            if cookie.to_lowercase().contains(&cookie_name.to_lowercase()) {
                signals.push(VendorSignal {
                    vendor,
                    indicator: format!("cookie {cookie_name}"),
                    weight: *weight,
                });
            }
        }
    }

    for (vendor, needle, weight) in VENDOR_BODY {
        if body_lower.contains(needle) {
            signals.push(VendorSignal {
                vendor,
                indicator: format!("body contains \"{needle}\""),
                weight: *weight,
            });
        }
    }

    signals.sort_by(|a, b| b.weight.cmp(&a.weight));
    signals
}

/// Aggregate vendor signals into (vendor, total confidence 0–100), strongest first.
pub fn vendor_confidences(signals: &[VendorSignal]) -> Vec<(String, u32)> {
    let mut scores: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for s in signals {
        let entry = scores.entry(s.vendor.to_string()).or_insert(0);
        *entry = (*entry + s.weight as u32).min(100);
    }
    let mut out: Vec<(String, u32)> = scores.into_iter().collect();
    out.sort_by(|a, b| b.1.cmp(&a.1));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflare_detected_from_header() {
        let headers = vec![("CF-RAY".to_string(), "abc123".to_string())];
        let signals = detect_vendors(&headers, &[], "");
        assert!(signals.iter().any(|s| s.vendor == "cloudflare"));
    }

    #[test]
    fn aws_cloudfront_detected() {
        let headers = vec![("Server".to_string(), "CloudFront".to_string())];
        let signals = detect_vendors(&headers, &[], "");
        assert!(signals.iter().any(|s| s.vendor == "aws"));
    }

    #[test]
    fn akamai_detected_from_reference_body() {
        let signals = detect_vendors(&[], &[], "Reference #18.abc123");
        assert!(signals.iter().any(|s| s.vendor == "akamai"));
    }

    #[test]
    fn fastly_detected_from_request_id() {
        let headers = vec![("X-Fastly-Request-ID".to_string(), "xyz".to_string())];
        let signals = detect_vendors(&headers, &[], "");
        assert!(signals.iter().any(|s| s.vendor == "fastly"));
    }

    #[test]
    fn generic_waf_detected_from_modsecurity() {
        let signals = detect_vendors(&[], &[], "Request blocked by ModSecurity");
        assert!(signals.iter().any(|s| s.vendor == "generic-waf"));
    }

    #[test]
    fn cookie_based_detection() {
        let cookies = vec!["__cf_bm=abc".to_string()];
        let signals = detect_vendors(&[], &cookies, "");
        assert!(signals.iter().any(|s| s.vendor == "cloudflare"));
    }

    #[test]
    fn clean_response_yields_no_signals() {
        let signals = detect_vendors(&[], &[], "<html>hello</html>");
        assert!(signals.is_empty());
    }

    #[test]
    fn every_signal_reports_an_indicator() {
        let headers = vec![("CF-RAY".to_string(), "x".to_string())];
        let signals = detect_vendors(&headers, &[], "");
        for s in &signals {
            assert!(!s.indicator.is_empty(), "signal lacked an indicator");
        }
    }

    #[test]
    fn confidences_aggregate_and_sort() {
        let headers = vec![
            ("CF-RAY".to_string(), "x".to_string()),
            ("CF-Mitigated".to_string(), "challenge".to_string()),
        ];
        let signals = detect_vendors(&headers, &[], "");
        let confidences = vendor_confidences(&signals);
        assert_eq!(confidences[0].0, "cloudflare");
        assert!(confidences[0].1 >= 100 || confidences[0].1 > 90);
    }
}
