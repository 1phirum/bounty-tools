use crate::waf::models::{ResponseOrigin, WafAction, WafObservation};
use bugtools_core::http::HttpResponse;

pub fn classify_origin(resp: &HttpResponse) -> WafObservation {
    let mut origin = ResponseOrigin::OriginApplication;
    let mut confidence = 0.5;
    let mut action = WafAction::Allow;
    let mut evidence = Vec::new();

    let mut is_cloudflare = false;

    // Check headers
    for (k, v) in &resp.headers {
        let key_lower = k.to_lowercase();
        if key_lower == "server" && v.to_lowercase().contains("cloudflare") {
            is_cloudflare = true;
            evidence.push("Server: cloudflare header present".to_string());
        }
        if key_lower == "cf-ray" {
            is_cloudflare = true;
            evidence.push("cf-ray header present".to_string());
        }
        if key_lower == "cf-mitigated" {
            is_cloudflare = true;
            evidence.push("cf-mitigated header present (Challenge/Block)".to_string());
            action = WafAction::Challenge;
            origin = ResponseOrigin::CloudflareChallenge;
            confidence = 0.95;
        }
    }

    // Check status codes
    if is_cloudflare {
        match resp.status_code {
            403 => {
                origin = ResponseOrigin::CloudflareWaf;
                action = WafAction::Block;
                confidence = 0.90;
                evidence.push("403 Forbidden with Cloudflare headers".to_string());
            }
            429 => {
                origin = ResponseOrigin::CloudflareRateLimit;
                action = WafAction::Block;
                confidence = 0.95;
                evidence.push("429 Too Many Requests with Cloudflare headers".to_string());
            }
            _ => {}
        }
    }

    // Check body signatures
    let body_lower = resp.body.to_lowercase();
    if body_lower.contains("cloudflare") && body_lower.contains("ray id") {
        if body_lower.contains("error 1020") {
            origin = ResponseOrigin::CloudflareWaf;
            action = WafAction::Block;
            confidence = 0.99;
            evidence.push("Cloudflare WAF Error 1020 Template Detected".to_string());
        } else if body_lower.contains("attention required!") || body_lower.contains("just a moment") {
            origin = ResponseOrigin::CloudflareChallenge;
            action = WafAction::Challenge;
            confidence = 0.98;
            evidence.push("Cloudflare Managed Challenge Template Detected".to_string());
        } else if body_lower.contains("access denied") && resp.status_code == 403 {
            origin = ResponseOrigin::CloudflareWaf;
            action = WafAction::Block;
            confidence = 0.95;
            evidence.push("Generic Cloudflare Access Denied Page".to_string());
        }
    }

    // If no strong WAF evidence, assume origin
    if origin == ResponseOrigin::OriginApplication {
        evidence.push("No known WAF blocking signatures detected".to_string());
        confidence = 0.8;
    }

    // Simple fingerprint based on status and length to identify this specific response class
    let fingerprint = format!("{}_{}", resp.status_code, resp.size_bytes);

    WafObservation {
        origin,
        confidence,
        action,
        fingerprint,
        evidence,
    }
}
