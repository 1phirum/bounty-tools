//! Environmental interference classification (brief §19).
//!
//! A 403, 429, or 5xx must never be interpreted as SQL evidence on its own.
//! This module classifies responses that indicate the *environment* is
//! interfering, so the evidence engine can record them as contradictions
//! rather than supports.

use serde::{Deserialize, Serialize};

/// The kind of environmental condition a response indicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentClass {
    /// No environmental interference detected.
    Normal,
    /// A web-application firewall or challenge is blocking the request.
    WafChallenge,
    /// The server is rate limiting us.
    RateLimited,
    /// Bot protection (e.g. Cloudflare/Akamai challenge, CAPTCHA).
    BotProtection,
    /// The session is no longer authenticated.
    AuthFailure,
    /// The target explicitly forbade the request.
    Forbidden,
    /// The request never completed at the network layer.
    NetworkFailure,
    /// A server-side error not attributable to input parsing.
    ServerError,
    /// An application-level error.
    ApplicationError,
}

impl EnvironmentClass {
    /// Whether this class means the response cannot be used as SQL evidence.
    /// All interference classes are excluded; only `Normal` is usable.
    pub fn blocks_sql_evidence(&self) -> bool {
        !matches!(self, EnvironmentClass::Normal)
    }

    /// Human label for display.
    pub fn label(&self) -> &'static str {
        match self {
            EnvironmentClass::Normal => "Normal",
            EnvironmentClass::WafChallenge => "WAF_CHALLENGE",
            EnvironmentClass::RateLimited => "RATE_LIMITED",
            EnvironmentClass::BotProtection => "BOT_PROTECTION",
            EnvironmentClass::AuthFailure => "AUTH_FAILURE",
            EnvironmentClass::Forbidden => "FORBIDDEN",
            EnvironmentClass::NetworkFailure => "NETWORK_FAILURE",
            EnvironmentClass::ServerError => "SERVER_ERROR",
            EnvironmentClass::ApplicationError => "APPLICATION_ERROR",
        }
    }
}

/// Classify a response into an environment class.
///
/// `status` is the HTTP status code; `headers` and `body` are used for
/// signature matching. The result is a *classification of the environment*,
/// not of the input.
pub fn classify_environment(
    status: u16,
    headers: &[(&str, &str)],
    body: &str,
) -> EnvironmentClass {
    let body_lower = body.to_lowercase();
    let header_has = |name: &str| headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name));
    let header_value_contains = |name: &str, needle: &str| {
        headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case(name) && v.to_lowercase().contains(needle))
    };

    // Rate limiting is the most specific signal.
    if status == 429 || header_has("retry-after") {
        return EnvironmentClass::RateLimited;
    }

    // Bot protection / WAF challenge signatures.
    if header_value_contains("server", "cloudflare")
        && (body_lower.contains("checking your browser")
            || body_lower.contains("cf-chl")
            || header_has("cf-ray"))
    {
        return EnvironmentClass::BotProtection;
    }
    if body_lower.contains("captcha")
        || body_lower.contains("are you a robot")
        || body_lower.contains("g-recaptcha")
    {
        return EnvironmentClass::BotProtection;
    }
    if header_has("x-sucuri-id")
        || header_has("x-mod-security")
        || body_lower.contains("mod_security")
        || body_lower.contains("modsecurity")
        || body_lower.contains("request blocked")
        || body_lower.contains("access denied by")
    {
        return EnvironmentClass::WafChallenge;
    }

    // Authentication failure: a redirect to login, or an auth challenge.
    if status == 401
        || (status == 302
            && (body_lower.contains("/login")
                || body_lower.contains("signin")
                || header_value_contains("location", "login")))
        || header_value_contains("www-authenticate", "")
    {
        return EnvironmentClass::AuthFailure;
    }

    if status == 403 {
        return EnvironmentClass::Forbidden;
    }

    // Network failures surface as status 0 in our engine.
    if status == 0 {
        return EnvironmentClass::NetworkFailure;
    }

    if (500..=599).contains(&status) {
        return EnvironmentClass::ServerError;
    }

    if (400..=499).contains(&status) {
        return EnvironmentClass::ApplicationError;
    }

    EnvironmentClass::Normal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_200_is_not_interference() {
        let c = classify_environment(200, &[], "<html>ok</html>");
        assert_eq!(c, EnvironmentClass::Normal);
        assert!(!c.blocks_sql_evidence());
    }

    #[test]
    fn rate_limit_detected_by_status() {
        let c = classify_environment(429, &[], "");
        assert_eq!(c, EnvironmentClass::RateLimited);
        assert!(c.blocks_sql_evidence());
    }

    #[test]
    fn rate_limit_detected_by_retry_after() {
        let c = classify_environment(200, &[("Retry-After", "30")], "");
        assert_eq!(c, EnvironmentClass::RateLimited);
    }

    #[test]
    fn auth_redirect_to_login_is_not_sql() {
        // The exact scenario from the brief: 302 → /login must not look like SQL.
        let c = classify_environment(302, &[("Location", "/login")], "");
        assert_eq!(c, EnvironmentClass::AuthFailure);
        assert!(c.blocks_sql_evidence());
    }

    #[test]
    fn cloudflare_challenge_detected() {
        let c = classify_environment(
            503,
            &[("Server", "cloudflare"), ("CF-RAY", "abc")],
            "Checking your browser before accessing",
        );
        assert_eq!(c, EnvironmentClass::BotProtection);
    }

    #[test]
    fn modsecurity_waf_detected() {
        let c = classify_environment(403, &[], "Request blocked by ModSecurity rules");
        assert_eq!(c, EnvironmentClass::WafChallenge);
    }

    #[test]
    fn generic_403_is_forbidden() {
        let c = classify_environment(403, &[], "Forbidden");
        assert_eq!(c, EnvironmentClass::Forbidden);
        assert!(c.blocks_sql_evidence());
    }

    #[test]
    fn server_error_classified() {
        let c = classify_environment(500, &[], "Internal Server Error");
        assert_eq!(c, EnvironmentClass::ServerError);
    }

    #[test]
    fn network_failure_classified() {
        let c = classify_environment(0, &[], "");
        assert_eq!(c, EnvironmentClass::NetworkFailure);
    }

    #[test]
    fn redirect_not_to_login_is_not_auth_failure() {
        let c = classify_environment(302, &[("Location", "/products")], "");
        assert_ne!(c, EnvironmentClass::AuthFailure);
    }
}
