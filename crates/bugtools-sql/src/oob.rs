//! Out-of-band interaction correlation (brief §4, §23).
//!
//! OOB detection works by injecting a unique correlation token into a
//! payload and checking whether the token later appears in an interaction
//! recorded by callback infrastructure the researcher controls. Arbitrary
//! outbound traffic is *never* treated as proof — only a token that
//! correlates to a specific (target, endpoint, parameter) triple, within a
//! time window, becomes evidence.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// The kind of interaction the callback observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractionType {
    Dns,
    Http,
    /// Database-initiated external interaction surfaced another way.
    Database,
}

/// A token planted in a payload, awaiting correlation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OobToken {
    pub token: String,
    pub target: String,
    pub endpoint: String,
    pub parameter: String,
    pub input_location: String,
    pub planted_at: i64,
    /// How long after planting an interaction is still attributable.
    pub window_secs: i64,
}

impl OobToken {
    /// Mint a fresh, high-entropy token bound to the request context.
    ///
    /// `prefix` identifies the callback host so the token is recognizable
    /// in DNS labels (which are case-insensitive and label-length limited).
    pub fn mint(
        prefix: &str,
        target: impl Into<String>,
        endpoint: impl Into<String>,
        parameter: impl Into<String>,
        input_location: impl Into<String>,
        window_secs: i64,
    ) -> Self {
        let unique = Uuid::new_v4().simple().to_string();
        Self {
            token: format!("{prefix}-{}", &unique[..20]),
            target: target.into(),
            endpoint: endpoint.into(),
            parameter: parameter.into(),
            input_location: input_location.into(),
            planted_at: chrono::Utc::now().timestamp(),
            window_secs,
        }
    }

    /// Whether an interaction observed at `at` falls inside this token's
    /// attribution window.
    pub fn is_within_window(&self, at: i64) -> bool {
        at >= self.planted_at && at <= self.planted_at + self.window_secs
    }

    /// The hostname a payload should reference for DNS callbacks.
    pub fn callback_host(&self, callback_domain: &str) -> String {
        format!("{}.{}", self.token, callback_domain)
    }
}

/// An interaction recorded by callback infrastructure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OobInteraction {
    pub token: String,
    pub interaction_type: InteractionType,
    pub observed_at: i64,
    /// Where the interaction came from (source IP/ASN/description).
    pub source: String,
}

/// Evidence produced by a *correlated* interaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OobCorrelation {
    pub token: String,
    pub target: String,
    pub endpoint: String,
    pub parameter: String,
    pub input_location: String,
    pub interaction_type: InteractionType,
    pub observed_at: i64,
    pub source: String,
    /// Confidence contribution of this correlation.
    pub confidence_delta: i32,
}

/// Registry of planted tokens and the correlator that matches interactions.
#[derive(Debug, Clone, Default)]
pub struct OobCorrelator {
    tokens: HashMap<String, OobToken>,
}

impl OobCorrelator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a planted token. Tokens are stored by their exact string.
    pub fn plant(&mut self, token: OobToken) {
        self.tokens.insert(token.token.clone(), token);
    }

    pub fn planted_count(&self) -> usize {
        self.tokens.len()
    }

    /// Correlate an observed interaction.
    ///
    /// Returns `Some` only when the token was one *we planted* and the
    /// interaction arrived inside that token's window. Everything else is
    /// rejected — this is what stops stray traffic being reported as OOB.
    pub fn correlate(&self, interaction: &OobInteraction) -> Option<OobCorrelation> {
        let token = self.tokens.get(&interaction.token)?;
        if !token.is_within_window(interaction.observed_at) {
            return None;
        }
        // DNS tokens may arrive case-folded; the stored token is lowercase.
        Some(OobCorrelation {
            token: token.token.clone(),
            target: token.target.clone(),
            endpoint: token.endpoint.clone(),
            parameter: token.parameter.clone(),
            input_location: token.input_location.clone(),
            interaction_type: interaction.interaction_type,
            observed_at: interaction.observed_at,
            source: interaction.source.clone(),
            confidence_delta: match interaction.interaction_type {
                InteractionType::Dns => 40,
                InteractionType::Http => 45,
                InteractionType::Database => 35,
            },
        })
    }

    /// Correlate many interactions, discarding unmatched ones. Unmatched
    /// interactions are reported alongside so nothing is silently dropped.
    pub fn correlate_batch(
        &self,
        interactions: &[OobInteraction],
    ) -> (Vec<OobCorrelation>, Vec<OobInteraction>) {
        let mut correlated = Vec::new();
        let mut unmatched = Vec::new();
        for interaction in interactions {
            match self.correlate(interaction) {
                Some(c) => correlated.push(c),
                None => unmatched.push(interaction.clone()),
            }
        }
        (correlated, unmatched)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> OobToken {
        OobToken::mint("bt", "example.test", "/api/search", "q", "query", 300)
    }

    #[test]
    fn minted_token_is_unique_and_prefixed() {
        let a = token();
        let b = token();
        assert_ne!(a.token, b.token);
        assert!(a.token.starts_with("bt-"));
    }

    #[test]
    fn callback_host_uses_token_as_label() {
        let t = token();
        let host = t.callback_host("oob.example.net");
        assert!(host.starts_with(&t.token));
        assert!(host.ends_with("oob.example.net"));
    }

    #[test]
    fn correlation_succeeds_inside_window() {
        let mut c = OobCorrelator::new();
        let t = token();
        let observed = t.planted_at + 10;
        c.plant(t.clone());
        let interaction = OobInteraction {
            token: t.token.clone(),
            interaction_type: InteractionType::Dns,
            observed_at: observed,
            source: "1.2.3.4".into(),
        };
        let result = c.correlate(&interaction).unwrap();
        assert_eq!(result.parameter, "q");
        assert_eq!(result.target, "example.test");
        assert_eq!(result.confidence_delta, 40);
    }

    #[test]
    fn interaction_outside_window_is_rejected() {
        let mut c = OobCorrelator::new();
        let t = token();
        let late = t.planted_at + 10_000;
        c.plant(t.clone());
        let interaction = OobInteraction {
            token: t.token.clone(),
            interaction_type: InteractionType::Http,
            observed_at: late,
            source: "1.2.3.4".into(),
        };
        assert!(c.correlate(&interaction).is_none());
    }

    #[test]
    fn unknown_token_is_rejected() {
        // Arbitrary traffic with a token we never planted must not correlate.
        let c = OobCorrelator::new();
        let interaction = OobInteraction {
            token: "someone-elses-token".into(),
            interaction_type: InteractionType::Dns,
            observed_at: chrono::Utc::now().timestamp(),
            source: "9.9.9.9".into(),
        };
        assert!(c.correlate(&interaction).is_none());
    }

    #[test]
    fn batch_separates_matched_from_unmatched() {
        let mut c = OobCorrelator::new();
        let t = token();
        let good = t.planted_at + 5;
        let planted_token = t.token.clone();
        c.plant(t);
        let interactions = vec![
            OobInteraction {
                token: planted_token,
                interaction_type: InteractionType::Dns,
                observed_at: good,
                source: "1.1.1.1".into(),
            },
            OobInteraction {
                token: "not-ours".into(),
                interaction_type: InteractionType::Http,
                observed_at: good,
                source: "2.2.2.2".into(),
            },
        ];
        let (matched, unmatched) = c.correlate_batch(&interactions);
        assert_eq!(matched.len(), 1);
        assert_eq!(unmatched.len(), 1);
    }
}
