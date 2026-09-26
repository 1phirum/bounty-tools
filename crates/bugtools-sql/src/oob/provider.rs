//! The provider abstraction over out-of-band collectors.
//!
//! A provider registers with a collector (returning the callback domain that
//! tokens attach to) and polls it for interactions. The correlator decides
//! which of those interactions are evidence — a provider only transports them.

use super::correlator::OobInteraction;
#[cfg(test)]
use super::correlator::InteractionType;
use async_trait::async_trait;

/// A boxed, thread-safe error from a provider. Avoids pulling `anyhow` into the
/// SQL crate while still letting providers use `?` over heterogeneous errors.
pub type OobError = Box<dyn std::error::Error + Send + Sync>;
pub type OobResult<T> = Result<T, OobError>;

/// A source of out-of-band interactions the operator controls.
///
/// Implementors must poll a collector the *operator* owns — never the scoped
/// target. Registration returns the callback domain a payload should embed;
/// `OobToken::callback_host(domain)` prepends the planted token as a label.
#[async_trait]
pub trait OobProvider: Send + Sync {
    /// Register with the collector and return the callback domain tokens
    /// attach to (e.g. `<correlation-id><rand>.oast.example`).
    async fn register(&mut self) -> OobResult<String>;

    /// Interactions observed since the last poll. Providers return everything
    /// they saw; the correlator rejects anything not tied to a planted token.
    async fn poll(&mut self) -> OobResult<Vec<OobInteraction>>;
}

/// A scripted provider for offline tests: `register` hands back a fixed domain
/// and `poll` drains a queue of pre-seeded interactions. Nothing touches the
/// network, so `run_adaptive`'s OOB stage is exercised deterministically.
#[cfg(test)]
pub struct MockProvider {
    pub domain: String,
    pub interactions: std::sync::Mutex<Vec<OobInteraction>>,
}

#[cfg(test)]
impl MockProvider {
    pub fn new(domain: &str, interactions: Vec<OobInteraction>) -> Self {
        Self {
            domain: domain.to_string(),
            interactions: std::sync::Mutex::new(interactions),
        }
    }

    /// A DNS interaction fixture bound to a token string.
    pub fn dns(token: &str, observed_at: i64) -> OobInteraction {
        OobInteraction {
            token: token.to_string(),
            interaction_type: InteractionType::Dns,
            observed_at,
            source: "203.0.113.10".into(),
        }
    }
}

#[cfg(test)]
#[async_trait]
impl OobProvider for MockProvider {
    async fn register(&mut self) -> OobResult<String> {
        Ok(self.domain.clone())
    }

    async fn poll(&mut self) -> OobResult<Vec<OobInteraction>> {
        Ok(std::mem::take(&mut *self.interactions.lock().unwrap()))
    }
}
