//! Out-of-band interaction: correlation core plus collector providers.
//!
//! The [`correlator`] module holds the honest-correlation core — only a token
//! *we planted*, arriving inside its window, becomes evidence. The provider
//! modules give that core somewhere to poll from: a generic
//! bring-your-own-collector ([`byoc`]) and a full interactsh protocol client
//! ([`interactsh`]). Both implement the [`OobProvider`] trait so `run_adaptive`
//! is agnostic to where interactions come from.

pub mod byoc;
pub mod correlator;
pub mod interactsh;
pub mod provider;

pub use byoc::{ByocProvider, PollSource};
pub use correlator::{
    InteractionType, OobCorrelation, OobCorrelator, OobInteraction, OobToken,
};
pub use interactsh::InteractshProvider;
pub use provider::{OobError, OobProvider, OobResult};

#[cfg(test)]
pub use provider::MockProvider;
