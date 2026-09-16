//! Parameter discovery and intelligence.
//!
//! Phase 1 scope: type classification of discovered inputs. Full parameter
//! *discovery* (crawling forms, JS, OpenAPI, GraphQL) is Phase 5 of the
//! brief and is NOT implemented here — inputs currently come from a
//! `RequestTemplate`, which is the honest boundary.

pub mod classifier;

pub use classifier::{infer_type, infer_type_from_samples, DataType};
