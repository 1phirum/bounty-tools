//! Request modelling subsystem: template, cookies, raw import/export.
//!
//! This is Phase 1 of the research-engine brief. The remaining phases
//! (endpoint discovery, adaptive scheduler, evidence graph, sqlmap adapter)
//! are planned but NOT implemented here — see the crate-level MIGRATION.md
//! notes in `docs/`. Nothing in this module fakes those capabilities.

pub mod cookies;
pub mod model;
pub mod parser;

pub use cookies::{
    parse_cookie_header, parse_set_cookie, Cookie, CookieError, CookieJar, CookieProfiles,
};
pub use model::{
    AuthContext, BodyType, InputSlot, RequestModelError, RequestSource, RequestTemplate,
};
pub use parser::{parse_raw_request, to_raw_request};
