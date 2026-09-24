//! Command handlers. One file per command; each handler receives its parsed
//! arguments and returns `Result<()>`.

pub mod discover;
pub mod endpoints;
pub mod http;
pub mod payload;
pub mod pipeline;
pub mod resolve;
pub mod sql;
pub mod sqli;
pub mod target;
pub mod tech;
pub mod xss;
