//! NoSQL injection detection (MongoDB-focused, evidence-driven, non-destructive).
//!
//! This crate mirrors the discipline of `bugtools_sql`'s adaptive pipeline:
//! a multi-sample baseline, deduplicated experiments, repetition before trust,
//! a hard read-only safety gate on every payload, and an honest verdict that
//! includes a `NOT_INTERPRETED` negative finding. It answers "is this parameter
//! interpreted as a NoSQL query object, and can that be corroborated?" — never
//! more than the evidence supports.
//!
//! All transport goes through `bugtools_http::SafeHttpClient` (scope + budget +
//! rate-limit capped). Nothing here writes to the target: the [`safety`] gate
//! rejects any payload carrying a write/admin/server-exec operator and caps the
//! `$where` sleep and payload size.

pub mod assess;
pub mod detection;
pub mod payload;
pub mod run;
pub mod safety;

pub use assess::{NoSqlAssessment, NoSqlCoverage, TechniqueSummary};
pub use detection::{analyze_error_body, DetectionVerdict, NoSqlDetection, NoSqlFamily};
pub use payload::{InjectionStyle, NoSqlProbe, NoSqlTechnique};
pub use run::{run_nosql, NoSqlConfig, REQUIRED_REPETITIONS};
pub use safety::{clamp_sleep_ms, validate as validate_payload, Rejection};
