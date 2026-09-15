use crate::clause_map::SqlClause;
use crate::detection::{DbmsDetectionResult, DbmsFamily, FiredSignal};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SqlContext {
    Unknown,
    Numeric,
    String,
    Boolean,
    Like,
    OrderBy,
    Limit,
    Offset,
    Identifier,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SqlDialect {
    Generic,
    MySQL,
    PostgreSQL,
    MSSQL,
    Oracle,
    SQLite,
    MariaDB,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClauseCoverage {
    pub clause: SqlClause,
    pub dialects_accepting: Vec<DbmsFamily>,
    pub dialects_rejecting: Vec<DbmsFamily>,
}

/// Full analysis result combining DBMS detection, clause mapping, and
/// evidence. This is the primary output of the SQL research engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlAnalysisResult {
    pub target: String,
    pub endpoint: String,
    pub parameter: String,
    pub context: SqlContext,
    pub dbms_hypothesis: Option<DbmsFamily>,
    pub dbms_detection: DbmsDetectionResult,
    pub clause_coverage: Vec<ClauseCoverage>,
    pub techniques_tested: Vec<String>,
    pub signals: Vec<String>,
    pub confidence_score: u32,
    pub evidence_id: Option<Uuid>,
}

/// A single probe result: what we sent, what we got back, what it tells us.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub probe_id: String,
    pub probe_type: ProbeType,
    pub payload: String,
    pub response_status: u16,
    pub response_body_hash: String,
    pub response_duration_ms: u64,
    pub detection: DbmsDetectionResult,
    pub clause_tested: Option<SqlClause>,
    pub dialects_confirmed: Vec<DbmsFamily>,
    pub dialects_rejected: Vec<DbmsFamily>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeType {
    /// Clean request — establishes the baseline for comparison.
    Baseline,
    /// Inject a syntax error and check which DBMS dialect reports it.
    ErrorInjection,
    /// Send a dialect-specific function/keyword and check for acceptance.
    SyntaxFeature,
    /// Send a dialect-specific clause variant and observe behavior.
    ClauseVariant,
    /// Timing-based: measure if a dialect-specific delay function fires.
    TimingProbe,
    /// Boolean-based blind inference
    BooleanBlind,
    /// Union-based data extraction
    UnionBased,
}

/// Aggregate detection result across all probes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedDetection {
    pub detected_dbms: Option<DbmsFamily>,
    pub confidence: u32,
    pub all_signals: Vec<FiredSignal>,
    pub clauses_confirmed: Vec<SqlClause>,
    pub probes_run: usize,
    pub probes_with_signal: usize,
}
