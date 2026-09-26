//! NoSQL datastore fingerprinting from error text.
//!
//! Mirrors `bugtools_sql::detection::analyze_error_body`: a weighted
//! signature matcher over response bodies. It answers "does this text carry a
//! NoSQL-specific error signature, and from which engine?" — never "is the
//! target injectable", which only a behavioural differential can establish.
//!
//! Absence of a signature is not evidence of absence: many drivers swallow
//! errors or return a generic 500.

use serde::{Deserialize, Serialize};

/// The NoSQL engine family a signature points to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoSqlFamily {
    MongoDb,
    /// A Node.js Mongoose ODM stack frame (implies MongoDB underneath).
    Mongoose,
    CouchDb,
    Redis,
    Elasticsearch,
    Cassandra,
}

impl NoSqlFamily {
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::MongoDb => "MongoDB",
            Self::Mongoose => "Mongoose (MongoDB)",
            Self::CouchDb => "CouchDB",
            Self::Redis => "Redis",
            Self::Elasticsearch => "Elasticsearch",
            Self::Cassandra => "Cassandra",
        }
    }
}

/// The category of evidence a signature represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalCategory {
    /// A driver/engine error message.
    DriverError,
    /// A duplicate-key or constraint error (proves a live datastore).
    ConstraintError,
    /// A stack frame naming a known library.
    StackFrame,
    /// A distinctive JSON error shape.
    ErrorShape,
}

/// A signature definition.
#[derive(Debug, Clone)]
struct Signature {
    family: NoSqlFamily,
    /// A lowercase substring to search for.
    needle: &'static str,
    label: &'static str,
    weight: u32,
    category: SignalCategory,
}

/// A signature that fired against the analysed text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FiredSignal {
    pub family: NoSqlFamily,
    pub label: String,
    pub weight: u32,
    pub category: SignalCategory,
}

/// The outcome of analysing one body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoSqlDetection {
    pub detected: Option<NoSqlFamily>,
    pub confidence: u32,
    pub verdict: DetectionVerdict,
    pub signals: Vec<FiredSignal>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionVerdict {
    NoSignal,
    LowConfidence,
    MediumConfidence,
    HighConfidence,
}

/// The signature table. Weights are additive per family; a duplicate-key
/// error and a driver name together corroborate more than either alone.
const SIGNATURES: &[Signature] = &[
    // ── MongoDB driver / server errors.
    Signature { family: NoSqlFamily::MongoDb, needle: "mongoerror", label: "MongoError driver exception", weight: 45, category: SignalCategory::DriverError },
    Signature { family: NoSqlFamily::MongoDb, needle: "e11000", label: "E11000 duplicate key", weight: 40, category: SignalCategory::ConstraintError },
    Signature { family: NoSqlFamily::MongoDb, needle: "duplicate key error", label: "duplicate key error", weight: 30, category: SignalCategory::ConstraintError },
    Signature { family: NoSqlFamily::MongoDb, needle: "mongonetworkerror", label: "MongoNetworkError", weight: 35, category: SignalCategory::DriverError },
    Signature { family: NoSqlFamily::MongoDb, needle: "mongoservererror", label: "MongoServerError", weight: 45, category: SignalCategory::DriverError },
    Signature { family: NoSqlFamily::MongoDb, needle: "bson", label: "BSON type/serialization error", weight: 25, category: SignalCategory::DriverError },
    Signature { family: NoSqlFamily::MongoDb, needle: "$where", label: "$where evaluation error", weight: 20, category: SignalCategory::DriverError },
    Signature { family: NoSqlFamily::MongoDb, needle: "failed to parse", label: "MongoDB query parse failure", weight: 15, category: SignalCategory::DriverError },
    Signature { family: NoSqlFamily::MongoDb, needle: "unknown operator", label: "unknown operator error", weight: 30, category: SignalCategory::DriverError },
    Signature { family: NoSqlFamily::MongoDb, needle: "cannot use $", label: "operator misuse error", weight: 25, category: SignalCategory::DriverError },
    // ── Mongoose ODM (Node.js) — implies MongoDB.
    Signature { family: NoSqlFamily::Mongoose, needle: "mongoose", label: "Mongoose ODM frame", weight: 35, category: SignalCategory::StackFrame },
    Signature { family: NoSqlFamily::Mongoose, needle: "validationerror", label: "Mongoose ValidationError", weight: 25, category: SignalCategory::ErrorShape },
    Signature { family: NoSqlFamily::Mongoose, needle: "casterror", label: "Mongoose CastError", weight: 30, category: SignalCategory::ErrorShape },
    Signature { family: NoSqlFamily::Mongoose, needle: "strictpopulateerror", label: "Mongoose StrictPopulateError", weight: 25, category: SignalCategory::ErrorShape },
    // ── CouchDB.
    Signature { family: NoSqlFamily::CouchDb, needle: "couchdb", label: "CouchDB reference", weight: 35, category: SignalCategory::DriverError },
    Signature { family: NoSqlFamily::CouchDb, needle: "\"error\":\"not_found\"", label: "CouchDB not_found shape", weight: 20, category: SignalCategory::ErrorShape },
    Signature { family: NoSqlFamily::CouchDb, needle: "bad_request", label: "CouchDB bad_request", weight: 15, category: SignalCategory::ErrorShape },
    // ── Redis.
    Signature { family: NoSqlFamily::Redis, needle: "wrongtype operation", label: "Redis WRONGTYPE", weight: 40, category: SignalCategory::DriverError },
    Signature { family: NoSqlFamily::Redis, needle: "err unknown command", label: "Redis unknown command", weight: 35, category: SignalCategory::DriverError },
    Signature { family: NoSqlFamily::Redis, needle: "noscript", label: "Redis NOSCRIPT", weight: 25, category: SignalCategory::DriverError },
    // ── Elasticsearch.
    Signature { family: NoSqlFamily::Elasticsearch, needle: "search_phase_execution_exception", label: "Elasticsearch search_phase_execution_exception", weight: 40, category: SignalCategory::DriverError },
    Signature { family: NoSqlFamily::Elasticsearch, needle: "parsing_exception", label: "Elasticsearch parsing_exception", weight: 30, category: SignalCategory::DriverError },
    Signature { family: NoSqlFamily::Elasticsearch, needle: "x_content_parse_exception", label: "Elasticsearch x_content_parse_exception", weight: 30, category: SignalCategory::DriverError },
    // ── Cassandra / CQL.
    Signature { family: NoSqlFamily::Cassandra, needle: "syntaxerror: line", label: "CQL SyntaxError", weight: 30, category: SignalCategory::DriverError },
    Signature { family: NoSqlFamily::Cassandra, needle: "com.datastax", label: "DataStax driver frame", weight: 40, category: SignalCategory::StackFrame },
];

/// Analyse a response body for NoSQL error signatures. Sends nothing.
pub fn analyze_error_body(body: &str) -> NoSqlDetection {
    let hay = body.to_lowercase();
    let mut fired: Vec<FiredSignal> = Vec::new();
    // Accumulate weight per family.
    let mut totals: Vec<(NoSqlFamily, u32)> = Vec::new();

    for sig in SIGNATURES {
        if hay.contains(sig.needle) {
            fired.push(FiredSignal {
                family: sig.family,
                label: sig.label.to_string(),
                weight: sig.weight,
                category: sig.category,
            });
            match totals.iter_mut().find(|(f, _)| family_key(*f) == family_key(sig.family)) {
                Some((_, w)) => *w += sig.weight,
                None => totals.push((sig.family, sig.weight)),
            }
        }
    }

    // Pick the highest-weighted family; ties resolve to the first seen. The
    // reported family is folded (Mongoose → MongoDB) so the datastore
    // hypothesis names the engine, while `signals` keep the distinct labels.
    let best = totals.iter().max_by_key(|(_, w)| *w).copied();
    let (detected, confidence) = match best {
        Some((family, weight)) => (Some(family_key(family)), weight.min(100)),
        None => (None, 0),
    };

    let verdict = match confidence {
        0 => DetectionVerdict::NoSignal,
        1..=29 => DetectionVerdict::LowConfidence,
        30..=59 => DetectionVerdict::MediumConfidence,
        _ => DetectionVerdict::HighConfidence,
    };

    NoSqlDetection { detected, confidence, verdict, signals: fired }
}

/// Fold Mongoose into MongoDB for accumulation (Mongoose *is* MongoDB), while
/// keeping the distinct signal labels for the report.
fn family_key(f: NoSqlFamily) -> NoSqlFamily {
    match f {
        NoSqlFamily::Mongoose => NoSqlFamily::MongoDb,
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_mongo_from_e11000() {
        let d = analyze_error_body("MongoError: E11000 duplicate key error collection: app.users");
        assert_eq!(d.detected, Some(NoSqlFamily::MongoDb));
        assert!(d.confidence >= 45);
        assert!(matches!(d.verdict, DetectionVerdict::HighConfidence));
    }

    #[test]
    fn detects_mongoose_cast_error_as_mongo() {
        let d = analyze_error_body("CastError: Cast to ObjectId failed for value \"x\" at path \"_id\" (Mongoose)");
        // Mongoose folds into MongoDB for the datastore hypothesis.
        assert_eq!(d.detected, Some(NoSqlFamily::MongoDb));
        assert!(d.signals.iter().any(|s| s.family == NoSqlFamily::Mongoose));
    }

    #[test]
    fn detects_redis_wrongtype() {
        let d = analyze_error_body("WRONGTYPE Operation against a key holding the wrong kind of value");
        assert_eq!(d.detected, Some(NoSqlFamily::Redis));
    }

    #[test]
    fn detects_elasticsearch() {
        let d = analyze_error_body("{\"error\":{\"type\":\"parsing_exception\",\"reason\":\"...\"}}");
        assert_eq!(d.detected, Some(NoSqlFamily::Elasticsearch));
    }

    #[test]
    fn no_signature_is_not_a_detection() {
        let d = analyze_error_body("<html><body>Internal Server Error</body></html>");
        assert_eq!(d.detected, None);
        assert_eq!(d.confidence, 0);
        assert!(matches!(d.verdict, DetectionVerdict::NoSignal));
    }

    #[test]
    fn corroborated_signals_raise_confidence() {
        let one = analyze_error_body("E11000 duplicate key");
        let two = analyze_error_body("MongoServerError: E11000 duplicate key error");
        assert!(two.confidence > one.confidence);
    }
}
