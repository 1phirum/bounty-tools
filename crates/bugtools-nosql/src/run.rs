//! Live NoSQL detection pipeline (evidence-driven, non-destructive).
//!
//! Mirrors the SQL adaptive pipeline's discipline: a multi-sample baseline, a
//! bounded set of deduplicated experiments, repetition before trust, typed
//! observations, and an honest verdict — including a NOT_INTERPRETED negative
//! finding. All transport goes through `SafeHttpClient` (scope + budget +
//! rate-limit capped) and every payload is safety-gated before it is built.

use crate::assess::{NoSqlAssessment, NoSqlCoverage, TechniqueSummary};
use crate::detection::{self, NoSqlFamily};
use crate::payload::{self, InjectionStyle, NoSqlProbe, NoSqlTechnique};
use bugtools_core::http::{HttpRequest, HttpResponse};
use bugtools_http::{HttpClientConfig, SafeHttpClient};
use bugtools_scope::ScopeEngine;
use std::collections::BTreeSet;
use std::sync::Arc;

/// A single differential must reproduce this many times before it is trusted.
pub const REQUIRED_REPETITIONS: usize = 2;

/// Configuration for a NoSQL run.
#[derive(Debug, Clone)]
pub struct NoSqlConfig {
    pub baseline_samples: usize,
    pub max_experiments: usize,
    pub where_delay_ms: u64,
    /// If set, attempt bounded read-only `$regex` extraction of this field
    /// (only after an injection differential is observed).
    pub extract_field: Option<String>,
    pub extract_alphabet: String,
    pub extract_max_len: usize,
}

impl Default for NoSqlConfig {
    fn default() -> Self {
        Self {
            baseline_samples: 3,
            max_experiments: 16,
            where_delay_ms: 3_000,
            extract_field: None,
            extract_alphabet: "abcdefghijklmnopqrstuvwxyz0123456789".into(),
            extract_max_len: 8,
        }
    }
}

/// A normalized view of a response, for differential comparison.
#[derive(Debug, Clone)]
struct View {
    status: u16,
    body: String,
    body_len: usize,
    duration_ms: u64,
    hash: u64,
}

fn view_of(resp: &HttpResponse) -> View {
    View {
        status: resp.status_code,
        body: resp.body.clone(),
        body_len: resp.size_bytes,
        duration_ms: resp.duration_ms,
        hash: normalized_hash(&resp.body),
    }
}

/// A whitespace- and digit-run-collapsed FNV-1a hash, so dynamic timestamps
/// and counters do not masquerade as a structural difference.
fn normalized_hash(body: &str) -> u64 {
    let mut norm = String::with_capacity(body.len());
    let mut last_ws = false;
    let mut last_digit = false;
    for c in body.chars() {
        if c.is_ascii_whitespace() {
            if !last_ws {
                norm.push(' ');
            }
            last_ws = true;
            last_digit = false;
        } else if c.is_ascii_digit() {
            if !last_digit {
                norm.push('#');
            }
            last_digit = true;
            last_ws = false;
        } else {
            norm.push(c.to_ascii_lowercase());
            last_ws = false;
            last_digit = false;
        }
    }
    let mut h = 0xcbf29ce484222325u64;
    for b in norm.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Relative difference between two lengths, in [0, 1].
fn diff_ratio(a: usize, b: usize) -> f64 {
    let (a, b) = (a as f64, b as f64);
    let m = a.max(b).max(1.0);
    (a - b).abs() / m
}

/// Whether two views differ meaningfully (status, structure, or size).
fn differs(reference: &View, other: &View) -> bool {
    reference.status != other.status
        || reference.hash != other.hash
        || diff_ratio(reference.body_len, other.body_len) > 0.05
}

/// Build the HTTP request for a probe, applying the injection style.
fn build_request(base: &HttpRequest, parameter: &str, probe: &NoSqlProbe) -> HttpRequest {
    let mut req = base.clone();
    req.id = uuid::Uuid::new_v4();
    match probe.style {
        InjectionStyle::QueryBracket => {
            if let Ok(mut url) = url::Url::parse(&base.url) {
                let key_override =
                    probe.query_key.clone().unwrap_or_else(|| parameter.to_string());
                let pairs: Vec<(String, String)> = url
                    .query_pairs()
                    .map(|(k, v)| {
                        if k == parameter {
                            (key_override.clone(), probe.value.clone())
                        } else {
                            (k.to_string(), v.to_string())
                        }
                    })
                    .collect();
                url.set_query(None);
                if !pairs.is_empty() {
                    let mut qp = url.query_pairs_mut();
                    for (k, v) in pairs {
                        qp.append_pair(&k, &v);
                    }
                }
                req.url = url.to_string();
            }
        }
        InjectionStyle::JsonBody => {
            req.method = "POST".into();
            req.headers
                .insert("Content-Type".to_string(), "application/json".to_string());
            req.body = probe.json_body.clone();
        }
    }
    req
}

/// The evidence accumulated across a run, from which the verdict is derived.
#[derive(Debug, Clone, Default)]
struct Evidence {
    baseline_stable: bool,
    auth_bypass_differential: bool,
    boolean_diverged: bool,
    timing_separated: bool,
    error_signature_seen: bool,
    blocked: bool,
    auth_tested: bool,
    boolean_tested: bool,
    /// The `$regex` extraction oracle failed its liveness check (a guaranteed
    /// no-match and a guaranteed match were indistinguishable). Extraction was
    /// aborted rather than emit a fabricated value.
    regex_oracle_dead: bool,
}

/// Decide the coverage verdict from accumulated evidence. Pure, so it is
/// unit-tested without a live target.
fn decide_coverage(e: &Evidence, experiments: usize) -> NoSqlCoverage {
    let positive = e.auth_bypass_differential || e.boolean_diverged || e.timing_separated;
    let corroborated = [
        e.auth_bypass_differential,
        e.boolean_diverged,
        e.timing_separated,
        e.error_signature_seen,
    ]
    .iter()
    .filter(|x| **x)
    .count()
        >= 2;

    if experiments == 0 {
        NoSqlCoverage::Baselined
    } else if e.blocked && !positive {
        NoSqlCoverage::Blocked
    } else if corroborated && positive {
        NoSqlCoverage::Confirmed
    } else if positive {
        NoSqlCoverage::Interesting
    } else if e.baseline_stable && e.auth_tested && e.boolean_tested && !positive {
        // Operator injection ran verified against a stable baseline and never
        // diverged: the parameter is not interpreted as a query object.
        NoSqlCoverage::NotInterpreted
    } else {
        NoSqlCoverage::Inconclusive
    }
}

/// Build a **benign control** request that mirrors the probe's transport shape
/// — same method, same headers, same body structure — but carries a harmless
/// scalar value in place of the injection operator.
///
/// This is the crux of the interleaved-control guard. Comparing a `JsonBody`
/// POST payload against the baseline *GET* compares apples to oranges: the
/// method, content-type and (under a WAF) the status all differ for reasons
/// that have nothing to do with the operator, so every probe reads as a
/// differential and a 403 block masquerades as an auth bypass. A control that
/// shares the probe's shape makes those environmental effects hit both requests
/// equally, so only an operator-attributable difference survives.
fn build_control_request(base: &HttpRequest, parameter: &str, probe: &NoSqlProbe) -> HttpRequest {
    const SENTINEL: &str = "bugtools-control-sentinel";
    match probe.style {
        InjectionStyle::QueryBracket => {
            // Same method (GET), the target parameter with a benign value and no
            // operator in the key.
            let benign = NoSqlProbe {
                query_key: Some(parameter.to_string()),
                value: SENTINEL.to_string(),
                json_body: None,
                ..probe.clone()
            };
            build_request(base, parameter, &benign)
        }
        InjectionStyle::JsonBody => {
            // Same POST + application/json and the same top-level key(s), with
            // every operator/array object replaced by a benign scalar.
            let benign = NoSqlProbe {
                json_body: Some(benign_json_body(probe.json_body.as_deref(), SENTINEL)),
                query_key: None,
                ..probe.clone()
            };
            build_request(base, parameter, &benign)
        }
    }
}

/// Rewrite a probe body so each field maps to a benign scalar instead of an
/// operator object — `{"user":{"$ne":null}}` becomes `{"user":"<sentinel>"}`.
/// Falls back to a minimal benign object if the body is absent or unparseable.
fn benign_json_body(body: Option<&str>, sentinel: &str) -> String {
    if let Some(b) = body {
        if let Ok(serde_json::Value::Object(mut map)) =
            serde_json::from_str::<serde_json::Value>(b)
        {
            for (_k, v) in map.iter_mut() {
                if v.is_object() || v.is_array() {
                    *v = serde_json::Value::String(sentinel.to_string());
                }
            }
            if let Ok(s) = serde_json::to_string(&serde_json::Value::Object(map)) {
                return s;
            }
        }
    }
    format!("{{\"control\":\"{sentinel}\"}}")
}

/// Execute one probe `REQUIRED_REPETITIONS` times and report whether it
/// differed from an **interleaved, shape-matched control** every time
/// (reproduced), plus the last payload view.
///
/// The control ([`build_control_request`]) shares the probe's method, headers
/// and body structure but carries a benign value, so environmental drift — an
/// edge rate-limit, a method-routed 403, a cache flip, response jitter — moves
/// *both* requests and cancels out of the comparison. Only a difference between
/// the payload and its own benign control counts as a differential. This is
/// what stops a consistent rate-limit 403, or an endpoint that simply ignores
/// the parameter, from masquerading as a positive against a stale baseline.
async fn run_repeated(
    client: &SafeHttpClient,
    base: &HttpRequest,
    parameter: &str,
    probe: &NoSqlProbe,
) -> RepeatOutcome {
    let mut diffs = Vec::new();
    let mut last: Option<View> = None;
    for _ in 0..REQUIRED_REPETITIONS {
        // Shape-matched benign control taken next to the payload.
        let control_req = build_control_request(base, parameter, probe);
        let control = match client.execute(control_req).await {
            Ok(resp) => view_of(&resp),
            Err(_) => return RepeatOutcome { view: last, reproduced: false, flaky: false, errored: true },
        };
        let req = build_request(base, parameter, probe);
        match client.execute(req).await {
            Ok(resp) => {
                let v = view_of(&resp);
                diffs.push(differs(&control, &v));
                last = Some(v);
            }
            Err(_) => return RepeatOutcome { view: last, reproduced: false, flaky: false, errored: true },
        }
    }
    let all_same = diffs.iter().all(|d| *d == diffs[0]);
    RepeatOutcome {
        reproduced: all_same && diffs.first().copied().unwrap_or(false),
        flaky: !all_same,
        view: last,
        errored: false,
    }
}

struct RepeatOutcome {
    view: Option<View>,
    reproduced: bool,
    flaky: bool,
    errored: bool,
}

/// Run the NoSQL pipeline for one parameterized endpoint.
pub async fn run_nosql(
    base: &HttpRequest,
    parameter: &str,
    scope: Arc<ScopeEngine>,
    config: NoSqlConfig,
) -> Result<NoSqlAssessment, String> {
    let client = SafeHttpClient::new(
        scope,
        HttpClientConfig {
            max_concurrency: 2,
            rate_limit_rps: 5.0,
            max_budget: 5_000,
            ..Default::default()
        },
    );

    // ── Stage 1: baseline.
    let mut samples: Vec<View> = Vec::new();
    for _ in 0..config.baseline_samples.max(2) {
        let resp = client.execute(base.clone()).await.map_err(|e| e.to_string())?;
        samples.push(view_of(&resp));
    }
    let reference = samples.last().cloned().ok_or("no baseline sample")?;
    let baseline_stable = samples.iter().all(|s| s.status == reference.status)
        && samples
            .iter()
            .all(|s| diff_ratio(s.body_len, reference.body_len) <= 0.05);
    let baseline_summary = format!(
        "{} samples, status {}, ~{} bytes, {}",
        samples.len(),
        reference.status,
        reference.body_len,
        if baseline_stable { "stable" } else { "UNSTABLE" }
    );

    // ── Stage 2: experiments.
    let mut evidence = Evidence { baseline_stable, ..Default::default() };
    let mut experiments = 0usize;
    let mut duplicates = 0usize;
    let mut repetitions_verified = 0usize;
    let mut flaky = 0usize;
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut signals: Vec<String> = Vec::new();
    let mut datastore: Vec<(NoSqlFamily, u32)> = Vec::new();
    let mut boolean_true: Option<View> = None;
    let mut boolean_false: Option<View> = None;

    // Ordered probe batches: error → auth → boolean → timing.
    let mut batch: Vec<NoSqlProbe> = Vec::new();
    batch.extend(payload::error_probes(parameter, ""));
    batch.extend(payload::auth_bypass_probes(parameter));
    batch.extend(payload::boolean_pair(parameter));
    batch.extend(payload::where_timing(parameter, config.where_delay_ms));

    for probe in &batch {
        if experiments >= config.max_experiments {
            break;
        }
        let key = (probe.logical_label.clone(), format!("{:?}", probe.style));
        if !seen.insert(key) {
            duplicates += 1;
            continue;
        }
        let outcome = run_repeated(&client, base, parameter, probe).await;
        if outcome.errored {
            continue;
        }
        let view = match &outcome.view {
            Some(v) => v.clone(),
            None => continue,
        };
        experiments += 1;
        if outcome.flaky {
            flaky += 1;
            continue;
        }
        repetitions_verified += 1;

        // Datastore fingerprint from any error signature in the body.
        let det = detection::analyze_error_body(&view.body);
        if let Some(family) = det.detected {
            evidence.error_signature_seen = true;
            match datastore.iter_mut().find(|(f, _)| *f == family) {
                Some((_, w)) => *w = (*w).max(det.confidence),
                None => datastore.push((family, det.confidence)),
            }
            for s in &det.signals {
                signals.push(format!("error signature: {}", s.label));
            }
        }
        // Environmental block (edge WAF/rate-limit) invalidates app inference.
        if view.status == 429 || view.status == 403 {
            evidence.blocked = true;
            signals.push(format!("edge/blocked status {}", view.status));
        }

        match probe.technique {
            NoSqlTechnique::AuthBypass => {
                evidence.auth_tested = true;
                if outcome.reproduced {
                    evidence.auth_bypass_differential = true;
                    signals.push(format!("auth-bypass differential ({})", probe.logical_label));
                }
            }
            NoSqlTechnique::BooleanBlind => {
                evidence.boolean_tested = true;
                match probe.expected_truthy {
                    Some(true) => boolean_true = Some(view.clone()),
                    Some(false) => boolean_false = Some(view.clone()),
                    None => {}
                }
            }
            NoSqlTechnique::WhereTiming => {
                // A timing signal is a large, reproduced duration increase.
                if outcome.reproduced
                    && view.duration_ms > reference.duration_ms.saturating_add(config.where_delay_ms / 2)
                {
                    evidence.timing_separated = true;
                    signals.push(format!(
                        "timing separation: {}ms vs baseline {}ms",
                        view.duration_ms, reference.duration_ms
                    ));
                }
            }
            NoSqlTechnique::ErrorProbe | NoSqlTechnique::RegexExtraction => {}
        }
    }

    // Boolean divergence is the two arms differing from EACH OTHER, not just
    // from baseline — the matched-pair experiment.
    if let (Some(t), Some(f)) = (&boolean_true, &boolean_false) {
        if differs(t, f) {
            evidence.boolean_diverged = true;
            signals.push("boolean pair diverged (truthy vs falsy)".to_string());
        }
    }

    // ── Stage 3: bounded, read-only $regex extraction (only if warranted).
    let extracted_prefix = if config.extract_field.is_some()
        && (evidence.auth_bypass_differential || evidence.boolean_diverged)
    {
        match extract_prefix(&client, base, parameter, &config, &mut experiments).await {
            ExtractOutcome::Recovered(s) => Some(s),
            ExtractOutcome::OracleDead => {
                // The two extraction poles were indistinguishable: the endpoint's
                // response does not depend on the injected predicate. Any prefix
                // would be fabricated, so none is emitted.
                evidence.regex_oracle_dead = true;
                signals.push(
                    "regex extraction aborted — oracle liveness check failed (guaranteed \
                     match and no-match poles were indistinguishable); no value recovered"
                        .into(),
                );
                None
            }
            ExtractOutcome::NothingRecovered => None,
        }
    } else {
        None
    };

    // ── Stage 4: verdict.
    let coverage = decide_coverage(&evidence, experiments);
    let confirmed = matches!(coverage, NoSqlCoverage::Confirmed);
    let mut confidence = 0.0f32;
    if evidence.auth_bypass_differential {
        confidence += 0.3;
    }
    if evidence.boolean_diverged {
        confidence += 0.3;
    }
    if evidence.timing_separated {
        confidence += 0.2;
    }
    if evidence.error_signature_seen {
        confidence += 0.2;
    }
    if !baseline_stable {
        confidence *= 0.5;
    }
    confidence = confidence.clamp(0.0, 1.0);

    let techniques = summarize_techniques(&evidence);
    let diagnostic_report = build_diagnostics(&evidence, experiments, &coverage);
    let mut remaining_uncertainty = Vec::new();
    if datastore.is_empty() {
        remaining_uncertainty
            .push("Datastore not fingerprinted — no NoSQL error signature was observed".into());
    }
    if !evidence.boolean_diverged && !evidence.auth_bypass_differential {
        remaining_uncertainty
            .push("No repeatable injection differential — any single observation is unconfirmed".into());
    }
    let mut limitations = vec![
        "Detection is response-based; no out-of-band confirmation was attempted".to_string(),
    ];
    if !baseline_stable {
        limitations.push("Baseline was unstable; differentials are less trustworthy".into());
    }
    if evidence.regex_oracle_dead {
        limitations.push(
            "Read-only extraction was requested but the response oracle could not distinguish a \
             matching predicate from a non-matching one; no field value was extracted".into(),
        );
    }

    signals.sort();
    signals.dedup();

    Ok(NoSqlAssessment {
        target: base.url.clone(),
        endpoint: url::Url::parse(&base.url)
            .map(|u| u.path().to_string())
            .unwrap_or_default(),
        parameter: parameter.to_string(),
        baseline_summary,
        baseline_stable,
        datastore_hypotheses: datastore
            .into_iter()
            .map(|(f, w)| (f.display_name().to_string(), w))
            .collect(),
        signals,
        techniques,
        experiments_executed: experiments,
        duplicates_avoided: duplicates,
        repetitions_verified,
        flaky_tests: flaky,
        extracted_prefix,
        coverage: coverage.label().to_string(),
        confidence,
        confirmed,
        diagnostic_report,
        remaining_uncertainty,
        limitations,
    })
}

/// The outcome of an extraction attempt.
enum ExtractOutcome {
    /// A prefix was read back through a proven-live oracle.
    Recovered(String),
    /// The oracle failed its liveness check — no value could be honestly read.
    OracleDead,
    /// The oracle was live but no candidate extended the prefix.
    NothingRecovered,
}

/// Execute a probe `REQUIRED_REPETITIONS` times and return its view **only if**
/// the responses are structurally stable across repetitions. A flaky or errored
/// probe returns `None`, so an unstable pole can never anchor an inference.
async fn stable_probe_view(
    client: &SafeHttpClient,
    base: &HttpRequest,
    parameter: &str,
    probe: &NoSqlProbe,
) -> Option<View> {
    let mut views: Vec<View> = Vec::new();
    for _ in 0..REQUIRED_REPETITIONS {
        let req = build_request(base, parameter, probe);
        match client.execute(req).await {
            Ok(resp) => views.push(view_of(&resp)),
            Err(_) => return None,
        }
    }
    let first = views.first()?.clone();
    if views.iter().all(|v| !differs(&first, v)) {
        Some(first)
    } else {
        None
    }
}

/// Bounded, strictly read-only `$regex` prefix extraction.
///
/// Only invoked after an injection differential is already established. Before
/// trusting any inference it proves the oracle is *live* using two poles:
///
/// * a **no-match** pole (`^￿`, a noncharacter anchor that selects zero rows), and
/// * a **match-all** pole (`^`, which matches every row).
///
/// If those two responses are indistinguishable, the endpoint's output does not
/// depend on the predicate — the oracle is dead — and extraction aborts with
/// [`ExtractOutcome::OracleDead`] rather than walking the alphabet against a
/// stale baseline and emitting a fabricated string. When the oracle is live,
/// each candidate is judged by whether its response differs from the *live*
/// no-match pole, never from the run's baseline. Bounded by `extract_max_len`,
/// the alphabet, and the shared `experiments` budget. Never writes.
async fn extract_prefix(
    client: &SafeHttpClient,
    base: &HttpRequest,
    parameter: &str,
    config: &NoSqlConfig,
    experiments: &mut usize,
) -> ExtractOutcome {
    let field = match config.extract_field.as_ref() {
        Some(f) => f,
        None => return ExtractOutcome::NothingRecovered,
    };

    // Establish the two poles from fresh, stable observations.
    let no_match = match payload::regex_impossible_probe(field) {
        Some(p) => {
            let v = stable_probe_view(client, base, parameter, &p).await;
            *experiments += 1;
            v
        }
        None => None,
    };
    let match_all = match payload::regex_match_all_probe(field) {
        Some(p) => {
            let v = stable_probe_view(client, base, parameter, &p).await;
            *experiments += 1;
            v
        }
        None => None,
    };
    let (no_match, match_all) = match (no_match, match_all) {
        (Some(n), Some(m)) => (n, m),
        // A pole was unstable or unavailable: no trustworthy oracle.
        _ => return ExtractOutcome::OracleDead,
    };
    // Liveness gate: a guaranteed match and a guaranteed no-match MUST produce
    // distinguishable responses. If they don't, the oracle is dead.
    if !differs(&match_all, &no_match) {
        return ExtractOutcome::OracleDead;
    }

    let mut known = String::new();
    'positions: for _ in 0..config.extract_max_len {
        let step = payload::regex_extraction_step(parameter, field, &known, &config.extract_alphabet);
        let mut matched: Option<char> = None;
        for probe in &step {
            if *experiments >= config.max_experiments {
                break 'positions;
            }
            let cand = stable_probe_view(client, base, parameter, probe).await;
            *experiments += 1;
            let cand = match cand {
                Some(v) => v,
                None => continue,
            };
            // A candidate matched iff its response differs from the LIVE
            // no-match pole (it selected rows the empty predicate did not).
            if differs(&cand, &no_match) {
                matched = probe.value.chars().next();
                break;
            }
        }
        match matched {
            Some(c) => known.push(c),
            None => break 'positions, // no candidate extended the prefix
        }
    }
    if known.is_empty() {
        ExtractOutcome::NothingRecovered
    } else {
        ExtractOutcome::Recovered(known)
    }
}

/// Build the per-technique summary lines from accumulated evidence.
fn summarize_techniques(e: &Evidence) -> Vec<TechniqueSummary> {
    let mut out = Vec::new();
    out.push(TechniqueSummary {
        technique: "error_probe".into(),
        executed: 1,
        repeatable_differential: e.error_signature_seen,
        evidence_strength: if e.error_signature_seen { 0.6 } else { 0.0 },
    });
    if e.auth_tested {
        out.push(TechniqueSummary {
            technique: "auth_bypass".into(),
            executed: 1,
            repeatable_differential: e.auth_bypass_differential,
            evidence_strength: if e.auth_bypass_differential { 0.8 } else { 0.0 },
        });
    }
    if e.boolean_tested {
        out.push(TechniqueSummary {
            technique: "boolean_blind".into(),
            executed: 1,
            repeatable_differential: e.boolean_diverged,
            evidence_strength: if e.boolean_diverged { 0.8 } else { 0.0 },
        });
    }
    out.push(TechniqueSummary {
        technique: "where_timing".into(),
        executed: 1,
        repeatable_differential: e.timing_separated,
        evidence_strength: if e.timing_separated { 0.7 } else { 0.0 },
    });
    out
}

/// Compose the human-readable diagnostic narrative.
fn build_diagnostics(e: &Evidence, experiments: usize, coverage: &NoSqlCoverage) -> Vec<String> {
    let mut d = Vec::new();
    d.push(format!(
        "Ran {experiments} verified experiment(s) against a {} baseline.",
        if e.baseline_stable { "stable" } else { "unstable" }
    ));
    if e.auth_bypass_differential {
        d.push("Operator injection (`$ne`/`$gt`) produced a repeatable differential — the parameter reached the query object.".into());
    }
    if e.boolean_diverged {
        d.push("The matched truthy/falsy operator pair diverged from each other — boolean-blind inference is viable.".into());
    }
    if e.timing_separated {
        d.push("A `$where` conditional delay reproduced a timing separation from baseline.".into());
    }
    if e.error_signature_seen {
        d.push("A NoSQL driver error signature fingerprinted the datastore.".into());
    }
    if e.blocked {
        d.push("An edge control (WAF/rate-limit) returned 403/429 — application-layer inference is degraded.".into());
    }
    if e.regex_oracle_dead {
        d.push(
            "`$regex` extraction was attempted but aborted: a guaranteed-match and a \
             guaranteed-no-match probe produced indistinguishable responses, so the endpoint's \
             output does not track the predicate. No value was recovered (a walked alphabet here \
             would be fabricated).".into(),
        );
    }
    match coverage {
        NoSqlCoverage::NotInterpreted => d.push(
            "Verdict NOT_INTERPRETED: operator injection ran against a stable baseline and never diverged. Positive evidence the parameter is not parsed as a query object.".into(),
        ),
        NoSqlCoverage::Confirmed => d.push(
            "Verdict CONFIRMED: multiple independent techniques corroborate operator injection.".into(),
        ),
        NoSqlCoverage::Interesting => d.push(
            "Verdict INTERESTING: a repeatable differential was observed but is not yet corroborated across techniques.".into(),
        ),
        NoSqlCoverage::Blocked => d.push(
            "Verdict BLOCKED: the environment prevented reliable observation.".into(),
        ),
        NoSqlCoverage::Inconclusive => d.push(
            "Verdict INCONCLUSIVE: experiments ran but nothing separated from baseline or noise.".into(),
        ),
        NoSqlCoverage::Baselined => d.push("Verdict BASELINED: no experiments ran.".into()),
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(status: u16, body: &str, len: usize, dur: u64) -> View {
        View { status, body: body.into(), body_len: len, duration_ms: dur, hash: normalized_hash(body) }
    }

    #[test]
    fn normalized_hash_ignores_whitespace_and_digit_runs() {
        // Dynamic timestamps/counters and reflowed whitespace must not register
        // as a structural difference.
        let a = normalized_hash("user 12345 online at 09:31:07");
        let b = normalized_hash("user   987  online   at   23:00:00");
        assert_eq!(a, b);
    }

    #[test]
    fn normalized_hash_detects_structural_change() {
        assert_ne!(normalized_hash("welcome back"), normalized_hash("access denied"));
    }

    #[test]
    fn diff_ratio_is_bounded_and_symmetric_enough() {
        assert_eq!(diff_ratio(100, 100), 0.0);
        assert!((diff_ratio(100, 150) - 0.333).abs() < 0.01);
        assert!(diff_ratio(0, 0) <= 1.0);
    }

    #[test]
    fn differs_on_status_hash_or_size() {
        let base = view(200, "hello world", 11, 10);
        assert!(!differs(&base, &view(200, "hello world", 11, 999)), "duration alone must not count");
        assert!(differs(&base, &view(500, "hello world", 11, 10)), "status change");
        assert!(differs(&base, &view(200, "totally different", 17, 10)), "structural change");
        assert!(differs(&base, &view(200, "hello world padded to a much larger body", 60, 10)), "size change");
    }

    #[test]
    fn build_request_json_body_switches_to_post() {
        let base = HttpRequest {
            id: uuid::Uuid::nil(),
            job_id: None,
            url: "https://example.test/login?user=alice".into(),
            method: "GET".into(),
            headers: std::collections::HashMap::new(),
            body: None,
            timestamp: chrono::Utc::now(),
        };
        let probe = &payload::auth_bypass_probes("user")
            .into_iter()
            .find(|p| matches!(p.style, InjectionStyle::JsonBody))
            .unwrap();
        let req = build_request(&base, "user", probe);
        assert_eq!(req.method, "POST");
        assert_eq!(req.headers.get("Content-Type").map(String::as_str), Some("application/json"));
        assert!(req.body.as_deref().unwrap().contains("$ne"));
    }

    #[test]
    fn build_request_query_bracket_rewrites_key() {
        let base = HttpRequest {
            id: uuid::Uuid::nil(),
            job_id: None,
            url: "https://example.test/login?user=alice&next=/home".into(),
            method: "GET".into(),
            headers: std::collections::HashMap::new(),
            body: None,
            timestamp: chrono::Utc::now(),
        };
        let probe = &payload::auth_bypass_probes("user")
            .into_iter()
            .find(|p| matches!(p.style, InjectionStyle::QueryBracket))
            .unwrap();
        let req = build_request(&base, "user", probe);
        // The injected operator key replaces the target parameter; the unrelated
        // parameter is preserved.
        assert!(req.url.contains("%24ne") || req.url.contains("$ne"), "operator key present: {}", req.url);
        assert!(req.url.contains("next="), "unrelated param preserved: {}", req.url);
    }

    #[test]
    fn coverage_baselined_when_no_experiments() {
        let e = Evidence { baseline_stable: true, ..Default::default() };
        assert_eq!(decide_coverage(&e, 0), NoSqlCoverage::Baselined);
    }

    #[test]
    fn coverage_not_interpreted_on_verified_stable_null_result() {
        let e = Evidence {
            baseline_stable: true,
            auth_tested: true,
            boolean_tested: true,
            ..Default::default()
        };
        assert_eq!(decide_coverage(&e, 6), NoSqlCoverage::NotInterpreted);
    }

    #[test]
    fn coverage_confirmed_needs_corroboration_and_a_positive() {
        let e = Evidence {
            baseline_stable: true,
            auth_bypass_differential: true,
            boolean_diverged: true,
            auth_tested: true,
            boolean_tested: true,
            ..Default::default()
        };
        assert_eq!(decide_coverage(&e, 8), NoSqlCoverage::Confirmed);
    }

    #[test]
    fn coverage_interesting_on_single_uncorroborated_differential() {
        let e = Evidence {
            baseline_stable: true,
            boolean_diverged: true,
            boolean_tested: true,
            ..Default::default()
        };
        assert_eq!(decide_coverage(&e, 4), NoSqlCoverage::Interesting);
    }

    #[test]
    fn coverage_blocked_dominates_when_no_positive() {
        let e = Evidence { baseline_stable: true, blocked: true, auth_tested: true, ..Default::default() };
        assert_eq!(decide_coverage(&e, 3), NoSqlCoverage::Blocked);
    }

    #[test]
    fn coverage_blocked_yields_to_a_positive_finding() {
        // A confirmed injection outranks an environmental block.
        let e = Evidence {
            baseline_stable: true,
            blocked: true,
            auth_bypass_differential: true,
            boolean_diverged: true,
            auth_tested: true,
            boolean_tested: true,
            ..Default::default()
        };
        assert_eq!(decide_coverage(&e, 8), NoSqlCoverage::Confirmed);
    }
}

/// Live-target regression tests over a local TCP server, reproducing the exact
/// fabrication scenarios the trust-model fix targets: an endpoint that ignores
/// the parameter, an endpoint behind a constant rate-limit 403, and a genuinely
/// injectable endpoint whose secret is honestly recoverable.
#[cfg(test)]
mod live_tests {
    use super::*;
    use bugtools_core::scope::{ScopeRule, ScopeRuleType};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Clone, Copy)]
    enum Mode {
        /// Same 200 body for every request — the parameter is not used.
        IgnoreParam,
        /// Constant 403 for every request — an edge rate-limit.
        Always403,
        /// GET is answered 200 with a stable body; POST is method-routed to a
        /// 403. Reproduces the real-world case where the baseline GET and a
        /// `JsonBody` POST probe differ for a reason unrelated to the operator —
        /// a false differential unless the control mirrors the POST shape.
        MethodRouted403,
        /// A real operator/regex-injectable endpoint hiding the secret "abc".
        Injectable,
    }

    const SECRET: &str = "abc";

    fn regex_pattern(req: &str) -> Option<&str> {
        let key = "\"$regex\":\"";
        let start = req.find(key)? + key.len();
        let rest = &req[start..];
        let end = rest.find('"')?;
        Some(&rest[..end])
    }

    fn respond(mode: Mode, req: &str) -> (u16, String) {
        match mode {
            Mode::IgnoreParam => (200, "static content, identical for every request".into()),
            Mode::Always403 => (403, "forbidden by edge".into()),
            Mode::MethodRouted403 => {
                // The edge routes by method: GET is served, POST is refused.
                if req.starts_with("POST") {
                    (403, "forbidden: method blocked by edge".into())
                } else {
                    (200, "static content, identical for every GET request".into())
                }
            }
            Mode::Injectable => {
                if req.contains("$ne") {
                    // Truthy operator → authenticated view.
                    (200, "WELCOME AUTHENTICATED DASHBOARD longer body here xxxxxxxxxx".into())
                } else if let Some(pat) = regex_pattern(req) {
                    let prefix = pat.strip_prefix('^').unwrap_or(pat);
                    if SECRET.starts_with(prefix) {
                        (200, "MATCH row present aaaaaaaaaaaaaaaaaaaaaaaaaaaa".into())
                    } else {
                        (200, "NOMATCH empty".into())
                    }
                } else {
                    // Baseline / control / falsy: unauthenticated.
                    (200, "denied".into())
                }
            }
        }
    }

    async fn serve(mode: Mode) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut received = Vec::new();
                    let mut buffer = [0u8; 4096];
                    // Read headers.
                    while !received.windows(4).any(|w| w == b"\r\n\r\n") {
                        match socket.read(&mut buffer).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => received.extend_from_slice(&buffer[..n]),
                        }
                    }
                    // If a Content-Length is present, drain the body too.
                    let head = String::from_utf8_lossy(&received).to_string();
                    let content_len = head
                        .lines()
                        .find_map(|l| {
                            let l = l.to_ascii_lowercase();
                            l.strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().ok())
                        })
                        .flatten()
                        .unwrap_or(0);
                    let header_end = received
                        .windows(4)
                        .position(|w| w == b"\r\n\r\n")
                        .map(|p| p + 4)
                        .unwrap_or(received.len());
                    let mut body_have = received.len().saturating_sub(header_end);
                    while body_have < content_len {
                        match socket.read(&mut buffer).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                received.extend_from_slice(&buffer[..n]);
                                body_have += n;
                            }
                        }
                    }
                    let full = String::from_utf8_lossy(&received).to_string();
                    let (status, body) = respond(mode, &full);
                    let out = format!(
                        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(out.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        format!("http://{addr}/login?user=alice")
    }

    fn scope_for_localhost() -> Arc<ScopeEngine> {
        Arc::new(ScopeEngine::with_rules(vec![ScopeRule::new(
            uuid::Uuid::new_v4(),
            ScopeRuleType::IncludeDomain,
            "127.0.0.1",
        )]))
    }

    fn request(url: String) -> HttpRequest {
        HttpRequest {
            id: uuid::Uuid::new_v4(),
            job_id: None,
            url,
            method: "GET".to_string(),
            headers: std::collections::HashMap::new(),
            body: None,
            timestamp: chrono::Utc::now(),
        }
    }

    fn extract_config() -> NoSqlConfig {
        NoSqlConfig {
            baseline_samples: 2,
            max_experiments: 60,
            where_delay_ms: 0,
            extract_field: Some("password".into()),
            extract_alphabet: "abc".into(),
            extract_max_len: 4,
        }
    }

    #[tokio::test]
    async fn ignored_parameter_never_fabricates_and_reports_not_interpreted() {
        let url = serve(Mode::IgnoreParam).await;
        let result = run_nosql(&request(url), "user", scope_for_localhost(), extract_config())
            .await
            .unwrap();
        // The core fix: an endpoint that ignores the parameter yields no
        // differential, no extracted value, and the honest negative verdict.
        assert_eq!(result.extracted_prefix, None, "must not fabricate a prefix");
        assert!(!result.confirmed, "an ignored parameter is not a confirmed injection");
        assert_eq!(result.coverage, "NOT_INTERPRETED", "coverage: {}", result.coverage);
    }

    #[tokio::test]
    async fn constant_rate_limit_403_is_blocked_not_a_bypass() {
        let url = serve(Mode::Always403).await;
        let result = run_nosql(&request(url), "user", scope_for_localhost(), extract_config())
            .await
            .unwrap();
        // A consistent 403 hits payload and control alike → no differential.
        assert_eq!(result.extracted_prefix, None, "must not fabricate under a rate-limit");
        assert!(!result.confirmed);
        assert_eq!(result.coverage, "BLOCKED", "coverage: {}", result.coverage);
    }

    #[tokio::test]
    async fn method_routed_403_is_not_a_false_auth_bypass() {
        // The endpoint answers the baseline GET 200 but routes every POST to a
        // 403. A JsonBody auth-bypass probe is a POST, so comparing it against
        // the GET baseline would always look like a differential (and the 403
        // would trip `blocked`), reading as INTERESTING. With a shape-matched
        // control the 403 hits payload and control alike and the differential
        // collapses — the honest verdict is BLOCKED, not a bypass.
        let url = serve(Mode::MethodRouted403).await;
        let result = run_nosql(&request(url), "user", scope_for_localhost(), extract_config())
            .await
            .unwrap();
        assert_eq!(result.extracted_prefix, None, "must not fabricate under method routing");
        assert!(!result.confirmed, "a method-routed 403 is not an injection");
        assert_ne!(
            result.coverage, "INTERESTING",
            "method mismatch must not read as a differential: {}",
            result.coverage
        );
        assert_eq!(result.coverage, "BLOCKED", "coverage: {}", result.coverage);
    }

    #[tokio::test]
    async fn injectable_endpoint_recovers_the_real_secret() {
        let url = serve(Mode::Injectable).await;
        let result = run_nosql(&request(url), "user", scope_for_localhost(), extract_config())
            .await
            .unwrap();
        // A genuine injection: the differential is real, the oracle is live, and
        // the recovered value is the actual secret — not a walked placeholder.
        assert_eq!(result.extracted_prefix.as_deref(), Some(SECRET), "coverage: {}", result.coverage);
        assert!(result.confirmed, "corroborated injection should confirm");
    }
}



