//! Adaptive SQLi research pipeline (the evidence-driven replacement).
//!
//! This is the integration layer that makes the CLI/GUI produce learnable
//! output instead of a probe dump. It:
//!
//! 1. Collects a multi-sample baseline and judges stability.
//! 2. Runs a bounded set of *distinct* experiments, deduplicating by test
//!    fingerprint and collapsing equivalent families.
//! 3. Extracts typed signals from every comparison (never empty).
//! 4. Infers context / query-position / DBMS hypotheses from behaviour.
//! 5. Produces a diagnostic report — including for zero-result scans.

use crate::adaptive::baseline::{BaselineProfile, BaselineSample};
use crate::adaptive::fingerprint::{TestFingerprint, TestLedger, TestStatus};
use crate::adaptive::hypotheses::{infer_context, infer_dbms, ContextObservations, DbmsObservations};
use crate::adaptive::planner::{negative_result_report, remaining_uncertainty, CoverageState};
use crate::adaptive::repetition::{RepetitionTracker, RepetitionVerdict};
use crate::adaptive::signals::{extract_signals, ResponseView, Signal, SignalKind};
use crate::detection::DbmsFamily;
use crate::extract::{ConfirmedInjection, DumpSpec, ExtractedFact, ExtractionSession};
use crate::oob::{InteractionType, OobCorrelation, OobCorrelator, OobProvider, OobToken};
use crate::payload::{
    compose_for, compose_oob, decide_tier, techniques_for, ClauseStrategy, ComposeContext,
    EscalationTier, EvidenceSummary, QuoteMode, RepresentationContext,
};
use crate::safety::{is_oob_confirmation, SafetyLevel, SafetyVerdict};
use bugtools_core::http::HttpRequest;
use bugtools_scope::ScopeEngine;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// Summary of the wide technique sweep that ran before the adaptive phase.
///
/// The batch scanner runs the shared payload catalogue first (see
/// `generators::catalog`), which is what gives it the same technique coverage
/// as the single-URL analyze path. Recording what actually executed lets a
/// report distinguish "127 techniques ran and found nothing" from "8 techniques
/// ran because the depth was recon" — the difference between a negative result
/// and an unfinished one.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SweepSummary {
    /// Payloads attempted, after tier gating, technique filter and tampers.
    pub payloads_attempted: usize,
    /// How many the catalogue could have offered at this depth.
    pub payloads_available: usize,
    /// Per-technique counts, e.g. `("TimingProbe", 37)`.
    pub by_technique: Vec<(String, usize)>,
    /// Payloads whose response carried a DBMS-attributable signal.
    pub with_signal: usize,
    /// The engine the sweep named, if the response text revealed one.
    pub detected_dbms: Option<String>,
    /// The tamper chain applied to every payload (`identity` when none).
    pub tamper_chain: String,
    /// Technique labels selected on the command line (empty = tier default).
    pub technique_filter: Vec<String>,
}

/// The full result of an adaptive run against one parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveResult {
    pub target: String,
    pub endpoint: String,
    pub parameter: String,
    pub input_location: String,

    pub baseline_summary: String,
    pub baseline_stable: bool,

    pub context_hypotheses: Vec<(String, f32)>,
    pub query_position_hypotheses: Vec<(String, f32)>,
    pub dbms_hypotheses: Vec<(String, f32)>,

    pub signals: Vec<(String, f32)>,
    pub tested_families: Vec<FamilySummary>,
    pub experiments_executed: usize,
    pub duplicates_avoided: usize,
    /// Wide-catalogue sweep that preceded the adaptive phase, when one ran.
    /// Additive and optional: absent means "no sweep was executed", never
    /// "a sweep ran and found nothing".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sweep: Option<SweepSummary>,
    /// Tests whose outcome reproduced across repeated executions.
    pub repetitions_verified: usize,
    /// Tests whose outcomes disagreed across repetitions and were discarded.
    pub flaky_tests: usize,

    pub coverage: String,
    pub confidence: f32,
    pub confirmed: bool,

    /// Values recovered through the confirmed channel after a positive result
    /// (sqlmap's `getValue` analogue: banner / current-user / current-db /
    /// is-dba, plus any opt-in dump rows). Empty when nothing was extracted —
    /// a value that could not be read back is never fabricated here.
    #[serde(default)]
    pub extracted: Vec<ExtractedFact>,
    /// Out-of-band correlations: a planted token that arrived at the
    /// operator's collector inside its window. Each is proof of a (possibly
    /// fully blind) injection — the DB reached out to infrastructure we
    /// control. Empty unless the OOB stage ran and something correlated;
    /// stray/uncorrelated traffic is never recorded here.
    #[serde(default)]
    pub oob_correlations: Vec<OobCorrelation>,
    /// Whether the out-of-band stage actually ran (a collector was configured
    /// and an engine was identifiable). Lets a report say "OOB was attempted
    /// and nothing correlated" rather than silently omitting the channel.
    #[serde(default)]
    pub oob_attempted: bool,
    /// What was established even when nothing was found.
    pub diagnostic_report: Vec<String>,
    pub remaining_uncertainty: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilySummary {
    pub family: String,
    pub technique: String,
    pub tested: usize,
    pub executed: usize,
    pub equivalent_result: bool,
    pub evidence_strength: f32,
}

/// Configuration for an adaptive run.
#[derive(Debug, Clone)]
pub struct AdaptiveConfig {
    pub baseline_samples: usize,
    pub max_experiments: usize,
    pub delay_seconds: u32,
    /// Optional DBMS hypothesis supplied by the caller's fingerprinting.
    pub dbms_hint: Option<DbmsFamily>,
    /// Application technology hint (from the tech engine).
    pub application_hint: Option<String>,
    /// Recover a read-only proof set (version / user / db / is-dba) once a
    /// positive result is reached. On by default; the CLI's `--no-prove`
    /// disables it.
    pub extract: bool,
    /// When set, additionally walk a table read-only after the proof set
    /// (sqlmap's `--dump`, opt-in and row-capped).
    pub dump: Option<DumpSpec>,
    /// Technique labels selected on the command line (e.g. `["boolean","union"]`).
    /// Empty means "no restriction — use the tier's default technique set".
    /// When non-empty, the adaptive escalation phase only composes techniques
    /// whose label matches the filter, so `--techniques` constrains the whole
    /// run rather than just the pre-sweep.
    pub techniques: Vec<String>,
    /// When set, run the out-of-band confirmation stage against an
    /// operator-configured collector. Constructed and `register`ed by the CLI;
    /// `None` (the default) means the OOB stage never runs.
    pub oob: Option<OobRun>,
}

/// A live, registered out-of-band collector the OOB stage polls.
#[derive(Clone)]
pub struct OobRun {
    /// The callback domain tokens attach to (from `provider.register()`).
    pub callback_domain: String,
    /// The collector provider, shared so one registration serves every
    /// parameter in a sweep. Polled with the provider's *own* plain client —
    /// never the scoped `SafeHttpClient` — because it is off-target
    /// operator-owned infrastructure.
    pub provider: Arc<Mutex<dyn OobProvider>>,
    /// How long to wait after sending OOB payloads before polling, giving the
    /// target DB time to perform the outbound lookup.
    pub wait_secs: u64,
}

impl std::fmt::Debug for OobRun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OobRun")
            .field("callback_domain", &self.callback_domain)
            .field("wait_secs", &self.wait_secs)
            .finish_non_exhaustive()
    }
}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        Self {
            baseline_samples: 3,
            max_experiments: 8,
            delay_seconds: 5,
            dbms_hint: None,
            application_hint: None,
            extract: true,
            dump: None,
            techniques: Vec::new(),
            oob: None,
        }
    }
}

/// Execute a request and build a `ResponseView`.
pub(crate) async fn execute(
    client: &bugtools_http::SafeHttpClient,
    base: &HttpRequest,
    payload: Option<&str>,
    parameter: &str,
) -> Result<ResponseView, String> {
    let mut req = base.clone();
    if let Some(value) = payload {
        // Mutate only the target parameter's value in the query string.
        if let Ok(mut url) = url::Url::parse(&base.url) {
            let pairs: Vec<(String, String)> = url
                .query_pairs()
                .map(|(k, v)| {
                    if k == parameter {
                        (k.to_string(), value.to_string())
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

    let resp = client.execute(req).await.map_err(|e| e.to_string())?;
    let content_type = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.clone());
    let location = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("location"))
        .map(|(_, v)| v.clone());

    Ok(ResponseView {
        status: resp.status_code,
        body: resp.body.clone(),
        body_len: resp.size_bytes,
        content_type,
        location,
        duration_ms: resp.duration_ms,
        headers: resp.headers.into_iter().collect(),
        normalized_hash: crate::adaptive::signals::normalize(&resp.body),
    })
}

/// Ordinal rank of an escalation tier, so tiers can be compared.
fn tier_rank(tier: EscalationTier) -> u8 {    match tier {
        EscalationTier::Recon => 0,
        EscalationTier::Confirm => 1,
        EscalationTier::Explore => 2,
    }
}

/// Local cap on extraction requests for one confirmed injection. A secondary
/// fence in front of the client's shared request budget: proof-set recovery is
/// cheap (UNION/error are 1–2 requests each; a blind value costs ~len×8), and a
/// row dump is additionally bounded by its own row cap.
const EXTRACTION_MAX_REQUESTS: usize = 1024;

/// Whether an escalation-phase technique passes the caller's `--techniques`
/// filter. An empty filter selects everything (the tier default). Matching
/// mirrors the sweep's `catalog_for_labels`: case-insensitive, and a label
/// matches by prefix in either direction so `boolean`, `bool`, and
/// `BooleanBlind` all select the boolean technique.
fn technique_selected(technique: crate::types::ProbeType, filter: &[String]) -> bool {
    if filter.is_empty() {
        return true;
    }
    let name = crate::generators::technique_label(technique).to_ascii_lowercase();
    filter.iter().any(|l| {
        let l = l.trim().to_ascii_lowercase();
        !l.is_empty() && (name == l || name.starts_with(&l) || l.starts_with(&name))
    })
}

/// Run the adaptive pipeline for one parameterized endpoint.
pub async fn run_adaptive(
    base: &HttpRequest,
    parameter: &str,
    original_value: &str,
    scope: Arc<ScopeEngine>,
    config: AdaptiveConfig,
) -> Result<AdaptiveResult, String> {
    let client = bugtools_http::SafeHttpClient::new(
        scope,
        bugtools_http::HttpClientConfig {
            max_concurrency: 2,
            rate_limit_rps: 5.0,
            max_budget: 5_000,
            ..Default::default()
        },
    );

    // ── Stage 1: baseline samples.
    let mut samples = Vec::new();
    for _ in 0..config.baseline_samples {
        let view = execute(&client, base, None, parameter).await?;
        samples.push(BaselineSample::from_view(&view));
    }
    let baseline = BaselineProfile::from_samples(samples);
    let baseline_view = execute(&client, base, None, parameter).await?;

    let mut ledger = TestLedger::new();
    let mut all_signals: Vec<Signal> = Vec::new();

    // ── Stage 2: an evidence-gated, escalating set of distinct experiments.
    let mut ctx = ComposeContext {
        clause: ClauseStrategy::Where,
        quote_mode: if original_value.chars().all(|c| c.is_ascii_digit())
            && !original_value.is_empty()
        {
            QuoteMode::None
        } else {
            QuoteMode::Single
        },
        dbms: config.dbms_hint,
        representation: RepresentationContext::QueryValue,
        original_value: original_value.to_string(),
        waf_interference: false,
    };

    let mut experiments = 0usize;
    let mut syntax_error_seen = false;
    let mut boolean_diverged = false;
    // Whether a timing probe produced a statistically separated distribution.
    let mut timing_separated = false;
    // Whether each side of the boolean pair actually ran a verified (non-flaky)
    // test against the baseline — the precondition for a NOT_SQL_INTERPRETED
    // conclusion.
    let mut always_true_tested = false;
    let mut always_false_tested = false;
    let mut observed_error_body: Option<String> = None;
    // The boundary + engine of the first candidate to reach a verified positive
    // — the descriptor the extraction session splices its read-only reads into.
    let mut confirmed_injection: Option<(crate::payload::Boundary, Option<DbmsFamily>)> = None;
    let mut repetitions_verified = 0usize;
    let mut flaky_tests = 0usize;

    // Escalate only as far as accumulated evidence earns: Recon is always run;
    // Confirm and Explore are entered only when `decide_tier` unlocks them.
    // This keeps a parameter with no signal cheap while letting a corroborated
    // one reach Union/Timing/Clause breadth — all bounded by `max_experiments`.
    let tiers = [
        EscalationTier::Recon,
        EscalationTier::Confirm,
        EscalationTier::Explore,
    ];
    'outer: for tier in tiers {
        if tier != EscalationTier::Recon {
            let evidence = EvidenceSummary {
                error_signal: syntax_error_seen,
                boolean_signal: boolean_diverged,
                timing_signal: timing_separated,
                dbms_known: config.dbms_hint.is_some() || observed_error_body.is_some(),
                waf_interference: ctx.waf_interference,
                attempts_so_far: experiments as u32,
            };
            // `decide_tier` returns the highest tier the evidence unlocks; stop
            // escalating once the requested tier exceeds it.
            if tier_rank(tier) > tier_rank(decide_tier(&evidence)) {
                break 'outer;
            }
        }
        // Timing is only spent once a signal has justified escalation.
        let has_delay = tier != EscalationTier::Recon;
        for technique in techniques_for(tier, has_delay) {
            // Honor an explicit `--techniques` filter across the escalation
            // phase, not just the pre-sweep. Empty filter = tier default.
            if !technique_selected(technique, &config.techniques) {
                continue;
            }
            let candidates = compose_for(technique, &ctx, tier, config.delay_seconds);
            for candidate in candidates {
                if experiments >= config.max_experiments {
                    break 'outer;
                }

            // Deduplicate by identity: a family+boundary+transform already
            // run is not re-executed.
            let fingerprint = TestFingerprint {
                endpoint: base.url.clone(),
                parameter: parameter.to_string(),
                location: "query".into(),
                technique: format!("{technique:?}"),
                context: format!("{:?}", ctx.quote_mode),
                boundary: format!("{:?}", candidate.boundary),
                dialect: candidate.dialect.clone().unwrap_or_else(|| "unknown".into()),
                transformation: candidate.trace.summary(),
                semantic_family: candidate.logical_test.clone(),
            };
            if !ledger.register(fingerprint.clone()) {
                continue; // duplicate — skip
            }

            // Execute the SAME test repeatedly. A single differential is not
            // evidence: dynamic content, cache and jitter all produce one-off
            // differences. Only a reproduced outcome is trusted.
            let mut tracker = RepetitionTracker::new();
            let mut last_view: Option<ResponseView> = None;
            for _ in 0..crate::adaptive::repetition::REQUIRED_REPETITIONS {
                match execute(&client, base, Some(&candidate.rendered), parameter).await {
                    Ok(v) => {
                        let reps = extract_signals(
                            &baseline_view,
                            &v,
                            "baseline",
                            &candidate.logical_test,
                        );
                        tracker.push(&reps);
                        last_view = Some(v);
                    }
                    Err(e) => {
                        ledger.record_outcome(&fingerprint, TestStatus::Inconclusive, e);
                        continue;
                    }
                }
            }
            let view = match last_view {
                Some(v) => v,
                None => continue,
            };
            experiments += 1;

            // Verify repetition before accepting any signal.
            let verdict = tracker.verdict();
            let repeated = matches!(verdict, RepetitionVerdict::Reproduced { .. });
            if let RepetitionVerdict::Flaky { detail } = &verdict {
                // A flaky result is recorded as such and contributes nothing.
                flaky_tests += 1;
                ledger.record_outcome(&fingerprint, TestStatus::Inconclusive, detail.clone());
                continue;
            }
            repetitions_verified += 1;

            let signals = extract_signals(
                &baseline_view,
                &view,
                "baseline",
                &candidate.logical_test,
            );

            // Track the two behavioural facts the hypotheses need.
            if signals.iter().any(|s| {
                s.kind == SignalKind::ErrorSignatureChanged
                    || (s.kind == SignalKind::ApplicationError && s.strength > 0.4)
            }) {
                syntax_error_seen = true;
            }
            // Remember the body that carried a DBMS signature for inference.
            if observed_error_body.is_none()
                && crate::detection::analyze_error_body(&view.body).detected_dbms.is_some()
            {
                observed_error_body = Some(view.body.clone());
            }
            if candidate.logical_test.contains("AlwaysTrue")
                || candidate.logical_test.contains("AlwaysFalse")
            {
                // Record that this side of the boolean pair produced a verified
                // (non-flaky) observation against the baseline.
                if candidate.logical_test.contains("AlwaysTrue") {
                    always_true_tested = true;
                }
                if candidate.logical_test.contains("AlwaysFalse") {
                    always_false_tested = true;
                }
                // The pair diverging is captured by comparing in the caller;
                // here a body-similarity change on a boolean test is the hint.
                if signals
                    .iter()
                    .any(|s| s.kind == SignalKind::BodySimilarityChanged && s.strength > 0.2)
                {
                    boolean_diverged = true;
                }
            }

            // A verified timing separation is the timing technique's signal.
            if repeated
                && signals
                    .iter()
                    .any(|s| s.kind == SignalKind::TimingShift && s.strength > 0.3)
            {
                timing_separated = true;
            }
            // Real edge interference widens the representation breadth of every
            // subsequent tier (identity-only is lifted once the WAF is seen).
            if signals.iter().any(|s| s.kind.is_environmental()) {
                ctx.waf_interference = true;
            }

            // Status is gated on repetition: an unverified positive is not
            // allowed to become "Interesting".
            let status = if signals.iter().any(|s| s.kind.is_environmental()) {
                TestStatus::Blocked
            } else if repeated
                && signals
                    .iter()
                    .any(|s| s.kind.supports_sql_hypothesis() && s.strength > 0.3)
            {
                TestStatus::Interesting
            } else {
                TestStatus::ApplicationResponse
            };
            // Remember the first verified positive's boundary + engine so the
            // extraction session can splice its read-only reads under the exact
            // break-out that the differential proved.
            if status == TestStatus::Interesting && confirmed_injection.is_none() {
                confirmed_injection = Some((candidate.boundary.clone(), candidate.expected_dbms));
            }
            ledger.record_outcome(
                &fingerprint,
                status,
                signals
                    .first()
                    .map(|s| s.label().to_string())
                    .unwrap_or_default(),
            );
            // Keep the strongest instance of each signal kind, so the output
            // reports what was observed rather than how many times.
            for signal in signals {
                match all_signals.iter_mut().find(|s| s.kind == signal.kind) {
                    Some(existing) => {
                        if signal.strength > existing.strength {
                            *existing = signal;
                        }
                    }
                    None => all_signals.push(signal),
                }
            }
        }
    }
    }

    // ── Stage 3: summarise.
    let families: Vec<FamilySummary> = ledger
        .families()
        .into_iter()
        .map(|f| FamilySummary {
            family: f.semantic_family,
            technique: f.technique,
            tested: f.tested,
            executed: f.executed,
            equivalent_result: f.equivalent_result,
            evidence_strength: f.evidence_strength,
        })
        .collect();

    // ── Stage 4: hypotheses from observation.
    let context_set = infer_context(&ContextObservations {
        parameter_name: parameter.to_string(),
        original_value: original_value.to_string(),
        declared_type: None,
        accepts_non_numeric: false,
        rejects_non_numeric: false,
        syntax_error_on_quote: syntax_error_seen,
        accepts_quotes: false,
        length_sensitive: false,
        reflected: false,
    });

    // DBMS from the signals the engine actually matched, if the caller
    // pre-computed them; otherwise from any error text observed.
    // Prefer a caller-supplied fingerprint; otherwise derive from the DBMS
    // error signature actually observed in a response.
    let mut dbms_signals: Vec<(String, u32, String)> = Vec::new();
    if let Some(hint) = config.dbms_hint {
        dbms_signals.push((format!("{hint:?}"), 60, "caller-supplied fingerprint".into()));
    }
    if let Some(observed_body) = observed_error_body.as_ref() {
        let detected = crate::detection::analyze_error_body(observed_body);
        for signal in &detected.signals {
            dbms_signals.push((
                format!("{:?}", signal.dbms),
                signal.weight,
                signal.label.clone(),
            ));
        }
    }
    let dbms_set = infer_dbms(&DbmsObservations {
        matched_signals: dbms_signals,
        application_hint: config.application_hint.clone(),
    });

    let position_set = crate::adaptive::hypotheses::infer_query_position(
        &crate::adaptive::hypotheses::PositionObservations {
            parameter_name: parameter.to_string(),
            boolean_diverged,
            expression_syntax_error: syntax_error_seen,
            accepted_ordering: false,
            looks_paginated: false,
            accepted_wildcard: false,
        },
    );

    // ── Stage 5: coverage + confidence.
    let has_positive = ledger.count(TestStatus::Interesting) > 0;

    // ── Stage 5a: read-only extraction (sqlmap's getValue). Once a differential
    // is verified we try to recover a real value through the confirmed channel;
    // a recovered value is what upgrades a positive to CONFIRMED. Every payload
    // passes the read-only gate inside the session, and recovery shares the
    // client's request budget. Nothing is attempted without a known engine.
    let mut extracted: Vec<ExtractedFact> = Vec::new();
    if config.extract && has_positive {
        if let Some((boundary, cand_dbms)) = confirmed_injection.clone() {
            let dbms = cand_dbms.or(config.dbms_hint).or_else(|| {
                observed_error_body
                    .as_ref()
                    .and_then(|b| crate::detection::analyze_error_body(b).detected_dbms)
            });
            match dbms {
                Some(dbms) => {
                    let injection = ConfirmedInjection {
                        dbms,
                        boundary,
                        union_columns: None,
                        union_position: None,
                    };
                    let mut session = ExtractionSession::new(
                        &client,
                        base,
                        parameter,
                        &baseline,
                        injection,
                        config.delay_seconds,
                        EXTRACTION_MAX_REQUESTS,
                    );
                    extracted.extend(session.proof_set().await);
                    if let Some(spec) = &config.dump {
                        extracted.extend(session.dump(spec).await);
                    }
                }
                None => extracted.push(crate::extract::note_fact(
                    "extract",
                    "engine not identified; no read-only expression set to attempt",
                )),
            }
        }
    }

    // ── Stage 5b: out-of-band confirmation. The only proof channel for a
    // *fully blind* injection — no error, no boolean differential, no timing
    // signal. We mint a per-injection correlation token, plant it locally, make
    // the DB reach out to the operator-controlled collector, then poll and
    // correlate. Only a planted token arriving inside its window is evidence;
    // stray traffic never is. Runs solely when the CLI configured a collector
    // (opt-in, authorize-gated) and an engine is identifiable.
    let mut oob_correlations: Vec<OobCorrelation> = Vec::new();
    let mut oob_attempted = false;
    let mut oob_note: Option<String> = None;
    let mut oob_sent = 0usize;
    if let Some(oob) = &config.oob {
        oob_attempted = true;
        // The engine to target: a confirmed candidate's dbms, else the caller's
        // hint, else what an error body revealed. OOB needs a known engine to
        // pick the right outbound primitive; without one there is nothing to send.
        let likely_dbms = confirmed_injection
            .as_ref()
            .and_then(|(_, d)| *d)
            .or(config.dbms_hint)
            .or_else(|| {
                observed_error_body
                    .as_ref()
                    .and_then(|b| crate::detection::analyze_error_body(b).detected_dbms)
            });
        match likely_dbms {
            None => {
                oob_note = Some(
                    "Out-of-band stage skipped: no DBMS engine was identified, so no \
                     engine-specific outbound primitive could be selected."
                        .to_string(),
                );
            }
            Some(dbms) => {
                let endpoint = url::Url::parse(&base.url)
                    .map(|u| u.path().to_string())
                    .unwrap_or_default();
                // One token per (target, endpoint, parameter, location); every
                // OOB vector for this point shares it, so any correlated
                // interaction attributes back here. The window covers the poll
                // wait plus slack for collector/DB clock skew.
                let window_secs = oob.wait_secs as i64 + 120;
                let token = OobToken::mint(
                    "bt",
                    base.url.clone(),
                    endpoint,
                    parameter.to_string(),
                    "query".to_string(),
                    window_secs,
                );
                let mut correlator = OobCorrelator::new();
                correlator.plant(token.clone());
                let callback_host = token.callback_host(&oob.callback_domain);

                // Compose engine-specific OOB vectors under the discovered
                // clause/quote context: {HOST}=token host, {Q}=version expr.
                let mut oob_ctx = ctx.clone();
                oob_ctx.dbms = Some(dbms);
                let candidates = compose_oob(&oob_ctx, &callback_host);

                // Send each through the OOB safety gate. OOB is authorize-gated
                // and opt-in, so the narrow Extended allowance applies here — it
                // permits the recognized outbound-lookup primitives (incl. MSSQL
                // xp_dirtree) while still refusing destructive/credential forms.
                for cand in &candidates {
                    if let SafetyVerdict::Permitted =
                        is_oob_confirmation(&cand.sql, SafetyLevel::Extended)
                    {
                        if execute(&client, base, Some(&cand.rendered), parameter)
                            .await
                            .is_ok()
                        {
                            oob_sent += 1;
                        }
                    }
                }

                if oob_sent > 0 {
                    // Give the DB time to perform the outbound lookup, then poll
                    // the collector (with its own plain client) and correlate.
                    tokio::time::sleep(Duration::from_secs(oob.wait_secs)).await;
                    let mut provider = oob.provider.lock().await;
                    match provider.poll().await {
                        Ok(interactions) => {
                            let (matched, _unmatched) =
                                correlator.correlate_batch_contains(&interactions);
                            oob_correlations = matched;
                        }
                        Err(e) => {
                            oob_note = Some(format!(
                                "Out-of-band poll failed after sending {oob_sent} vector(s): {e}"
                            ));
                        }
                    }
                } else {
                    oob_note = Some(
                        "Out-of-band stage: no permitted outbound primitive was available for \
                         the identified engine; nothing was sent."
                            .to_string(),
                    );
                }
            }
        }
    }
    let oob_confirmed = !oob_correlations.is_empty();

    // A value read back through the confirmed channel (not a mere note/schema
    // marker) is undeniable proof of access — the CONFIRMED upgrade.
    let value_recovered = extracted
        .iter()
        .any(|f| !matches!(f.channel.as_str(), "none" | "schema"));

    let confirmed =
        ledger.count(TestStatus::Confirmed) > 0 || value_recovered || oob_confirmed;
    let blocked = ledger.count(TestStatus::Blocked);
    // Both boolean arms ran verified against a stable baseline and neither
    // diverged: positive evidence the parameter is not SQL-interpreted, which
    // is a stronger statement than generic inconclusiveness.
    let not_sql_interpreted = baseline.stable
        && !has_positive
        && !confirmed
        && always_true_tested
        && always_false_tested
        && !boolean_diverged
        && blocked < experiments;
    // A broader honest negative: a battery of techniques ran (at least one
    // verified, non-flaky) against a stable baseline and none produced a
    // repeated differential, but the strict both-boolean-arms precondition for
    // NOT_SQL_INTERPRETED was not met. This is "tested clean on the channels
    // exercised" — distinct from INCONCLUSIVE (baseline instability / all
    // flaky) and from BASELINED (nothing tested).
    let tested_clean = baseline.stable
        && !has_positive
        && !confirmed
        && experiments > 0
        && repetitions_verified > 0
        && blocked < experiments;
    let coverage = if confirmed {
        CoverageState::Confirmed
    } else if has_positive {
        CoverageState::Interesting
    } else if blocked == experiments && experiments > 0 {
        CoverageState::Blocked
    } else if experiments == 0 {
        CoverageState::Baselined
    } else if not_sql_interpreted {
        CoverageState::NotSqlInterpreted
    } else if tested_clean {
        CoverageState::TestedClean
    } else {
        CoverageState::Inconclusive
    };

    // Confidence is driven by evidence, never by test count.
    let mut confidence = 0.0f32;
    if has_positive {
        confidence += 0.3;
    }
    if families.iter().any(|f| f.evidence_strength > 0.5) {
        confidence += 0.2;
    }
    if !baseline.stable {
        confidence *= 0.5; // an unstable baseline undermines every conclusion
    }
    // A value read back over the confirmed channel is the strongest evidence
    // available — it moots the heuristics above.
    if value_recovered {
        confidence = confidence.max(0.98);
    }
    // An out-of-band correlation is likewise dispositive: a token we planted came
    // back through the collector inside its window, so the DB itself performed the
    // outbound lookup we induced. It confirms even a fully blind injection.
    if oob_confirmed {
        confidence = confidence.max(0.98);
    }
    confidence = confidence.clamp(0.0, 1.0);

    // ── Stage 6: diagnostics + honesty.
    let mut diagnostic_report = negative_result_report(&baseline, &all_signals, experiments);
    if not_sql_interpreted {
        diagnostic_report.push(
            "Both the AlwaysTrue and AlwaysFalse boolean arms executed against a stable \
             baseline and produced no divergent response. This is positive evidence that the \
             parameter is not evaluated in a SQL boolean context (NOT_SQL_INTERPRETED) — a \
             moderate-confidence negative finding. It is not proof of safety against every \
             technique (error-, time-, or out-of-band-based vectors are not excluded)."
                .to_string(),
        );
    } else if tested_clean {
        diagnostic_report.push(format!(
            "{experiments} experiment(s) executed against a stable baseline ({repetitions_verified} \
             verified across controlled repeats) and none produced a repeated differential. This is \
             an honest negative (TESTED_CLEAN) scoped to the channels exercised — it distinguishes a \
             parameter that was probed and stayed inert from one that was never tested. It is not a \
             both-arms boolean exclusion (NOT_SQL_INTERPRETED) and does not rule out techniques the \
             run did not reach."
        ));
    }
    if value_recovered {
        let n = extracted
            .iter()
            .filter(|f| !matches!(f.channel.as_str(), "none" | "schema"))
            .count();
        diagnostic_report.push(format!(
            "Read-only extraction recovered {n} value(s) through the confirmed channel \
             (CONFIRMED). This is proof of access, not theory: the injection reads real data \
             back out. All extraction was read-only SELECT, request-budget-capped, and only \
             expressions the engine's profile knows were attempted."
        ));
    }
    if oob_confirmed {
        let (dns, http): (Vec<_>, Vec<_>) = oob_correlations
            .iter()
            .partition(|c| matches!(c.interaction_type, InteractionType::Dns));
        diagnostic_report.push(format!(
            "Out-of-band interaction CONFIRMED the injection: {} correlated callback(s) \
             ({} DNS, {} HTTP) carrying a token this run planted arrived at the operator's \
             collector within its window, from {} vector(s) sent. This proves a fully blind \
             injection — the database itself performed the outbound lookup we induced. Only \
             planted, in-window tokens are counted; stray traffic is never treated as evidence.",
            oob_correlations.len(),
            dns.len(),
            http.len(),
            oob_sent,
        ));
    } else if let Some(note) = &oob_note {
        diagnostic_report.push(note.clone());
    }
    let uncertainty = remaining_uncertainty(
        context_set.is_decisive(),
        dbms_set.is_decisive(),
        false,
    );    let mut limitations = Vec::new();
    if !baseline.stable {
        limitations.push(format!(
            "Baseline instability: {}",
            baseline.instability_reason.as_deref().unwrap_or("unknown")
        ));
    }
    if all_signals.iter().any(|s| s.kind.is_environmental()) {
        limitations.push(
            "Environmental interference was observed; application behaviour could not be isolated"
                .into(),
        );
    }
    // Honest account of the out-of-band channel: only claim it was untried when
    // it genuinely was. When attempted, state what was sent and what came back.
    if !oob_attempted {
        limitations.push(
            "Detection is response-based; no out-of-band or second-order confirmation was \
             attempted"
                .into(),
        );
    } else if oob_confirmed {
        limitations.push(format!(
            "Out-of-band confirmation succeeded ({} correlated callback(s) from {} vector(s) \
             sent); second-order confirmation was not attempted",
            oob_correlations.len(),
            oob_sent,
        ));
    } else if oob_sent > 0 {
        limitations.push(format!(
            "Out-of-band confirmation was attempted ({oob_sent} vector(s) sent) but no planted \
             token was observed at the collector within its window — absence of a callback is \
             not proof of absence of injection (egress filtering, no outbound DNS/HTTP, or a \
             longer delay than the wait can all suppress it); second-order confirmation was not \
             attempted"
        ));
    } else {
        // Attempted but nothing left the tool (no engine identified, or no
        // permitted outbound primitive) — oob_note carries the specifics.
        limitations.push(
            oob_note.clone().unwrap_or_else(|| {
                "Out-of-band confirmation was requested but could not be exercised; \
                 second-order confirmation was not attempted"
                    .to_string()
            }),
        );
    }

    Ok(AdaptiveResult {
        target: base.url.clone(),
        endpoint: url::Url::parse(&base.url)
            .map(|u| u.path().to_string())
            .unwrap_or_default(),
        parameter: parameter.to_string(),
        input_location: "query".to_string(),
        baseline_summary: baseline.summary(),
        baseline_stable: baseline.stable,
        context_hypotheses: context_set
            .hypotheses
            .iter()
            .map(|h| (h.label.clone(), h.probability))
            .collect(),
        query_position_hypotheses: position_set
            .hypotheses
            .iter()
            .map(|h| (h.label.clone(), h.probability))
            .collect(),
        dbms_hypotheses: dbms_set
            .hypotheses
            .iter()
            .map(|h| (h.label.clone(), h.probability))
            .collect(),
        signals: all_signals
            .iter()
            .map(|s| (s.label().to_string(), s.strength))
            .collect(),
        tested_families: families,
        experiments_executed: experiments,
        duplicates_avoided: ledger.duplicates_avoided(),
        sweep: None,
        repetitions_verified,
        flaky_tests,
        coverage: coverage.label().to_string(),
        confidence,
        confirmed,
        extracted,
        diagnostic_report,
        remaining_uncertainty: uncertainty,
        limitations,
        oob_correlations,
        oob_attempted,
    })
}

#[cfg(test)]
mod oob_stage_tests {
    use super::*;
    use crate::oob::{InteractionType, OobInteraction, OobProvider, OobResult};
    use async_trait::async_trait;
    use bugtools_core::scope::{ScopeRule, ScopeRuleType};
    use std::sync::{Arc as StdArc, Mutex as StdMutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn technique_filter_selects_by_label_and_defaults_to_all() {
        use crate::types::ProbeType;
        // Empty filter → everything runs.
        assert!(technique_selected(ProbeType::UnionBased, &[]));
        // Case-insensitive prefix match in either direction.
        assert!(technique_selected(ProbeType::BooleanBlind, &["boolean".into()]));
        assert!(technique_selected(ProbeType::BooleanBlind, &["bool".into()]));
        assert!(technique_selected(ProbeType::UnionBased, &["UNION".into()]));
        // A filter that names other techniques excludes this one.
        assert!(!technique_selected(ProbeType::TimingProbe, &["boolean".into(), "union".into()]));
    }

    /// A fake collector that reports exactly what the target was induced to look
    /// up. The test HTTP target records every raw request it receives into a
    /// shared log; `poll` turns each into a DNS interaction. This faithfully
    /// models a real collector: the (simulated) DB performs the outbound lookup
    /// carrying our callback host, and the collector logs it. Because the OOB
    /// payload embeds the planted token in that host, the recorded request
    /// *contains* the token and correlates by containment — while every baseline
    /// / experiment request (which never carries the token) stays unmatched,
    /// exercising the "stray traffic is never evidence" guarantee too.
    struct EchoCollector {
        domain: String,
        observed: StdArc<StdMutex<Vec<String>>>,
    }

    #[async_trait]
    impl OobProvider for EchoCollector {
        async fn register(&mut self) -> OobResult<String> {
            Ok(self.domain.clone())
        }
        async fn poll(&mut self) -> OobResult<Vec<OobInteraction>> {
            let now = chrono::Utc::now().timestamp();
            let seen = self.observed.lock().unwrap().clone();
            Ok(seen
                .into_iter()
                .map(|line| OobInteraction {
                    token: line.to_ascii_lowercase(),
                    interaction_type: InteractionType::Dns,
                    observed_at: now,
                    source: "203.0.113.7".to_string(),
                })
                .collect())
        }
    }

    /// A collector that logs unrelated traffic only — never anything carrying a
    /// token this run planted. Used to prove an honest negative.
    struct SilentCollector {
        domain: String,
    }

    #[async_trait]
    impl OobProvider for SilentCollector {
        async fn register(&mut self) -> OobResult<String> {
            Ok(self.domain.clone())
        }
        async fn poll(&mut self) -> OobResult<Vec<OobInteraction>> {
            Ok(vec![OobInteraction {
                token: "someone-elses-scan.oast.test".to_string(),
                interaction_type: InteractionType::Dns,
                observed_at: chrono::Utc::now().timestamp(),
                source: "9.9.9.9".to_string(),
            }])
        }
    }

    /// Spawn a target that answers 200 to every request and records each raw
    /// request head into `log`. Returns the base URL. Runs until dropped.
    async fn serve_recording(log: StdArc<StdMutex<Vec<String>>>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let log = log.clone();
                tokio::spawn(async move {
                    let mut received = Vec::new();
                    let mut buffer = [0u8; 2048];
                    while !received.windows(4).any(|w| w == b"\r\n\r\n") {
                        match socket.read(&mut buffer).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => received.extend_from_slice(&buffer[..n]),
                        }
                    }
                    if let Ok(head) = String::from_utf8(received) {
                        log.lock().unwrap().push(head);
                    }
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        format!("http://{addr}/?id=1")
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

    fn oob_config(provider: Arc<Mutex<dyn OobProvider>>, domain: &str) -> AdaptiveConfig {
        AdaptiveConfig {
            baseline_samples: 1,
            max_experiments: 2,
            delay_seconds: 0,
            dbms_hint: Some(DbmsFamily::MySQL),
            application_hint: None,
            extract: false,
            dump: None,
            techniques: Vec::new(),
            oob: Some(OobRun {
                callback_domain: domain.to_string(),
                provider,
                wait_secs: 0,
            }),
        }
    }

    #[tokio::test]
    async fn oob_correlation_confirms_blind_injection() {
        let log = StdArc::new(StdMutex::new(Vec::new()));
        let url = serve_recording(log.clone()).await;

        let domain = "oast.test";
        let provider: Arc<Mutex<dyn OobProvider>> = Arc::new(Mutex::new(EchoCollector {
            domain: domain.to_string(),
            observed: log.clone(),
        }));

        let result = run_adaptive(
            &request(url),
            "id",
            "1",
            scope_for_localhost(),
            oob_config(provider, domain),
        )
        .await
        .unwrap();

        assert!(result.oob_attempted, "OOB stage should have run");
        assert!(
            !result.oob_correlations.is_empty(),
            "the planted token echoed back should correlate"
        );
        assert!(
            result.confirmed,
            "an in-window planted-token callback is proof of a blind injection"
        );
        assert!(result.confidence >= 0.98);
        // The stale hard-coded limitation must be gone; the honest account stays.
        assert!(
            !result
                .limitations
                .iter()
                .any(|l| l.contains("no out-of-band or second-order confirmation was attempted")),
            "the 'no OOB attempted' limitation must flip once OOB ran"
        );
        assert!(result
            .diagnostic_report
            .iter()
            .any(|d| d.contains("Out-of-band interaction CONFIRMED")));
    }

    #[tokio::test]
    async fn oob_without_callback_is_honest_negative() {
        let log = StdArc::new(StdMutex::new(Vec::new()));
        let url = serve_recording(log).await;

        let domain = "oast.test";
        let provider: Arc<Mutex<dyn OobProvider>> = Arc::new(Mutex::new(SilentCollector {
            domain: domain.to_string(),
        }));

        let result = run_adaptive(
            &request(url),
            "id",
            "1",
            scope_for_localhost(),
            oob_config(provider, domain),
        )
        .await
        .unwrap();

        assert!(result.oob_attempted);
        assert!(
            result.oob_correlations.is_empty(),
            "unrelated traffic must never correlate as evidence"
        );
        // Attempted-but-negative: neither the stale blanket limitation nor a
        // false confirmation; the limitation states OOB ran without a callback.
        assert!(result
            .limitations
            .iter()
            .any(|l| l.contains("no planted token was observed")));
    }
}
