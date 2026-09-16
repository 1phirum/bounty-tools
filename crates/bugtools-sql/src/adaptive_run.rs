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
use crate::adaptive::signals::{extract_signals, ResponseView, Signal, SignalKind};
use crate::detection::DbmsFamily;
use crate::payload::{compose_for, ClauseStrategy, ComposeContext, EscalationTier, QuoteMode, RepresentationContext};
use crate::types::ProbeType;
use bugtools_core::http::HttpRequest;
use bugtools_scope::ScopeEngine;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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

    pub coverage: String,
    pub confidence: f32,
    pub confirmed: bool,

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
}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        Self {
            baseline_samples: 3,
            max_experiments: 8,
            delay_seconds: 5,
            dbms_hint: None,
            application_hint: None,
        }
    }
}

/// Execute a request and build a `ResponseView`.
async fn execute(
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

    // ── Stage 2: a bounded set of distinct experiments.
    let ctx = ComposeContext {
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

    let techniques = [
        ProbeType::ErrorInjection,
        ProbeType::BooleanBlind,
    ];

    let mut experiments = 0usize;
    let mut syntax_error_seen = false;
    let mut boolean_diverged = false;
    let mut observed_error_body: Option<String> = None;

    'outer: for technique in techniques {
        let candidates = compose_for(technique, &ctx, EscalationTier::Recon, config.delay_seconds);
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

            let view = match execute(&client, base, Some(&candidate.rendered), parameter).await {
                Ok(v) => v,
                Err(e) => {
                    ledger.record_outcome(&fingerprint, TestStatus::Inconclusive, e);
                    continue;
                }
            };
            experiments += 1;

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
                // The pair diverging is captured by comparing in the caller;
                // here a body-similarity change on a boolean test is the hint.
                if signals
                    .iter()
                    .any(|s| s.kind == SignalKind::BodySimilarityChanged && s.strength > 0.2)
                {
                    boolean_diverged = true;
                }
            }

            let status = if signals.iter().any(|s| s.kind.is_environmental()) {
                TestStatus::Blocked
            } else if signals
                .iter()
                .any(|s| s.kind.supports_sql_hypothesis() && s.strength > 0.3)
            {
                TestStatus::Interesting
            } else {
                TestStatus::ApplicationResponse
            };
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
    let confirmed = ledger.count(TestStatus::Confirmed) > 0;
    let coverage = if confirmed {
        CoverageState::Confirmed
    } else if has_positive {
        CoverageState::Interesting
    } else if ledger.count(TestStatus::Blocked) == experiments && experiments > 0 {
        CoverageState::Blocked
    } else if experiments == 0 {
        CoverageState::Baselined
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
    confidence = confidence.clamp(0.0, 1.0);

    // ── Stage 6: diagnostics + honesty.
    let diagnostic_report = negative_result_report(&baseline, &all_signals, experiments);
    let uncertainty = remaining_uncertainty(
        context_set.is_decisive(),
        dbms_set.is_decisive(),
        false,
    );
    let mut limitations = Vec::new();
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
    limitations.push(
        "Detection is response-based; no out-of-band or second-order confirmation was attempted"
            .into(),
    );

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
        coverage: coverage.label().to_string(),
        confidence,
        confirmed,
        diagnostic_report,
        remaining_uncertainty: uncertainty,
        limitations,
    })
}
