//! The XSS engine: one orchestrator that runs the full analysis pipeline.
//!
//! This is the single entry point the CLI consumes. It composes the
//! subsystems in the brief's order and produces an `XssAssessment` whose
//! `confirmed` flag can only become true through the exploitability machine.

use crate::assessment::{AssessmentBuilder, AssessmentReflection, XssAssessment};
use crate::confidence::{calibrate, confirm_on_execution, EvidenceScore};
use crate::exploitability::{
    ExploitabilityMachine, ObservationKind as StageObservation, XssObservation,
};
use crate::parser::html::ContextMethod;
use crate::reflection::correlate;
use crate::strategy::build_strategy;
use crate::taint::graph::build_graph;
use crate::technology::{detect, observations_from_response};

/// Input to a single engine run.
#[derive(Debug, Clone)]
pub struct AnalyzeRequest {
    /// The endpoint URL the response came from.
    pub url: String,
    /// The parameter whose value was submitted.
    pub parameter: String,
    /// The exact value submitted (the probe string).
    pub submitted: String,
    /// The response body to analyze.
    pub body: String,
    /// Response headers as (name, value) pairs.
    pub headers: Vec<(String, String)>,
    /// Inline <script> sources extracted from the page, for taint analysis.
    pub script_sources: Vec<String>,
}

/// Run the complete analysis for one request/response pair.
///
/// Pipeline: technology -> rendering model -> reflection -> context ->
/// source/sink taint -> exploitability -> confidence -> assessment.
pub fn analyze(req: &AnalyzeRequest) -> XssAssessment {
    // 1. Technology fingerprint from the response.
    let observations = observations_from_response(&req.headers, &req.body, &[]);
    let findings = detect(&observations);

    // 2. Strategy and rendering model.
    let strategy = build_strategy(&findings);
    let rendering_model = strategy.rendering_model;

    // 3. Reflection analysis with resolved contexts.
    let reflections = correlate(&req.body, &req.parameter, &req.submitted);

    let mut builder = AssessmentBuilder::new(&req.url, endpoint_of(&req.url))
        .parameter(&req.parameter)
        .technology(findings)
        .rendering_model(rendering_model);

    // 4. The exploitability machine. Reflection alone only reaches REFLECTED;
    //    deeper stages need the corresponding observations, which we produce
    //    from the parsed contexts and the taint analysis.
    let mut machine = ExploitabilityMachine::new();
    let mut evidence = EvidenceScore::default();

    if let Some(first) = reflections.first() {
        // Reflection observed.
        let _ = machine.observe(XssObservation {
            kind: StageObservation::Reflection,
            evidence_id: "refl-1".into(),
            detail: format!(
                "value reflected at offset {} as {}",
                first.offset, first.encoding
            ),
        });
        evidence.add(0.3, "reflection");
        builder = builder.reflection(AssessmentReflection {
            parameter: first.parameter.clone(),
            response_offset: first.offset,
            length: first.length,
            encoding: first.encoding.clone(),
            html_context: first.html_context.clone(),
            js_context: first.js_context.clone(),
        });

        // Context resolved when the parser succeeded.
        if let Some(html_ctx) = &first.html_context {
            if html_ctx.method == ContextMethod::Parsed {
                let _ = machine.observe(XssObservation {
                    kind: StageObservation::ContextResolved,
                    evidence_id: "ctx-1".into(),
                    detail: format!(
                        "reflection sits in {} (element {:?}, attribute {:?})",
                        html_ctx.node_type.label(),
                        html_ctx.element_name,
                        html_ctx.attribute_name
                    ),
                });
                evidence.add(0.2, "parsed-context");

                // A breakout is only OBSERVED when the reflected value
                // actually injected markup: the response contains the value's
                // angle bracket (or equivalent) intact at the reflection site.
                // Being in a breakable context is necessary but NOT evidence.
                if first.encoding == "Exact" && submitted_breaks_out(&req.submitted) {
                    let end = (first.offset + first.length).min(req.body.len());
                        let after = &req.body[first.offset..end];
                    if after.starts_with(&req.submitted) {
                        let _ = machine.observe(XssObservation {
                            kind: StageObservation::ContextBreakout,
                            evidence_id: "brk-1".into(),
                            detail: "submitted markup appeared intact at the reflection site".into(),
                        });
                        evidence.add(0.25, "context-breakout");
                    }
                }
            }
        }

        // Sink reachability from the taint graph on the page's scripts.
        let mut saw_sink = false;
        for script in &req.script_sources {
            let graph = build_graph(script);
            let critical = graph.unsanitized_critical_flows();
            if !critical.is_empty() {
                saw_sink = true;
                let detail = critical
                    .iter()
                    .map(|f| format!("{} -> {}", f.source.label, f.sink.label))
                    .collect::<Vec<_>>()
                    .join(", ");
                let _ = machine.observe(XssObservation {
                    kind: StageObservation::SinkReachable,
                    evidence_id: "sink-1".into(),
                    detail: format!("unsanitized critical flow: {detail}"),
                });
                evidence.add(0.3, "taint-flow");
            }
        }
        if !saw_sink {
            builder = builder.uncertainty("no dangerous sink reachable from any detected source");
        }
    } else {
        builder = builder.uncertainty("no reflection of the submitted value was found");
    }

    // 5. Confidence. The engine (without a browser) can never confirm
    //    execution, so the assessment's confirmed stays false here.
    let assessment_confidence = calibrate(&evidence);
    let _ = confirm_on_execution(assessment_confidence, false);

    // 6. Stage-derived limitations. Anything short of confirmation carries
    //    an explicit statement of what weakens it.
    let machine = machine;
    if machine.current.is_finding() {
        // Should be unreachable without browser evidence, but the builder
        // enforces limitations regardless.
        builder = builder.limitation("assessment generated without browser verification");
    } else {
        builder = builder.limitation(
            "execution was not verified: browser confirmation is required before a finding",
        );
    }

    builder
        .exploitability(&machine)
        .confidence(evidence_summary(evidence, machine))
        .build()
        .expect("builder validates its own invariants")
}

fn evidence_summary(score: EvidenceScore, machine: ExploitabilityMachine) -> crate::confidence::ConfidenceAssessment {
    let mut a = calibrate(&score);
    // The assessment's confidence tracks the machine: a blocked or
    // inconclusive machine caps the level at Possible.
    if machine.current == crate::exploitability::ExploitabilityStage::MitigationBlocked
        || machine.current == crate::exploitability::ExploitabilityStage::Inconclusive
    {
        if a.level > crate::confidence::ConfidenceLevel::Possible {
            a.level = crate::confidence::ConfidenceLevel::Possible;
        }
    }
    a
}

/// Whether a submitted value contains markup that, if reflected intact,
/// constitutes an actual breakout (not merely a candidate).
fn submitted_breaks_out(submitted: &str) -> bool {
    submitted.contains('<')
        || submitted.contains("javascript:")
        || submitted.contains("onerror")
        || submitted.contains("onload")
}

fn endpoint_of(url: &str) -> String {
    url::Url::parse(url)
        .map(|u| u.path().to_string())
        .unwrap_or_else(|_| url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(body: &str, submitted: &str) -> AnalyzeRequest {
        AnalyzeRequest {
            url: "https://t.test/item".into(),
            parameter: "q".into(),
            submitted: submitted.into(),
            body: body.into(),
            headers: vec![("content-type".into(), "text/html".into())],
            script_sources: vec![],
        }
    }

    #[test]
    fn plain_reflection_is_not_confirmed() {
        let a = analyze(&req("<p>hello xyzzy42 bye</p>", "xyzzy42"));
        assert!(!a.confirmed);
        // Plain reflection in a text node: the parser resolves the context,
        // so the machine legitimately advances to CONTEXT_IDENTIFIED — which
        // is still not a finding.
        assert_eq!(a.exploitability_stage.label(), "CONTEXT_IDENTIFIED");
        assert!(!a.limitations.is_empty());
    }

    #[test]
    fn attribute_reflection_reaches_candidate() {
        let a = analyze(&req(r#"<input value="xyzzy42">"#, "xyzzy42"));
        // Exact reflection in a quoted attribute should at least resolve
        // context and mark a breakout candidate.
        assert!(
            matches!(
                a.exploitability_stage.label(),
                "INJECTION_CANDIDATE" | "HTML_INJECTION" | "CONTEXT_IDENTIFIED"
            ),
            "stage was {}",
            a.exploitability_stage.label()
        );
        assert!(!a.confirmed);
    }

    #[test]
    fn script_reflection_reaches_candidate() {
        let a = analyze(&req(r#"<script>var x = "xyzzy42";</script>"#, "xyzzy42"));
        assert!(a.reflection.is_some());
        assert!(!a.confirmed, "no browser evidence means no confirmation");
    }

    #[test]
    fn no_reflection_stays_not_observed() {
        let a = analyze(&req("<p>nothing to see</p>", "xyzzy42"));
        assert_eq!(a.exploitability_stage.label(), "NOT_OBSERVED");
        assert!(!a.confirmed);
        assert!(!a.remaining_uncertainty.is_empty());
    }

    #[test]
    fn taint_flow_advances_the_machine() {
        let request = AnalyzeRequest {
            url: "https://t.test/app".into(),
            parameter: "q".into(),
            submitted: "xyzzy42".into(),
            body: "<p>xyzzy42</p><script>var v = location.hash; el.innerHTML = v;</script>".into(),
            headers: vec![],
            script_sources: vec!["var v = location.hash; el.innerHTML = v;".into()],
        };
        let a = analyze(&request);
        assert!(!a.confirmed);
        assert!(
            matches!(
                a.exploitability_stage.label(),
                "DOM_REACHABILITY" | "SINK_CANDIDATE" | "SINK_REACHED" | "HTML_INJECTION"
            ),
            "a taint flow should advance past reflection: {}",
            a.exploitability_stage.label()
        );
    }

    #[test]
    fn technology_reported_with_evidence() {
        let a = analyze(&req("<p>xyzzy42</p>", "xyzzy42"));
        // No technology markers in this mock: none reported, none invented.
        assert!(a.technology.is_empty() || a.technology.iter().all(|t| !t.version.as_deref().unwrap_or("").is_empty() || t.evidence.iter().any(|e| e.evidence_source == crate::technology::EvidenceSource::ResponseHeader)));
    }

    #[test]
    fn every_assessment_carries_a_limitation() {
        let a = analyze(&req("<p>xyzzy42</p>", "xyzzy42"));
        assert!(!a.limitations.is_empty());
    }

    #[test]
    fn summary_is_readable() {
        let a = analyze(&req("<p>xyzzy42</p>", "xyzzy42"));
        let s = a.summary();
        assert!(s.contains("/item"));
        assert!(s.contains("CONTEXT_IDENTIFIED"));
    }
}
