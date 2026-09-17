//! BugTools XSS research engine.
//!
//! Technology-aware, context-driven, evidence-first. The pipeline is:
//!
//! ```text
//! Fingerprint technology  →  derive strategy  →  classify context
//!                        →  assess exploitability stage  →  evidence
//! ```
//!
//! Core rules enforced in code (see the brief):
//! - Technology and version claims require corroborating evidence. A version
//!   is only reported when the exact string was observed.
//! - `reflection ≠ HTML injection ≠ execution`. Only confirmed execution is
//!   a finding.
//! - An edge/WAF block is never an XSS result.

pub mod assessment;
pub mod confidence;
pub mod exploitability;
pub mod finding;
pub mod parser;
pub mod engine;
pub mod reflection;
pub mod sanitize;
pub mod sink;
pub mod source;
pub mod taint;
pub mod strategy;
pub mod technology;
pub mod verification;

pub use exploitability::{
    ExploitabilityMachine, ExploitabilityStage, ObservationKind, StageError, StageTransition,
    XssObservation,
};
pub use assessment::{AssessmentBuilder, AssessmentError, AssessmentReflection, XssAssessment};
pub use engine::{analyze, AnalyzeRequest};
pub use reflection::{correlate, detect_reflections, DetectionConfig, ReflectionPoint};
pub use sink::{detect_sinks, SinkRisk, SinkTarget};
pub use source::{detect_sources, SourceKind};
pub use taint::{build_graph, TaintFlow, TaintGraph};
pub use confidence::{calibrate, confirm_on_execution, ConfidenceAssessment, ConfidenceLevel, EvidenceScore};
pub use parser::{
    lex_at, parse_at, parse_script, ContextMethod, HtmlNodeType, HtmlParseContext,
    JavaScriptNodeType, JavaScriptParseContext, ScopeGraph, SourceRange, SyntaxKind, SyntaxTree,
    Token, TokenKind,
};
pub use strategy::{build_strategy, RenderingModel, StrategyItem, XssStrategy};
pub use technology::{
    detect, observations_from_response, TechnologyEvidence, TechnologyFinding, TechCategory,
};
pub use verification::{
    BrowserVerifier, BrowserEnvironment, ExecutionEvidence, ExecutionEvidenceKind, ExecutionMarker,
    MitigationPolicy, NoVerifier, VerificationRequest, VerificationResult, VerificationSafety,
};

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::technology::Observation;

    #[test]
    fn full_phase_one_pipeline() {
        // 1. Fingerprint from real response signals.
        let headers = vec![
            ("Server".to_string(), "nginx/1.25.3".to_string()),
            ("X-Powered-By".to_string(), "Next.js".to_string()),
        ];
        let body = r#"<div id="__next"></div><script src="/_next/static/chunk.js"></script><script>window.__NEXT_DATA__ = {"props":{}}</script>"#;

        let obs = observations_from_response(&headers, body, &[]);
        let findings = detect(&obs);

        assert!(findings.iter().any(|f| f.technology == "nginx"));
        assert!(findings.iter().any(|f| f.technology == "Next.js"));

        // nginx version was observed explicitly.
        let nginx = findings.iter().find(|f| f.technology == "nginx").unwrap();
        assert_eq!(nginx.version.as_deref(), Some("1.25.3"));

        // Next.js version was NOT observed, so none is claimed.
        let next = findings.iter().find(|f| f.technology == "Next.js").unwrap();
        assert_eq!(next.version, None);

        // 2. Derive the strategy from those findings.
        let strategy = build_strategy(&findings);
        assert!(!strategy.is_generic());
        assert!(strategy
            .items
            .iter()
            .any(|i| i.focus.contains("hydration") || i.focus.contains("__NEXT_DATA__")));

        // 3. Classify a reflection context with the real parser.
        let response = r#"<a href="/x?q=PAYLOAD">link</a>"#;
        let offset = response.find("PAYLOAD").unwrap();
        let ctx = parse_at(response, offset, "PAYLOAD");
        assert_eq!(ctx.node_type, HtmlNodeType::QuotedAttribute);
        assert_eq!(ctx.attribute_name.as_deref(), Some("href"));
        assert_eq!(ctx.method, ContextMethod::Parsed);

        // 4. A reflection is NOT a finding.
        assert!(!ExploitabilityStage::Reflected.is_finding());
    }

    #[test]
    fn clean_target_reports_unknown_technology_and_generic_strategy() {
        let obs = vec![
            Observation::header("content-type", "text/html; charset=utf-8"),
            Observation::body("<html><body><h1>Hello</h1></body></html>"),
        ];
        let findings = detect(&obs);
        let strategy = build_strategy(&findings);
        assert!(strategy.is_generic(), "clean target must not invent a stack");
        assert_eq!(strategy.rendering_model, RenderingModel::Unknown);
    }

    #[test]
    fn different_stacks_yield_different_strategies() {
        let react = detect(&[Observation::body("<div data-reactroot=\"\"></div>")]);
        let twig = detect(&[Observation::body("<div class='twig-node'></div>")]);
        let react_strategy = build_strategy(&react);
        let twig_strategy = build_strategy(&twig);
        // React is detected (body marker weight 0.6 meets threshold);
        // the two strategies must not be textually identical.
        assert_ne!(
            react_strategy.items.len(),
            twig_strategy.items.len(),
            "React and an unknown/twig stack produced identical strategy sizes"
        );
    }
}
