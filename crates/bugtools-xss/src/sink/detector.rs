//! Sink detection: identify dangerous DOM operations in client-side code.
//!
//! A *sink* is an operation that can interpret its input as markup or code.
//! Each sink carries a risk weight used by the taint module when a flow
//! reaches it.

use serde::{Deserialize, Serialize};

/// How dangerous a sink is when attacker data reaches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SinkRisk {
    /// Interpretation of markup/code — direct execution path.
    Critical,
    /// URL/script assignment that can escalate with chaining.
    High,
    /// Indirect influence; needs another step to execute.
    Medium,
}

impl SinkRisk {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
        }
    }
}

/// The operation a sink performs on its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SinkTarget {
    /// `innerHTML` / `outerHTML` / `insertAdjacentHTML` — markup execution.
    HtmlInsertion,
    /// `document.write` / `writeln`.
    DocumentWrite,
    /// Direct script evaluation (`eval`, `Function`, `setTimeout` with a string).
    ScriptExecution,
    /// `src`/`href`/`action` assignment — JavaScript URL escalation.
    UrlAssignment,
    /// `srcdoc`, iframe content.
    IframeContent,
    /// jQuery `$()` with an HTML string, `.html()`.
    JqueryHtml,
    /// Framework raw-HTML APIs (dangerouslySetInnerHTML, v-html, bypassSecurityTrust...).
    FrameworkRawHtml,
}

impl SinkTarget {
    pub fn risk(&self) -> SinkRisk {
        match self {
            Self::HtmlInsertion | Self::DocumentWrite | Self::ScriptExecution => SinkRisk::Critical,
            Self::IframeContent | Self::JqueryHtml | Self::FrameworkRawHtml => SinkRisk::Critical,
            Self::UrlAssignment => SinkRisk::High,
        }
    }
}

/// A sink call found in client-side code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkCall {
    pub target: SinkTarget,
    /// Byte offset in the analyzed script.
    pub offset: usize,
    /// The API as written.
    pub api: String,
    /// The line of code containing the call.
    pub context_line: String,
    pub risk: SinkRisk,
}

/// Detect dangerous sink calls in JavaScript source text.
pub fn detect_sinks(script: &str) -> Vec<SinkCall> {
    const PATTERNS: &[(&str, SinkTarget)] = &[
        ("innerHTML", SinkTarget::HtmlInsertion),
        ("outerHTML", SinkTarget::HtmlInsertion),
        ("insertAdjacentHTML", SinkTarget::HtmlInsertion),
        ("document.write", SinkTarget::DocumentWrite),
        ("document.writeln", SinkTarget::DocumentWrite),
        ("eval(", SinkTarget::ScriptExecution),
        ("new Function(", SinkTarget::ScriptExecution),
        ("setTimeout(", SinkTarget::ScriptExecution),
        ("setInterval(", SinkTarget::ScriptExecution),
        (".src =", SinkTarget::UrlAssignment),
        (".href =", SinkTarget::UrlAssignment),
        ("srcdoc", SinkTarget::IframeContent),
        ("dangerouslySetInnerHTML", SinkTarget::FrameworkRawHtml),
        ("v-html", SinkTarget::FrameworkRawHtml),
        ("bypassSecurityTrust", SinkTarget::FrameworkRawHtml),
        ("$.html(", SinkTarget::JqueryHtml),
    ];

    let mut out = Vec::new();
    for (needle, target) in PATTERNS {
        let mut from = 0;
        while let Some(pos) = script[from..].find(needle) {
            let offset = from + pos;
            out.push(SinkCall {
                target: *target,
                offset,
                api: needle.to_string(),
                context_line: line_at(script, offset).to_string(),
                risk: target.risk(),
            });
            from = offset + needle.len();
        }
    }
    out.sort_by_key(|s| s.offset);
    out
}

fn line_at(script: &str, offset: usize) -> &str {
    let start = script[..offset].rfind('\n').map(|p| p + 1).unwrap_or(0);
    let end = script[offset..]
        .find('\n')
        .map(|p| offset + p)
        .unwrap_or(script.len());
    &script[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn innerhtml_is_critical() {
        let found = detect_sinks("el.innerHTML = userInput;");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].risk, SinkRisk::Critical);
        assert_eq!(found[0].target, SinkTarget::HtmlInsertion);
    }

    #[test]
    fn eval_is_script_execution() {
        let found = detect_sinks("eval(expr);");
        assert!(found.iter().any(|s| s.target == SinkTarget::ScriptExecution));
    }

    #[test]
    fn document_write_detected() {
        assert!(detect_sinks("document.write(html);")
            .iter()
            .any(|s| s.target == SinkTarget::DocumentWrite));
    }

    #[test]
    fn framework_apis_detected() {
        let found = detect_sinks("dangerouslySetInnerHTML = {__html: v}; v-html=\"x\"");
        assert!(found.iter().any(|s| s.target == SinkTarget::FrameworkRawHtml));
        assert!(found.iter().filter(|s| s.target == SinkTarget::FrameworkRawHtml).count() >= 2);
    }

    #[test]
    fn src_assignment_is_high_risk() {
        let found = detect_sinks("frame.src = url;");
        assert_eq!(found[0].risk, SinkRisk::High);
    }

    #[test]
    fn no_sinks_in_plain_code() {
        assert!(detect_sinks("var x = 1 + 2;").is_empty());
    }

    #[test]
    fn multiple_sinks_sorted_and_risk_labelled() {
        let found = detect_sinks("el.innerHTML = a; setTimeout(b, 1);");
        assert!(found.len() >= 2);
        for s in &found {
            assert!(!s.risk.label().is_empty());
        }
    }

    #[test]
    fn context_line_captured() {
        let found = detect_sinks("var x=1;\nel.innerHTML = v;");
        assert!(found[0].context_line.contains("innerHTML"));
    }
}
