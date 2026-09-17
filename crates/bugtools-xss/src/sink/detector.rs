//! Sink detection: identify dangerous DOM operations in client-side code.
//!
//! A *sink* is an operation that can interpret its input as markup or code.
//! Each sink carries a risk weight used by the taint module when a flow
//! reaches it.

use crate::parser::js::{NodeId, SyntaxKind, SyntaxTree};
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

// ----------------------------------------------------------------------
// Syntax-tree detection
// ----------------------------------------------------------------------

/// The static property of a member node (`obj.prop`): the object node and the
/// property name. A computed key (`o[k]`) resolves to nothing.
fn member_prop(tree: &SyntaxTree, id: NodeId) -> Option<(NodeId, String)> {
    if tree.node(id).kind != SyntaxKind::Member {
        return None;
    }
    let children = tree.node(id).children.clone();
    let obj = *children.first()?;
    let prop = children.get(1)?;
    (tree.node(*prop).kind == SyntaxKind::Ident).then_some((obj, tree.node_text(*prop).to_string()))
}

/// The final segment of a callee name: the identifier itself, or the property
/// of a member callee (`document.write` -> `write`).
fn last_segment(tree: &SyntaxTree, id: NodeId) -> String {
    match tree.node(id).kind {
        SyntaxKind::Ident => tree.node_text(id).to_string(),
        SyntaxKind::Member => member_prop(tree, id).map(|(_, p)| p).unwrap_or_default(),
        _ => String::new(),
    }
}

/// A sink found in the tree, anchored to the node that performs it.
type TreeSink = (NodeId, SinkCall);

/// Detect sinks by walking the syntax tree.
///
/// A sink is an *assignment target* or a *call callee* (or a `new` constructor)
/// whose API is a sink, so a mention inside a comment or a string literal is
/// not a sink, and reading `el.innerHTML` is not one either. Each sink carries
/// the id of the node that performs the operation, which is exactly what the
/// taint analysis looks up, so a flow is recorded against the real construct.
///
/// Framework template directives (`v-html`, `bypassSecurityTrust`) live in
/// template text, not in JavaScript, so they are not sinks of a script; the
/// text-scanning [`detect_sinks`] still reports them for other consumers, and
/// the framework analyzers will model them properly.
pub fn detect_sinks_in_tree(tree: &SyntaxTree) -> Vec<TreeSink> {
    let mut out = Vec::new();
    for id in tree.all_nodes() {
        let node = tree.node(id);
        match node.kind {
            // `el.innerHTML = v`, `el.src = v`, `el.innerHTML += v`.
            SyntaxKind::Assign => {
                if let Some(&lhs) = node.children.first() {
                    if let Some((target, api)) = assignment_sink(tree, lhs) {
                        out.push((lhs, sink_call(tree, lhs, target, api)));
                    }
                }
            }
            // `eval(v)`, `document.write(v)`, `el.insertAdjacentHTML(p, v)`.
            SyntaxKind::Call => {
                if let Some(&callee) = node.children.first() {
                    if let Some((target, api)) = call_sink(tree, callee) {
                        out.push((callee, sink_call(tree, callee, target, api)));
                    }
                }
            }
            // `new Function(v)`.
            SyntaxKind::New => {
                if let Some(&ctor) = node.children.first() {
                    if last_segment(tree, ctor) == "Function" {
                        out.push((id, sink_call(tree, id, SinkTarget::ScriptExecution,
                            format!("new {}", tree.node_text(ctor)))));
                    }
                }
            }
            _ => {}
        }
    }
    out.sort_by_key(|(_, s)| s.offset);
    out
}

/// An assignment to a sink property.
fn assignment_sink(tree: &SyntaxTree, lhs: NodeId) -> Option<(SinkTarget, String)> {
    match tree.node(lhs).kind {
        SyntaxKind::Member => {
            let (_, prop) = member_prop(tree, lhs)?;
            match prop.as_str() {
                "innerHTML" | "outerHTML" => Some((SinkTarget::HtmlInsertion, prop)),
                "srcdoc" => Some((SinkTarget::IframeContent, prop)),
                "src" | "href" => Some((SinkTarget::UrlAssignment, prop)),
                "dangerouslySetInnerHTML" => Some((SinkTarget::FrameworkRawHtml, prop)),
                _ => None,
            }
        }
        // A bare `dangerouslySetInnerHTML = ...` (compiled JSX attribute form).
        SyntaxKind::Ident if tree.node_text(lhs) == "dangerouslySetInnerHTML" => {
            Some((SinkTarget::FrameworkRawHtml, "dangerouslySetInnerHTML".into()))
        }
        _ => None,
    }
}

/// A call whose callee is a sink API.
fn call_sink(tree: &SyntaxTree, callee: NodeId) -> Option<(SinkTarget, String)> {
    match tree.node(callee).kind {
        SyntaxKind::Ident => match tree.node_text(callee) {
            "eval" | "setTimeout" | "setInterval" => {
                Some((SinkTarget::ScriptExecution, tree.node_text(callee).to_string()))
            }
            _ => None,
        },
        SyntaxKind::Member => {
            let (obj, prop) = member_prop(tree, callee)?;
            match prop.as_str() {
                "write" | "writeln" if tree.node_text(obj) == "document" => {
                    Some((SinkTarget::DocumentWrite, format!("document.{prop}")))
                }
                "insertAdjacentHTML" => Some((SinkTarget::HtmlInsertion, prop)),
                "setTimeout" | "setInterval" => Some((SinkTarget::ScriptExecution, prop)),
                // jQuery's `.html(v)`; the base object is not checked here,
                // so this matches `.html(` on any object, as the text scan did.
                "html" => Some((SinkTarget::JqueryHtml, prop)),
                _ => None,
            }
        }
        _ => None,
    }
}

fn sink_call(tree: &SyntaxTree, node: NodeId, target: SinkTarget, api: String) -> SinkCall {
    let offset = tree.node(node).range.start;
    SinkCall {
        target,
        offset,
        api,
        context_line: line_at(&tree.source, offset).to_string(),
        risk: target.risk(),
    }
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

    // ------------------------------------------------------------------
    // Syntax-tree detection
    // ------------------------------------------------------------------

    fn tree_sinks(src: &str) -> Vec<TreeSink> {
        detect_sinks_in_tree(&crate::parser::js::parse_script(src))
    }

    #[test]
    fn tree_finds_innerhtml_assignment() {
        let found = tree_sinks("el.innerHTML = userInput;");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1.target, SinkTarget::HtmlInsertion);
        assert_eq!(found[0].1.risk, SinkRisk::Critical);
        assert_eq!(found[0].1.api, "innerHTML");
    }

    #[test]
    fn tree_finds_compound_assignment() {
        // `+=` is an assignment too.
        let found = tree_sinks("el.innerHTML += chunk;");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1.target, SinkTarget::HtmlInsertion);
    }

    #[test]
    fn tree_ignores_a_property_read() {
        // Reading the property is not a sink; only assigning to it is.
        assert!(tree_sinks("var x = el.innerHTML;").is_empty());
        assert!(tree_sinks("if (el.innerHTML) { go(); }").is_empty());
    }

    #[test]
    fn tree_ignores_sink_names_in_strings_and_comments() {
        // A sink named inside a string literal or a comment is not performed.
        assert!(tree_sinks("var s = \"el.innerHTML = x\";").is_empty());
        assert!(tree_sinks("// el.innerHTML = x\nvar y = 1;").is_empty());
    }

    #[test]
    fn tree_finds_document_write_and_eval() {
        let found = tree_sinks("document.write(html); eval(expr);");
        assert!(found.iter().any(|(_, s)| s.target == SinkTarget::DocumentWrite));
        assert!(found.iter().any(|(_, s)| s.target == SinkTarget::ScriptExecution
            && s.api == "eval"));
    }

    #[test]
    fn tree_finds_new_function() {
        let found = tree_sinks("var g = new Function(body);");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1.target, SinkTarget::ScriptExecution);
        assert_eq!(found[0].1.api, "new Function");
    }

    #[test]
    fn tree_finds_src_and_href_assignments() {
        for src in ["frame.src = url;", "a.href = url;"] {
            let found = tree_sinks(src);
            assert_eq!(found.len(), 1, "{src}");
            assert_eq!(found[0].1.target, SinkTarget::UrlAssignment);
            assert_eq!(found[0].1.risk, SinkRisk::High);
        }
    }

    #[test]
    fn tree_finds_insert_adjacent_html_and_srcdoc() {
        let found = tree_sinks("el.insertAdjacentHTML('beforeend', h); f.srcdoc = h;");
        assert_eq!(found.len(), 2);
        assert!(found.iter().any(|(_, s)| s.target == SinkTarget::HtmlInsertion));
        assert!(found.iter().any(|(_, s)| s.target == SinkTarget::IframeContent));
    }

    #[test]
    fn tree_finds_window_prefixed_timer() {
        let found = tree_sinks("window.setTimeout(payload, 1);");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1.target, SinkTarget::ScriptExecution);
    }

    #[test]
    fn tree_ignores_unrelated_member_calls() {
        // `.write` on an object that is not `document` is not the DOM sink.
        assert!(tree_sinks("logger.write(msg);").is_empty());
        // A `.src` read, not an assignment.
        assert!(tree_sinks("var u = img.src;").is_empty());
    }
}
