//! The source -> sink taint graph.
//!
//! Given detected source reads and sink calls in the same script, determine
//! which sources can plausibly flow to which sinks, and what happens between
//! them. The analysis is deliberately conservative: a flow is only recorded
//! when the code structure supports it (assignment or direct use between the
//! source read and the sink call), and transformations are inferred from the
//! operations observed on the path.

use crate::sink::detector::detect_sinks;
use crate::source::detector::{detect_sources, SourceRead};
use serde::{Deserialize, Serialize};

/// A node in the taint graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintNode {
    pub id: String,
    pub kind: TaintNodeKind,
    /// Human-readable description (the API or operation).
    pub label: String,
    /// Offset in the analyzed script, for locating in source.
    pub offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaintNodeKind {
    Source,
    Transform,
    Sink,
}

/// An edge from one node to another, optionally via a transformation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintEdge {
    pub from: String,
    pub to: String,
    pub transformation: Option<String>,
}

/// One complete source -> sink flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFlow {
    pub source: TaintNode,
    pub sink: TaintNode,
    /// Transformations applied between source and sink, in order.
    pub transforms: Vec<String>,
    /// Whether a sanitizer-like operation was observed on the path.
    pub sanitized: bool,
    /// The risk of the sink reached.
    pub sink_risk: String,
}

/// The complete graph for one script.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaintGraph {
    pub nodes: Vec<TaintNode>,
    pub edges: Vec<TaintEdge>,
    pub flows: Vec<TaintFlow>,
}

impl TaintGraph {
    /// Number of source -> sink flows found.
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// Flows that reach a critical-risk sink without sanitization.
    pub fn unsanitized_critical_flows(&self) -> Vec<&TaintFlow> {
        self.flows
            .iter()
            .filter(|f| f.sink_risk == "critical" && !f.sanitized)
            .collect()
    }
}

/// Known sanitizer operations: calls that make input safe for a sink.
const SANITIZERS: &[&str] = &[
    "textContent",
    "createTextNode",
    "encodeURIComponent",
    "DOMPurify.sanitize",
    "sanitize(",
    "escapeHtml",
    "sanitizeHtml",
    "innerText",
];

/// Known transformations: operations that change data without sanitizing.
const TRANSFORMS: &[(&str, &str)] = &[
    ("decodeURIComponent", "decodeURIComponent"),
    ("decodeURI", "decodeURI"),
    ("unescape(", "unescape"),
    ("JSON.parse", "JSON.parse"),
    ("JSON.stringify", "JSON.stringify"),
    (".split(", "split"),
    (".replace(", "replace"),
    (".slice(", "slice"),
    (".substr", "substring"),
    ("atob(", "base64 decode"),
    ("btoa(", "base64 encode"),
];

/// Build the taint graph for a script by combining source and sink detection.
pub fn build_graph(script: &str) -> TaintGraph {
    let sources = detect_sources(script);
    let sinks = detect_sinks(script);

    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut flows = Vec::new();

    for src in &sources {
        let src_node = TaintNode {
            id: format!("src-{}", src.offset),
            kind: TaintNodeKind::Source,
            label: src.kind.label().to_string(),
            offset: src.offset,
        };
        nodes.push(src_node.clone());

        for sink in &sinks {
            // A sink can only consume a source that was read before it.
            if sink.offset < src.offset {
                continue;
            }
            // The plausible window: from the source read to shortly after
            // the sink call. If the sink line references the variable that
            // received the source, or the source is used inline, record it.
            let path_end = (sink.offset + 200).min(script.len());
            let path = &script[src.offset..path_end];
            let direct_use = same_data_object(&src.context_line, &sink.context_line);
            let inline_use = sink.context_line.contains(&src.label_backing(path));

            if !direct_use && !inline_use {
                continue;
            }

            // Analyze the path for sanitizers and transforms.
            let sanitized = SANITIZERS.iter().any(|s| path.contains(s));
            let transforms: Vec<String> = TRANSFORMS
                .iter()
                .filter(|(needle, _)| path.contains(needle))
                .map(|(_, name)| name.to_string())
                .collect();

            let sink_node = TaintNode {
                id: format!("sink-{}", sink.offset),
                kind: TaintNodeKind::Sink,
                label: sink.api.clone(),
                offset: sink.offset,
            };
            if !nodes.contains(&sink_node) {
                nodes.push(sink_node.clone());
            }

            edges.push(TaintEdge {
                from: src_node.id.clone(),
                to: sink_node.id.clone(),
                transformation: transforms.first().cloned(),
            });

            flows.push(TaintFlow {
                source: src_node.clone(),
                sink: sink_node,
                transforms,
                sanitized,
                sink_risk: sink.risk.label().to_string(),
            });
        }
    }

    TaintGraph {
        nodes,
        edges,
        flows,
    }
}

impl SourceRead {
    /// A short label suitable for inline-use matching on the path text.
    fn label_backing(&self, _path: &str) -> String {
        // The API name itself (e.g. "location.hash") is what would appear
        // inline in the sink line.
        self.kind.label().to_string()
    }
}

/// Whether two lines appear to move the same data object (a source line
/// assigning to a name that the sink line uses).
fn same_data_object(source_line: &str, sink_line: &str) -> bool {
    // Extract the assignment target from the source line, if any.
    let target = source_line
        .split('=')
        .next()
        .map(|lhs| {
            lhs.trim()
                .rsplit(['.', ' ', '('])
                .next()
                .unwrap_or("")
                .trim()
                .to_string()
        })
        .unwrap_or_default();

    // Reject empty or non-identifier targets. Single-letter variable names
    // (var a = ...) are legitimate and common; length alone is not a signal.
    if target.is_empty() || !target.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$') {
        return false;
    }
    sink_line.contains(&target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_source_to_sink_flow() {
        let script = "var v = location.hash; el.innerHTML = v;";
        let g = build_graph(script);
        assert_eq!(g.flow_count(), 1);
        let f = &g.flows[0];
        assert_eq!(f.source.label, "location.hash");
        assert_eq!(f.sink.label, "innerHTML");
        assert_eq!(f.sink_risk, "critical");
    }

    #[test]
    fn sanitized_flow_is_marked() {
        let script = "var v = location.hash; el.textContent = v;";
        let g = build_graph(script);
        // textContent is a sanitizer AND a sink-less operation; the sink
        // detector should not fire, so no flow to a dangerous sink exists.
        assert_eq!(g.flow_count(), 0);
    }

    #[test]
    fn sanitizer_between_source_and_sink_detected() {
        let script =
            "var v = location.hash; var clean = DOMPurify.sanitize(v); el.innerHTML = clean;";
        let g = build_graph(script);
        let f = &g.flows[0];
        assert!(f.sanitized, "DOMPurify on the path must mark the flow sanitized");
    }

    #[test]
    fn transforms_recorded_on_path() {
        let script =
            "var v = location.hash; var d = decodeURIComponent(v); el.innerHTML = d;";
        let g = build_graph(script);
        let f = &g.flows[0];
        assert!(f.transforms.contains(&"decodeURIComponent".to_string()));
    }

    #[test]
    fn unrelated_source_and_sink_are_not_connected() {
        let script = "var v = location.hash;\nvar other = getData();\nel.innerHTML = other;";
        let g = build_graph(script);
        assert_eq!(g.flow_count(), 0, "a source the sink never uses must not flow");
    }

    #[test]
    fn unsanitized_critical_flows_query() {
        let script = "var v = location.hash; el.innerHTML = v;";
        let g = build_graph(script);
        assert_eq!(g.unsanitized_critical_flows().len(), 1);
    }

    #[test]
    fn no_sources_no_flows() {
        let g = build_graph("var x = 1; el.innerHTML = '<b>static</b>';");
        assert_eq!(g.flow_count(), 0);
    }

    #[test]
    fn multiple_flows_supported() {
        let script = "var a = location.hash;\nvar b = document.referrer;\nel.innerHTML = a;\nel2.innerHTML = b;";
        let g = build_graph(script);
        assert_eq!(g.flow_count(), 2);
    }
}
