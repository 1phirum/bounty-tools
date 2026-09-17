//! Public result types for taint analysis.
//!
//! The analysis itself lives in [`crate::taint::dataflow`]: it walks the
//! parsed syntax tree rather than scanning a byte window, so a flow is
//! recorded only when the code structure actually supports it.
//!
//! This module keeps the shapes the engine and CLI consume.

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

// The analysis that populates these types — source→sink data flow over the
// parsed syntax tree, including sanitizer and transform classification —
// lives in [`crate::taint::dataflow`]. The previous line/substring
// heuristic (`same_data_object`, an arbitrary 200-byte path window, and
// substring sanitizer matching) has been removed: see that module for the
// replacement and its tests.

#[cfg(test)]
mod tests {
    use crate::taint::build_graph;

    #[test]
    fn public_entry_point_is_wired() {
        // The re-export must reach the data-flow analysis.
        let g = build_graph("var v = location.hash; el.innerHTML = v;");
        assert_eq!(g.flow_count(), 1);
        assert_eq!(g.flows[0].sink.label, "innerHTML");
        assert_eq!(g.unsanitized_critical_flows().len(), 1);
    }

    #[test]
    fn graph_types_are_serialisable() {
        // The CLI/JSON consumers depend on these deriving serde.
        let g = build_graph("var v = location.hash; el.innerHTML = v;");
        let json = serde_json::to_string(&g).expect("taint graph must serialise");
        assert!(json.contains("location.hash"));
    }
}

