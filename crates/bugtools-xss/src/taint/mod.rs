//! Taint analysis: connect a detected source to a detected sink through the
//! code between them, recording the transformation chain.

pub mod graph;

pub use graph::{build_graph, TaintEdge, TaintFlow, TaintGraph, TaintNode, TaintNodeKind};
