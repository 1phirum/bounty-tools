//! Taint analysis: connect a detected source to a detected sink through the
//! code between them, recording the transformation chain.
//!
//! [`graph`] holds the public result types; [`dataflow`] implements the
//! AST-based analysis.

pub mod dataflow;
pub mod graph;

pub use dataflow::build as build_graph;
pub use graph::{TaintEdge, TaintFlow, TaintGraph, TaintNode, TaintNodeKind};
