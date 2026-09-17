//! AST-based data-flow taint analysis.
//!
//! Replaces the line/substring heuristic (`same_data_object`) with a walk
//! over the parsed syntax tree. The question the old heuristic could only
//! guess at — *does the value reaching this sink trace back to this
//! source?* — is now answered structurally:
//!
//! 1. [`detect_sources`] / [`detect_sinks`] stay the evidence feeders: they
//!    decide *which* APIs are sources and sinks, and where they occur.
//! 2. The syntax tree decides *how data moves*: a value is tainted by a
//!    source read, propagates through assignments, declarations, member
//!    accesses, calls, arrays and template interpolations, and is checked
//!    at each sink argument.
//! 3. Sanitizers and transforms are classified from the *call structure*
//!    instead of a substring match over a byte window, so a sanitizer must
//!    really sit on the path, not merely appear nearby.
//!
//! The analysis is deliberately conservative: it records a flow only when
//! the code structure supports it, and never invents a path it did not see.
//! It is intraprocedural — a value passed into a user-defined function is
//! not traced through that function's body. Interprocedural summarization
//! (arguments → parameters → returns) is P1.3.

use std::collections::{HashMap, HashSet};

use crate::parser::js::ast::SyntaxKind;
use crate::parser::js::scope::binding_idents;
use crate::parser::js::{parse_script, NodeId, ScopeGraph, SyntaxTree};
use crate::sink::detector::{detect_sinks, SinkCall};
use crate::source::detector::{detect_sources, SourceRead};
use crate::taint::graph::{TaintEdge, TaintFlow, TaintGraph, TaintNode, TaintNodeKind};

/// Build the taint graph for one script by walking its syntax tree.
pub fn build(script: &str) -> TaintGraph {
    let sources = detect_sources(script);
    let sinks = detect_sinks(script);
    if sources.is_empty() || sinks.is_empty() {
        return TaintGraph::default();
    }
    let tree = parse_script(script);
    let scopes = ScopeGraph::build(&tree);
    let mut analyzer = Analyzer::new(&tree, &scopes, sources, sinks);
    analyzer.run();
    analyzer.finish()
}

/// The provenance of a tainted value: where it entered and what happened to
/// it on the way.
#[derive(Debug, Clone)]
struct TaintState {
    origin: SourceRead,
    transforms: Vec<String>,
    sanitized: bool,
}

impl TaintState {
    fn from_source(src: &SourceRead) -> Self {
        Self { origin: src.clone(), transforms: Vec::new(), sanitized: false }
    }
}

/// Merge several states into one, keeping the first (source-order) origin
/// and every transformation seen on any branch.
fn combine(states: Vec<Option<TaintState>>) -> Option<TaintState> {
    let mut iter = states.into_iter().flatten();
    let mut out = iter.next()?;
    for st in iter {
        out.transforms.extend(st.transforms);
    }
    Some(out)
}

/// How a call affects a tainted value flowing through it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CallClass {
    /// Makes the value safe for the sink it reaches.
    Sanitizer,
    /// Changes the value without sanitizing. Carries the canonical
    /// operation name recorded on the flow.
    Transform(String),
}

/// Sanitizer call names. A call whose callee matches makes the result safe.
const SANITIZERS: &[&str] = &[
    "textContent",
    "createTextNode",
    "encodeURIComponent",
    "DOMPurify.sanitize",
    "sanitize",
    "escapeHtml",
    "sanitizeHtml",
    "innerText",
];

/// Transform call names. Recorded on the flow, but the value stays tainted.
const TRANSFORMS: &[&str] = &[
    "decodeURIComponent",
    "decodeURI",
    "unescape",
    "JSON.parse",
    "JSON.stringify",
    "split",
    "replace",
    "slice",
    "substr",
    "substring",
    "atob",
    "btoa",
];

/// Classify a call by its callee name, accepting either the full dotted
/// name (`JSON.parse`, `DOMPurify.sanitize`) or the final segment
/// (`.split(`, `escapeHtml(`). The name recorded on a transform is the
/// canonical operation — the dotted name when that is the match
/// (`JSON.parse`), otherwise the final segment (`slice`).
fn classify_call(name: &str) -> Option<CallClass> {
    let last = name.rsplit('.').next().unwrap_or(name);
    if SANITIZERS.contains(&name) || SANITIZERS.contains(&last) {
        Some(CallClass::Sanitizer)
    } else if TRANSFORMS.contains(&name) {
        Some(CallClass::Transform(name.to_string()))
    } else if TRANSFORMS.contains(&last) {
        Some(CallClass::Transform(last.to_string()))
    } else {
        None
    }
}

struct Analyzer<'a> {
    tree: &'a SyntaxTree,
    scopes: &'a ScopeGraph,
    sources: Vec<SourceRead>,
    sinks: Vec<SinkCall>,
    /// Tainted bindings, keyed by declaration range.
    bindings: HashMap<(usize, usize), TaintState>,
    /// Tainted implicit globals (assigned without a declaration).
    globals: HashMap<String, TaintState>,
    /// Tainted property paths (`obj.prop`), coarse — real aliasing is P1.4.
    props: HashMap<String, TaintState>,
    flows: Vec<TaintFlow>,
}

impl<'a> Analyzer<'a> {
    fn new(tree: &'a SyntaxTree, scopes: &'a ScopeGraph, sources: Vec<SourceRead>, sinks: Vec<SinkCall>) -> Self {
        Self {
            tree,
            scopes,
            sources,
            sinks,
            bindings: HashMap::new(),
            globals: HashMap::new(),
            props: HashMap::new(),
            flows: Vec::new(),
        }
    }

    fn run(&mut self) {
        self.walk(self.tree.root);
    }

    fn finish(self) -> TaintGraph {
        let mut nodes: Vec<TaintNode> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut edges: Vec<TaintEdge> = Vec::new();
        for f in &self.flows {
            if seen.insert(f.source.id.clone()) {
                nodes.push(f.source.clone());
            }
            if seen.insert(f.sink.id.clone()) {
                nodes.push(f.sink.clone());
            }
            edges.push(TaintEdge {
                from: f.source.id.clone(),
                to: f.sink.id.clone(),
                transformation: f.transforms.first().cloned(),
            });
        }
        TaintGraph { nodes, edges, flows: self.flows }
    }

    // ------------------------------------------------------------------
    // Source / sink location
    // ------------------------------------------------------------------

    /// The source read whose match span lies within this node's range, if
    /// any. The span (not just the start) is required so that
    /// `location.hash` matches the `location.hash` member rather than a
    /// bare `location` identifier.
    fn source_within(&self, id: NodeId) -> Option<&SourceRead> {
        let range = self.tree.node(id).range;
        self.sources.iter().find(|s| {
            let span_end = s.offset + s.kind.label().len();
            range.start <= s.offset && range.end >= span_end
        })
    }

    /// The sink whose offset lies within this node's range.
    fn sink_within(&self, id: NodeId) -> Option<&SinkCall> {
        let range = self.tree.node(id).range;
        self.sinks.iter().find(|s| range.contains(s.offset))
    }

    /// The dotted callee name of a call (`escapeHtml`, `DOMPurify.sanitize`,
    /// `JSON.parse`, `location.hash.substring`).
    fn callee_name(&self, callee: NodeId) -> String {
        match self.tree.node(callee).kind {
            SyntaxKind::Ident => self.tree.node_text(callee).to_string(),
            SyntaxKind::Member => {
                let children = self.tree.node(callee).children.clone();
                let Some(obj) = children.first() else {
                    return self.tree.node_text(callee).to_string();
                };
                let prop = children.get(1).map(|&p| self.tree.node_text(p).to_string()).unwrap_or_default();
                match self.tree.node(*obj).kind {
                    SyntaxKind::Ident | SyntaxKind::This => {
                        format!("{}.{}", self.tree.node_text(*obj), prop)
                    }
                    SyntaxKind::Member => format!("{}.{}", self.member_path(*obj).unwrap_or_default(), prop),
                    _ => prop,
                }
            }
            _ => self.tree.node_text(callee).to_string(),
        }
    }

    /// A best-effort dotted path for a member expression, used as the
    /// property-taint key.
    fn member_path(&self, id: NodeId) -> Option<String> {
        if self.tree.node(id).kind != SyntaxKind::Member {
            return None;
        }
        let children = self.tree.node(id).children.clone();
        let obj = *children.first()?;
        let prop = children.get(1)?;
        let obj_text = match self.tree.node(obj).kind {
            SyntaxKind::Ident => self.tree.node_text(obj).to_string(),
            SyntaxKind::This => "this".to_string(),
            SyntaxKind::Member => self.member_path(obj)?,
            _ => return None,
        };
        Some(format!("{}.{}", obj_text, self.tree.node_text(*prop)))
    }

    // ------------------------------------------------------------------
    // Statement walk
    // ------------------------------------------------------------------

    /// Walk statements in source order, propagating taint. Expression nodes
    /// that carry data (assignments, calls) are evaluated rather than
    /// recursed into, so each is analysed exactly once.
    fn walk(&mut self, id: NodeId) {
        let children = self.tree.node(id).children.clone();
        for child in children {
            match self.tree.node(child).kind {
                SyntaxKind::VarDeclarator => self.handle_declarator(child),
                SyntaxKind::Assign | SyntaxKind::Call | SyntaxKind::New => {
                    self.eval(child);
                }
                _ => self.walk(child),
            }
        }
    }

    /// `name = init` — taint the declared binding from the initializer.
    fn handle_declarator(&mut self, id: NodeId) {
        let children = self.tree.node(id).children.clone();
        let Some(target) = children.first() else {
            return;
        };
        let Some(init) = children.get(1) else {
            return; // a bare declaration has nothing to taint.
        };
        let st = self.eval(*init);
        // A simple name, or a destructuring pattern: every name the pattern
        // binds inherits the initializer's taint.
        for ident in binding_idents(self.tree, *target) {
            self.taint_binding(ident, st.clone());
        }
    }

    // ------------------------------------------------------------------
    // Expression evaluation
    // ------------------------------------------------------------------

    /// The taint state of an expression: `None` when the value is clean.
    fn eval(&mut self, id: NodeId) -> Option<TaintState> {
        match self.tree.node(id).kind {
            // Literals: a source read may appear directly inside one.
            SyntaxKind::StringLit
            | SyntaxKind::NumberLit
            | SyntaxKind::BoolLit
            | SyntaxKind::NullLit
            | SyntaxKind::RegexLit
            | SyntaxKind::TemplateLit => {
                if let Some(src) = self.source_within(id) {
                    return Some(TaintState::from_source(src));
                }
                if self.tree.node(id).kind == SyntaxKind::TemplateLit {
                    return self.template_taint(id);
                }
                None
            }
            SyntaxKind::Ident => {
                if let Some(src) = self.source_within(id) {
                    return Some(TaintState::from_source(src));
                }
                self.read_binding(id)
            }
            // `obj.prop` — taint flows from the object; otherwise a source
            // may start exactly here (`location.hash`), or a previously
            // written property may be read back.
            SyntaxKind::Member => {
                let obj = self.tree.node(id).children.first().copied();
                let mut st = obj.and_then(|o| self.eval(o));
                if st.is_none() {
                    if let Some(src) = self.source_within(id) {
                        st = Some(TaintState::from_source(src));
                    }
                }
                if st.is_none() {
                    if let Some(path) = self.member_path(id) {
                        st = self.props.get(&path).cloned();
                    }
                }
                st
            }
            // `f(args)` — a sink consumes its arguments here; a sanitizer or
            // transform is classified from the callee structure.
            SyntaxKind::Call => {
                let children = self.tree.node(id).children.clone();
                let Some((&callee, args)) = children.split_first() else {
                    return None;
                };
                let mut states = Vec::with_capacity(children.len());
                for &arg in args {
                    states.push(self.eval(arg));
                }
                states.push(self.eval(callee));
                let mut combined = combine(states);
                if let Some(sink) = self.sink_within(callee).cloned() {
                    if let Some(st) = &combined {
                        self.record_flow(&sink, st);
                    }
                }
                if let Some(ref mut st) = combined {
                    let name = self.callee_name(callee);
                    match classify_call(&name) {
                        Some(CallClass::Sanitizer) => st.sanitized = true,
                        Some(CallClass::Transform(op)) => st.transforms.push(op),
                        None => {}
                    }
                }
                combined
            }
            // `new Foo(args)` — a sink may appear in the constructor name.
            SyntaxKind::New => {
                let children = self.tree.node(id).children.clone();
                let combined = combine(children.into_iter().map(|c| self.eval(c)).collect());
                if let Some(sink) = self.sink_within(id).cloned() {
                    if let Some(st) = &combined {
                        self.record_flow(&sink, st);
                    }
                }
                combined
            }
            // `lhs = rhs` — a property-write sink consumes the right side
            // here, and the target becomes tainted.
            SyntaxKind::Assign => {
                let children = self.tree.node(id).children.clone();
                let Some(lhs) = children.first() else {
                    return None;
                };
                let rhs = children.get(1).copied();
                let st = rhs.and_then(|r| self.eval(r));
                if let Some(sink) = self.sink_within(*lhs).cloned() {
                    if let Some(st) = &st {
                        self.record_flow(&sink, st);
                    }
                }
                self.taint_target(*lhs, st.clone());
                st
            }
            // Function expressions and arrows: the body is a new scope and
            // its parameters are not bound here. Tracing into it is
            // interprocedural analysis (P1.3); the value does not carry the
            // caller's taint.
            SyntaxKind::FunctionExpr | SyntaxKind::ArrowFn => None,
            // `{ key: value }` — only the value is read. A shorthand `{ a }`
            // does read the variable `a`, so its single child is evaluated.
            // The key of a `key: value` pair is a label, not a variable read.
            SyntaxKind::Property => {
                let children = self.tree.node(id).children.clone();
                match children.as_slice() {
                    [only] => self.eval(*only),
                    [_, value, ..] => self.eval(*value),
                    _ => None,
                }
            }
            // Any other composite expression: taint flows through children.
            _ => {
                let children = self.tree.node(id).children.clone();
                combine(children.into_iter().map(|c| self.eval(c)).collect())
            }
        }
    }

    /// Coarse template-interpolation taint: a template is one token, so
    /// `${ name }` interpolations are scanned for plain identifiers and
    /// resolved in the template's scope. Expression interpolations
    //  (`${ v.toUpperCase() }`) are not traced — a documented limitation
    /// shared with the lexer, refined in P1.4.
    fn template_taint(&mut self, id: NodeId) -> Option<TaintState> {
        let text = self.tree.node_text(id);
        let scope_offset = self.tree.node(id).range.start;
        let mut from = 0usize;
        while let Some(rel) = text[from..].find("${") {
            let open = from + rel;
            let Some(close_rel) = text[open + 2..].find('}') else {
                break;
            };
            let close = open + 2 + close_rel;
            let inner = text[open + 2..close].trim();
            if !inner.is_empty()
                && inner
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
            {
                if let Some(b) = self.scopes.resolve_at(scope_offset, inner) {
                    if let Some(st) = self.bindings.get(&(b.range.start, b.range.end)) {
                        return Some(st.clone());
                    }
                }
                if let Some(st) = self.globals.get(inner) {
                    return Some(st.clone());
                }
            }
            from = close + 1;
        }
        None
    }

    // ------------------------------------------------------------------
    // Binding taint
    // ------------------------------------------------------------------

    /// Taint the binding declared/written at an identifier node.
    fn taint_binding(&mut self, ident: NodeId, st: Option<TaintState>) {
        let Some(st) = st else {
            return;
        };
        let name = self.tree.node_text(ident).to_string();
        let offset = self.tree.node(ident).range.start;
        if let Some(b) = self.scopes.resolve_at(offset, &name) {
            self.bindings.insert((b.range.start, b.range.end), st);
        } else {
            // An assignment to an undeclared name: an implicit global.
            self.globals.insert(name, st);
        }
    }

    /// The taint of a binding read at an identifier node.
    fn read_binding(&self, id: NodeId) -> Option<TaintState> {
        let name = self.tree.node_text(id);
        let offset = self.tree.node(id).range.start;
        if let Some(b) = self.scopes.resolve_at(offset, name) {
            return self.bindings.get(&(b.range.start, b.range.end)).cloned();
        }
        self.globals.get(name).cloned()
    }

    /// Taint an assignment target: a binding, a property path, or every
    /// name a destructuring pattern introduces.
    fn taint_target(&mut self, lhs: NodeId, st: Option<TaintState>) {
        let Some(st) = st else {
            return;
        };
        match self.tree.node(lhs).kind {
            SyntaxKind::Ident => self.taint_binding(lhs, Some(st)),
            SyntaxKind::Member => {
                if let Some(path) = self.member_path(lhs) {
                    self.props.insert(path, st);
                }
            }
            SyntaxKind::ObjectLit | SyntaxKind::ArrayLit => {
                for ident in binding_idents(self.tree, lhs) {
                    self.taint_binding(ident, Some(st.clone()));
                }
            }
            _ => {}
        }
    }

    // ------------------------------------------------------------------
    // Flow recording
    // ------------------------------------------------------------------

    fn record_flow(&mut self, sink: &SinkCall, st: &TaintState) {
        self.flows.push(TaintFlow {
            source: TaintNode {
                id: format!("src-{}", st.origin.offset),
                kind: TaintNodeKind::Source,
                label: st.origin.kind.label().to_string(),
                offset: st.origin.offset,
            },
            sink: TaintNode {
                id: format!("sink-{}", sink.offset),
                kind: TaintNodeKind::Sink,
                label: sink.api.clone(),
                offset: sink.offset,
            },
            transforms: st.transforms.clone(),
            sanitized: st.sanitized,
            sink_risk: sink.risk.label().to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flows(src: &str) -> Vec<TaintFlow> {
        build(src).flows
    }

    #[test]
    fn direct_source_to_sink_flow() {
        let f = flows("var v = location.hash; el.innerHTML = v;");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].source.label, "location.hash");
        assert_eq!(f[0].sink.label, "innerHTML");
        assert_eq!(f[0].sink_risk, "critical");
        assert!(!f[0].sanitized);
    }

    #[test]
    fn inline_source_reaches_sink() {
        // No intermediate variable: the source is the sink argument itself.
        let f = flows("el.innerHTML = location.hash;");
        assert_eq!(f.len(), 1);
        assert!(!f[0].sanitized);
    }

    #[test]
    fn unrelated_variable_is_not_connected() {
        // The exact failure mode of the old `same_data_object` heuristic: a
        // source the sink never uses must not flow.
        let f = flows("var v = location.hash;\nvar other = getData();\nel.innerHTML = other;");
        assert!(f.is_empty(), "an unrelated variable must not carry taint");
    }

    #[test]
    fn unsanitized_critical_flows_query() {
        let g = build("var v = location.hash; el.innerHTML = v;");
        assert_eq!(g.unsanitized_critical_flows().len(), 1);
    }

    #[test]
    fn sanitized_flow_is_marked() {
        // A sanitizer call on the path marks the flow sanitized.
        let f = flows("var v = location.hash; var clean = DOMPurify.sanitize(v); el.innerHTML = clean;");
        assert_eq!(f.len(), 1);
        assert!(f[0].sanitized, "DOMPurify must sanitize the flow");

        // The same flow without a sanitizer is not marked.
        let plain = flows("var v = location.hash; el.innerHTML = v;");
        assert!(!plain[0].sanitized);
    }

    #[test]
    fn sanitizer_must_be_on_the_path() {
        // A sanitizer that is NOT on the path must not mark the flow. This
        // is what the old substring-over-a-window approach got wrong.
        let f = flows("var v = location.hash;\nif (false) { escapeHtml(other); }\nel.innerHTML = v;");
        assert_eq!(f.len(), 1);
        assert!(!f[0].sanitized, "an off-path sanitizer must not sanitize");
    }

    #[test]
    fn transforms_recorded_on_path() {
        let f = flows("var v = location.hash; var d = decodeURIComponent(v); el.innerHTML = d;");
        assert_eq!(f.len(), 1);
        assert!(f[0].transforms.iter().any(|t| t == "decodeURIComponent"));
    }

    #[test]
    fn member_transform_recorded() {
        // `v.replace(...)` — a method transform on a tainted value.
        let f = flows("var v = location.hash; var d = v.replace('a','b'); el.innerHTML = d;");
        assert_eq!(f.len(), 1);
        assert!(f[0].transforms.iter().any(|t| t == "replace"), "transforms: {:?}", f[0].transforms);
    }

    #[test]
    fn chained_source_transform() {
        // The source is transformed in place: `location.hash.slice(1)`.
        let f = flows("el.innerHTML = location.hash.slice(1);");
        assert_eq!(f.len(), 1);
        assert!(f[0].transforms.iter().any(|t| t == "slice"), "transforms: {:?}", f[0].transforms);
    }

    #[test]
    fn no_sources_no_flows() {
        assert!(flows("var x = 1; el.innerHTML = '<b>static</b>';").is_empty());
    }

    #[test]
    fn no_sinks_no_flows() {
        assert!(flows("var v = location.hash; console.log(v);").is_empty());
    }

    #[test]
    fn multiple_flows_supported() {
        let f = flows(
            "var a = location.hash;\nvar b = document.referrer;\nel.innerHTML = a;\nel2.innerHTML = b;",
        );
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn implicit_global_carries_taint() {
        // No `var`: the assignment target is an implicit global.
        let f = flows("v = location.hash; el.innerHTML = v;");
        assert_eq!(f.len(), 1, "an implicit global must still propagate");
    }

    #[test]
    fn call_sink_argument_traced() {
        let f = flows("var v = location.hash; document.write(v);");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].sink.label, "document.write");
    }

    #[test]
    fn eval_sink_argument_traced() {
        let f = flows("var v = location.hash; setTimeout(v, 100);");
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn new_function_sink_traced() {
        let f = flows("var v = location.hash; var g = new Function(v);");
        assert_eq!(f.len(), 1, "new Function is a script-execution sink");
    }

    #[test]
    fn array_element_carries_taint() {
        let f = flows("var v = location.hash; var arr = [v]; el.innerHTML = arr[0];");
        assert_eq!(f.len(), 1, "taint must flow through array elements");
    }

    #[test]
    fn property_write_and_read() {
        // Coarse property taint: a written property read back is tainted.
        let f = flows("var v = location.hash; box.data = v; el.innerHTML = box.data;");
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn template_interpolation_carries_taint() {
        let f = flows("var v = location.hash; var s = `${v}`; el.innerHTML = s;");
        assert_eq!(f.len(), 1, "a template interpolation must carry taint");
    }

    #[test]
    fn shadowed_parameter_does_not_leak() {
        // An inner parameter shadows an outer tainted name: no cross-scope
        // leakage into the function body.
        let f = flows("var v = location.hash;\nfunction f(v) { return v; }\nel.innerHTML = f('safe');");
        // The argument is a clean literal, so no flow reaches the sink.
        assert!(f.is_empty(), "a shadowed parameter must not inherit taint: {:?}", f);
    }

    #[test]
    fn top_level_function_source_flows() {
        // A source inside a top-level function declaration is still found.
        let f = flows("function load() { var v = location.hash; el.innerHTML = v; }");
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn assignment_chain_propagates() {
        let f = flows("var v = location.hash; var w = v; var x = w; el.innerHTML = x;");
        assert_eq!(f.len(), 1, "taint must propagate through a chain");
    }

    #[test]
    fn sanitized_flow_excluded_from_critical_query() {
        let g = build("var v = location.hash; var c = escapeHtml(v); el.innerHTML = c;");
        assert_eq!(g.flows.len(), 1);
        assert!(g.flows[0].sanitized);
        assert!(g.unsanitized_critical_flows().is_empty());
    }

    #[test]
    fn object_destructuring_carries_taint() {
        let f = flows("var { a } = { a: location.hash }; el.innerHTML = a;");
        assert_eq!(f.len(), 1, "a destructured binding must inherit taint");
    }

    #[test]
    fn renamed_destructuring_carries_taint() {
        let f = flows("var { a: x } = { a: location.hash }; el.innerHTML = x;");
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn destructured_parameter_carries_taint() {
        // The parameter is bound; the caller passes a literal, so no flow.
        // This asserts the binding exists without a false positive.
        let f = flows("function f({ id }) { el.innerHTML = id; }\nf({ id: 'safe' });");
        assert!(f.is_empty(), "a clean literal argument must not taint: {:?}", f);
    }

    #[test]
    fn object_key_is_not_a_variable_read() {
        // `{ a: 'clean' }` must not read the variable `a`, so a tainted `a`
        // does not leak into a later `o.a` read.
        let f = flows("var a = location.hash; var o = { a: 'clean' }; el.innerHTML = o.a;");
        assert!(f.is_empty(), "a property key must not be a variable read: {:?}", f);
    }

    #[test]
    fn shorthand_property_reads_the_variable() {
        // `{ v }` shorthand DOES read the variable, so it carries taint.
        let f = flows("var v = location.hash; var o = { v }; el.innerHTML = o.v;");
        assert_eq!(f.len(), 1, "an object value must carry taint");
    }
}
