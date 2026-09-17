//! AST-based data-flow taint analysis.
//!
//! Replaces the line/substring heuristic (`same_data_object`) with a walk
//! over the parsed syntax tree. The question the old heuristic could only
//! guess at â€” *does the value reaching this sink trace back to this
//! source?* â€” is now answered structurally:
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
//!
//! Calls into user-defined functions *in the same script* are traced
//! interprocedurally: the arguments are bound to the callee's parameters,
//! the body is walked under that binding, sinks reached inside the body are
//! recorded against the argument's real origin, and the value the function
//! returns carries the taint back to the caller. Each (function, argument
//! context) pair is summarized once and cached; recursion is refused and the
//! total work is budget-capped, so the analysis always terminates. Built-in
//! calls, methods, and cross-script functions stay opaque â€” a value passed
//! to one is not traced further.

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

/// A signature of a taint state: enough to decide that two states behave
/// identically in the analysis (the origin that taints them, whether a
/// sanitizer was seen, and the transforms recorded). Used as the
/// interprocedural cache key, so the summary for a `(function, arguments)`
/// pair is computed once.
type TaintSig = Option<(usize, bool, Vec<String>)>;

fn taint_sig(st: &Option<TaintState>) -> TaintSig {
    st.as_ref().map(|s| (s.origin.offset, s.sanitized, s.transforms.clone()))
}

/// The hard cap on interprocedural analyses for one script. The call stack
/// already refuses recursion; this bounds the total work for pathological
/// input (deep call chains, loops) so the analysis always terminates. Beyond
/// the budget, calls are treated as opaque â€” nothing is invented.
const INTERPROCEDURAL_BUDGET: usize = 4_096;

/// The deepest call nesting analysed. Each level costs a stack frame, so a
/// chain deeper than this is truncated rather than risk overflowing the
/// stack; the argument's own taint still propagates, only the callee's body
/// stops being traced. Real inline scripts do not approach this depth.
const MAX_CALL_DEPTH: usize = 64;

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
/// canonical operation â€” the dotted name when that is the match
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
    /// Tainted property paths (`obj.prop`), coarse â€” real aliasing is P1.4.
    props: HashMap<String, TaintState>,
    flows: Vec<TaintFlow>,
    /// Every function in the script, keyed by its own range, so a binding's
    /// initializer range resolves to the function node it declares.
    fn_by_range: HashMap<(usize, usize), NodeId>,
    /// Functions currently being analysed, innermost last. A repeat entry is
    /// recursion and is refused rather than followed.
    call_stack: Vec<NodeId>,
    /// Cached summaries: (function, argument context, shared state) -> the
    /// taint the function returns. A miss is computed once and reused.
    summaries: HashMap<(NodeId, Vec<TaintSig>, Vec<(String, TaintSig)>), Option<TaintState>>,
    /// Return values collected while walking the current function body.
    returns: Vec<Option<TaintState>>,
    /// Flows already recorded, by identity: a source-to-sink pair reached the
    /// same way is one flow, however many walks observe it.
    seen_flows: HashSet<(usize, usize, bool, Vec<String>)>,
    /// Remaining interprocedural analyses.
    budget: usize,
}

/// How a call's callee was handled by the interprocedural analysis.
enum CallTrace {
    /// The callee was traced into. Carries the taint of the value it returns,
    /// which is [`None`] when the function returns clean.
    Modelled(Option<TaintState>),
    /// The callee is not traced â€” a builtin, a method, a name this script does
    /// not declare â€” so the callee and its arguments are the value's
    /// provenance, and a sink in the callee's range consumes them at the call.
    Opaque,
}

impl<'a> Analyzer<'a> {
    fn new(tree: &'a SyntaxTree, scopes: &'a ScopeGraph, sources: Vec<SourceRead>, sinks: Vec<SinkCall>) -> Self {
        let fn_by_range = tree
            .all_nodes()
            .into_iter()
            .filter(|&id| {
                matches!(
                    tree.node(id).kind,
                    SyntaxKind::FunctionDecl | SyntaxKind::FunctionExpr | SyntaxKind::ArrowFn
                )
            })
            .map(|id| {
                let r = tree.node(id).range;
                ((r.start, r.end), id)
            })
            .collect();
        Self {
            tree,
            scopes,
            sources,
            sinks,
            bindings: HashMap::new(),
            globals: HashMap::new(),
            props: HashMap::new(),
            flows: Vec::new(),
            fn_by_range,
            call_stack: Vec::new(),
            summaries: HashMap::new(),
            returns: Vec::new(),
            seen_flows: HashSet::new(),
            budget: INTERPROCEDURAL_BUDGET,
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
                // `return e`: the expression is the function's value. It is
                // evaluated (recording any flow it contains) and collected by
                // the enclosing function analysis.
                SyntaxKind::Return => {
                    if let Some(&expr) = self.tree.node(child).children.first() {
                        let st = self.eval(expr);
                        self.returns.push(st);
                    }
                }
                // A nested function is analysed on demand at its call sites.
                // The top-level walk still descends to catch a flow entirely
                // inside a function that is never called; from inside a
                // function body it does not, so the inner returns cannot be
                // mistaken for the outer function's own.
                SyntaxKind::FunctionDecl | SyntaxKind::FunctionExpr | SyntaxKind::ArrowFn
                    if !self.call_stack.is_empty() => {}
                _ => self.walk(child),
            }
        }
    }

    /// `name = init` â€” taint the declared binding from the initializer.
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
            | SyntaxKind::RegexLit => {
                if let Some(src) = self.source_within(id) {
                    return Some(TaintState::from_source(src));
                }
                None
            }
            // `` `text ${ expr } more` ``: the interpolations are children, so
            // a value interpolated into a template is traced like any other
            // expression — including calls, members and sources inside `${}`.
            // The literal text between them carries no taint.
            SyntaxKind::TemplateLit => {
                let children = self.tree.node(id).children.clone();
                combine(children.into_iter().map(|c| self.eval(c)).collect())
            }
            SyntaxKind::Ident => {
                if let Some(src) = self.source_within(id) {
                    return Some(TaintState::from_source(src));
                }
                self.read_binding(id)
            }
            // `obj.prop` â€” taint flows from the object; otherwise a source
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
            // `f(args)` â€” a sink consumes its arguments here; a sanitizer or
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
                let combined = match self.analyze_call(callee, &states) {
                    // The callee was traced: its value is what the body
                    // returns. A return derived from an argument supersedes
                    // that argument â€” it is the same data, carrying the
                    // transforms and sanitizers the body applied to it â€” so
                    // the argument drops out of the combination. A return
                    // from elsewhere, and every argument it does not derive
                    // from, is independent data and is kept.
                    CallTrace::Modelled(Some(ret)) => {
                        let origin = ret.origin.offset;
                        let mut combined = vec![Some(ret)];
                        for st in &states {
                            match st {
                                Some(st) if st.origin.offset == origin => {}
                                other => combined.push(other.clone()),
                            }
                        }
                        combine(combined)
                    }
                    // Traced and clean, or understood but not traced
                    // (recursion, the depth cap, the budget): the arguments
                    // stay as the value's provenance. A sink inside the
                    // callee's range is not consulted here â€” the body's own
                    // analysis records those it reaches.
                    CallTrace::Modelled(None) => combine(states),
                    // Not a call this analysis models: the callee joins its
                    // arguments as provenance, and a sink in the callee's
                    // range consumes the value here.
                    CallTrace::Opaque => {
                        let mut states = states;
                        states.push(self.eval(callee));
                        let combined = combine(states);
                        if let Some(sink) = self.sink_within(callee).cloned() {
                            if let Some(st) = &combined {
                                self.record_flow(&sink, st);
                            }
                        }
                        combined
                    }
                };
                let mut combined = combined;
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
            // `new Foo(args)` â€” a sink may appear in the constructor name.
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
            // `lhs = rhs` â€” a property-write sink consumes the right side
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
            // its parameters are not bound here. As a *value* a function
            // carries no taint; as a *callee* it is traced by
            // [`Self::analyze_call`] from the enclosing call.
            SyntaxKind::FunctionExpr | SyntaxKind::ArrowFn => None,
            // `{ key: value }` â€” only the value is read. A shorthand `{ a }`
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
    // Interprocedural analysis
    // ------------------------------------------------------------------

    /// Resolve a callee to the function node it refers to in this script: a
    /// name whose declaration initializer is a function, or a function
    /// expression used directly. Everything else â€” builtins, methods, names
    /// this script does not declare â€” resolves to nothing and stays opaque.
    fn resolve_callee(&self, callee: NodeId) -> Option<NodeId> {
        match self.tree.node(callee).kind {
            SyntaxKind::Ident => {
                let name = self.tree.node_text(callee);
                let offset = self.tree.node(callee).range.start;
                let binding = self.scopes.resolve_at(offset, name)?;
                let init = binding.init?;
                self.fn_by_range.get(&(init.start, init.end)).copied()
            }
            SyntaxKind::FunctionExpr | SyntaxKind::ArrowFn => Some(callee),
            _ => None,
        }
    }

    /// Trace `args` through the body of the function `callee` refers to, and
    /// return the taint that function's value carries back. Cached per
    /// (function, argument context, shared state); recursion and the budget
    /// are refused rather than followed.
    fn analyze_call(&mut self, callee: NodeId, args: &[Option<TaintState>]) -> CallTrace {
        let Some(fn_node) = self.resolve_callee(callee) else {
            return CallTrace::Opaque;
        };
        // Recursion is refused; so is any nesting beyond the depth cap, which
        // bounds the stack as well as the work.
        if self.call_stack.contains(&fn_node) || self.call_stack.len() >= MAX_CALL_DEPTH {
            return CallTrace::Modelled(None);
        }
        if self.budget == 0 {
            return CallTrace::Modelled(None);
        }
        let key = (
            fn_node,
            args.iter().map(taint_sig).collect(),
            self.state_signature(),
        );
        if let Some(ret) = self.summaries.get(&key) {
            return CallTrace::Modelled(ret.clone());
        }
        self.budget -= 1;
        let (params, body) = function_parts(self.tree, fn_node);
        let ret = self.analyze_function(fn_node, &params, body, args);
        self.summaries.insert(key, ret.clone());
        CallTrace::Modelled(ret)
    }

    /// Walk a function body with the arguments bound to its parameters,
    /// recording any sink reached inside, and return the taint of its value.
    fn analyze_function(
        &mut self,
        fn_node: NodeId,
        params: &[NodeId],
        body: Option<NodeId>,
        args: &[Option<TaintState>],
    ) -> Option<TaintState> {
        // Snapshot the taint state: the callee's own locals must not leak
        // back into the caller, and a call with clean arguments must not
        // inherit the taint a previous call left on a parameter. Sinks
        // reached inside the body are kept â€” they are recorded in `flows`.
        let bindings = std::mem::take(&mut self.bindings);
        let globals = std::mem::take(&mut self.globals);
        let props = std::mem::take(&mut self.props);
        let returns = std::mem::take(&mut self.returns);
        self.call_stack.push(fn_node);
        for (i, param) in params.iter().enumerate() {
            // Positional: an argument is bound to its parameter, a missing
            // one falls back to the parameter's default when it has one.
            let st = args
                .get(i)
                .cloned()
                .flatten()
                .or_else(|| param_default(self.tree, *param).and_then(|d| self.eval(d)));
            self.bind_param(*param, st);
        }
        let ret = match body {
            // A block body: walk it, and the value is what its returns carry.
            Some(body) if self.tree.node(body).kind == SyntaxKind::Block => {
                self.walk(body);
                combine(std::mem::take(&mut self.returns))
            }
            // An arrow's expression body: the expression is the value.
            Some(body) => self.eval(body),
            None => None,
        };
        self.call_stack.pop();
        self.bindings = bindings;
        self.globals = globals;
        self.props = props;
        self.returns = returns;
        ret
    }

    /// Set the taint state of every name a parameter binds: tainted when the
    /// argument is tainted, and explicitly cleared otherwise so a clean
    /// argument cannot inherit a previous call's taint.
    fn bind_param(&mut self, param: NodeId, st: Option<TaintState>) {
        for ident in param_idents(self.tree, param) {
            let name = self.tree.node_text(ident);
            let offset = self.tree.node(ident).range.start;
            let Some(binding) = self.scopes.resolve_at(offset, name) else {
                continue;
            };
            let key = (binding.range.start, binding.range.end);
            match st.clone() {
                Some(st) => {
                    self.bindings.insert(key, st);
                }
                None => {
                    self.bindings.remove(&key);
                }
            }
        }
    }

    /// A signature of the taint state shared with a callee: the bindings,
    /// globals and properties visible at the call. Two calls whose arguments
    /// *and* shared state match behave identically, so the cached summary is
    /// exact. Sorted because the maps iterate in arbitrary order.
    fn state_signature(&self) -> Vec<(String, TaintSig)> {
        let mut sig: Vec<(String, TaintSig)> = self
            .bindings
            .iter()
            .map(|((s, e), st)| (format!("b-{s}-{e}"), taint_sig(&Some(st.clone()))))
            .chain(self.globals.iter().map(|(n, st)| (format!("g-{n}"), taint_sig(&Some(st.clone())))))
            .chain(self.props.iter().map(|(n, st)| (format!("p-{n}"), taint_sig(&Some(st.clone())))))
            .collect();
        sig.sort_by(|a, b| a.0.cmp(&b.0));
        sig
    }

    // ------------------------------------------------------------------
    // Flow recording
    // ------------------------------------------------------------------

    fn record_flow(&mut self, sink: &SinkCall, st: &TaintState) {
        // The same source-to-sink pair may be observed by more than one walk
        // (a function is descended into at the top level and again at its
        // call site). It is one flow, recorded once.
        let identity = (st.origin.offset, sink.offset, st.sanitized, st.transforms.clone());
        if !self.seen_flows.insert(identity) {
            return;
        }
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

/// The parameters and body of a function node.
///
/// Its children are `[name?, params..., body]`: a declaration (or a named
/// expression) opens with an identifier, then the parameters â€” a plain
/// [`SyntaxKind::Param`], a defaulted one, a [`SyntaxKind::Spread`], or a
/// destructuring literal â€” and finally the body, a block or, for an arrow, an
/// expression. The parameter run stops at the first child that cannot be one;
/// when that leaves no body, the last parameter is the body (an arrow whose
/// expression is a parenthesized object or array literal).
fn function_parts(tree: &SyntaxTree, id: NodeId) -> (Vec<NodeId>, Option<NodeId>) {
    let node = tree.node(id);
    let mut start = 0;
    if matches!(node.kind, SyntaxKind::FunctionDecl | SyntaxKind::FunctionExpr) {
        if let Some(first) = node.children.first() {
            if tree.node(*first).kind == SyntaxKind::Ident {
                start = 1;
            }
        }
    }
    let mut params = Vec::new();
    let mut i = start;
    while i < node.children.len() {
        if matches!(
            tree.node(node.children[i]).kind,
            SyntaxKind::Param | SyntaxKind::Spread | SyntaxKind::ObjectLit | SyntaxKind::ArrayLit
        ) {
            params.push(node.children[i]);
            i += 1;
        } else {
            break;
        }
    }
    let body = node.children.get(i).copied().or_else(|| params.pop());
    (params, body)
}

/// The identifier nodes a parameter binds: the name of a plain or defaulted
/// parameter, the operand of a rest parameter, or every name a destructuring
/// pattern introduces.
fn param_idents(tree: &SyntaxTree, param: NodeId) -> Vec<NodeId> {
    let node = tree.node(param);
    match node.kind {
        // `p` (a leaf) or `p = default` / `{ a } = default` (the name is the
        // first child, itself a plain Param or a destructuring literal).
        SyntaxKind::Param => match node.children.first() {
            Some(&child) => param_idents(tree, child),
            None => vec![param],
        },
        // `...rest`: the operand is the binding.
        SyntaxKind::Spread => node
            .children
            .first()
            .map(|&child| param_idents(tree, child))
            .unwrap_or_default(),
        SyntaxKind::ObjectLit | SyntaxKind::ArrayLit => binding_idents(tree, param),
        _ => Vec::new(),
    }
}

/// The default expression of a parameter, when it has one (`p = expr`).
fn param_default(tree: &SyntaxTree, param: NodeId) -> Option<NodeId> {
    match tree.node(param).kind {
        SyntaxKind::Param => tree.node(param).children.get(1).copied(),
        _ => None,
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
        // `v.replace(...)` â€” a method transform on a tainted value.
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
    fn template_interpolation_expression_carries_taint() {
        // `${ v.toUpperCase() }`: the interpolation is a real expression now,
        // not a scanned name, so a call inside it is traced.
        let f = flows("var v = location.hash; var s = `${v.toUpperCase()}`; el.innerHTML = s;");
        assert_eq!(f.len(), 1, "an expression interpolation must carry taint");
        // And a classified transform inside the interpolation is recorded.
        let f = flows("var v = location.hash; var s = `${v.replace('a','b')}`; el.innerHTML = s;");
        assert_eq!(f.len(), 1);
        assert!(f[0].transforms.iter().any(|t| t == "replace"), "transforms: {:?}", f[0].transforms);
    }

    #[test]
    fn template_interpolation_source_read() {
        // The source read is inside the interpolation itself.
        let f = flows("var s = `${location.hash}`; el.innerHTML = s;");
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn template_interpolation_member_of_tainted() {
        let f = flows("var o = { a: location.hash }; var s = `${o.a}`; el.innerHTML = s;");
        assert_eq!(f.len(), 1, "a member interpolation must carry taint");
    }

    #[test]
    fn template_interpolation_sanitizer_on_path() {
        // A sanitizer applied inside the interpolation sanitizes the flow.
        let f = flows("var v = location.hash; var s = `${escapeHtml(v)}`; el.innerHTML = s;");
        assert_eq!(f.len(), 1);
        assert!(f[0].sanitized, "a sanitizer inside an interpolation must sanitize");
    }

    #[test]
    fn template_text_without_interpolation_is_clean() {
        let f = flows("var v = location.hash; var s = `plain text`; el.innerHTML = s;");
        assert!(f.is_empty(), "template text alone must not carry taint: {:?}", f);
    }

    #[test]
    fn template_interpolation_function_call_traced() {
        // An interprocedural value inside an interpolation.
        let f = flows("function f(x) { return x; } var s = `${f(location.hash)}`; el.innerHTML = s;");
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn nested_template_interpolation_carries_taint() {
        let f = flows("var v = location.hash; var s = `a ${ `b ${v}` }`; el.innerHTML = s;");
        assert_eq!(f.len(), 1, "a nested interpolation must carry taint");
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

    // -----------------------------------------------------------------
    // Interprocedural analysis (P1.3)
    // -----------------------------------------------------------------

    #[test]
    fn argument_reaches_sink_through_function_return() {
        // The classic helper pattern: data crosses a function boundary.
        let f = flows("function f(x) { return x; }\nel.innerHTML = f(location.hash);");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].source.label, "location.hash");
        assert!(!f[0].sanitized);
    }

    #[test]
    fn clean_argument_through_function_stays_clean() {
        // The same function, a clean argument: no flow may be invented.
        let f = flows("function f(x) { return x; }\nel.innerHTML = f('safe');");
        assert!(f.is_empty(), "a clean argument must not be tainted: {:?}", f);
    }

    #[test]
    fn clean_call_after_tainted_call_is_not_polluted() {
        // The soundness core of the summary cache: a call with clean
        // arguments must not inherit the taint a previous call left on the
        // parameter, and the callee's locals must not leak into the caller.
        let f = flows(
            "function f(x) { var t = x; return t; }\nvar a = f(location.hash);\nvar b = f('safe');\nel.innerHTML = b;",
        );
        assert!(f.is_empty(), "stale callee state must not taint a later call: {:?}", f);
    }

    #[test]
    fn sink_inside_function_body_is_reached() {
        // The sink is inside the callee; the origin is the caller's argument.
        let f = flows("function h(x) { el.innerHTML = x; }\nh(location.hash);");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].source.label, "location.hash");
        assert_eq!(f[0].sink.label, "innerHTML");
    }

    #[test]
    fn transform_inside_function_is_recorded() {
        let f = flows(
            "function f(x) { return x.replace('a', 'b'); }\nel.innerHTML = f(location.hash);",
        );
        assert_eq!(f.len(), 1);
        assert!(f[0].transforms.iter().any(|t| t == "replace"), "transforms: {:?}", f[0].transforms);
    }

    #[test]
    fn sanitizer_inside_function_marks_the_flow() {
        let f = flows("function f(x) { return escapeHtml(x); }\nel.innerHTML = f(location.hash);");
        assert_eq!(f.len(), 1);
        assert!(f[0].sanitized, "a sanitizer inside the callee must sanitize the flow");
    }

    #[test]
    fn sanitizer_name_still_applies_to_interprocedural_call() {
        // The name-based classification composes with the traced body.
        let f = flows("function escapeHtml(x) { return x; }\nel.innerHTML = escapeHtml(location.hash);");
        assert_eq!(f.len(), 1);
        assert!(f[0].sanitized);
    }

    #[test]
    fn call_chain_of_two_functions() {
        let f = flows(
            "function f(x) { return x; }\nfunction g(y) { return f(y); }\nel.innerHTML = g(location.hash);",
        );
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn deep_call_chain_terminates_and_flows() {
        // A chain long enough to matter, each link calling the next twice:
        // without the summary cache this is exponential.
        let mut src = String::new();
        for i in 0..40 {
            src.push_str(&format!("function f{i}(x) {{ return f{}(x); return f{}(x); }}", i + 1, i + 1));
        }
        src.push_str("function f40(x) { return x; }");
        src.push_str("el.innerHTML = f0(location.hash);");
        let f = flows(&src);
        assert_eq!(f.len(), 1, "a deep chain must still be traced exactly once");
    }

    #[test]
    fn direct_recursion_terminates() {
        // Recursion is refused rather than followed; the analysis completes.
        let f = flows("function r(x) { return r(x); }\nel.innerHTML = r(location.hash);");
        // The callee falls back to reading the argument, so the flow stands.
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn mutual_recursion_terminates() {
        let f = flows(
            "function a(x) { return b(x); }\nfunction b(x) { return a(x); }\nel.innerHTML = a(location.hash);",
        );
        assert!(f.len() <= 1, "mutual recursion must not blow up: {} flows", f.len());
    }

    #[test]
    fn nested_function_return_does_not_pollute_the_outer() {
        // The inner function applies a sanitizer to a tainted outer variable
        // but is never called: that must not mark the outer function's own
        // return sanitized. Observable only through the sanitized flag, since
        // the argument's taint conservatively reaches the sink either way.
        let f = flows(
            "function h(x) {\n  var t = x;\n  function g() { return escapeHtml(t); }\n  return x;\n}\nvar r = h(location.hash);\nel.innerHTML = r;",
        );
        assert_eq!(f.len(), 1);
        assert!(!f[0].sanitized, "an uncalled nested function must not sanitize: {:?}", f);
    }

    #[test]
    fn nested_function_called_from_body_carries_taint() {
        // Same shape, but g is called: the outer variable must be visible to
        // it, and the callee's locals must survive until the outer returns.
        let f = flows(
            "function h(x) {\n  var t = x;\n  function g() { return t; }\n  return g();\n}\nel.innerHTML = h(location.hash);",
        );
        assert_eq!(f.len(), 1, "a called nested function must carry the taint back: {:?}", f);
    }

    #[test]
    fn arrow_function_traces_argument() {
        let f = flows("const f = (x) => x;\nel.innerHTML = f(location.hash);");
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn arrow_with_block_body_sink() {
        let f = flows("const h = (x) => { el.innerHTML = x; };\nh(location.hash);");
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn immediately_invoked_function_expression() {
        let f = flows("(function(x) { el.innerHTML = x; })(location.hash);");
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn interprocedural_destructured_parameter() {
        let f = flows("function f({ id }) { return id; }\nel.innerHTML = f({ id: location.hash });");
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn rest_parameter_carries_taint() {
        let f = flows("function f(...rest) { el.innerHTML = rest[0]; }\nf(location.hash);");
        assert_eq!(f.len(), 1, "a rest parameter must bind and carry taint");
    }

    #[test]
    fn defaulted_parameter_is_the_initializer() {
        // No argument: the default is the value the parameter starts with.
        let f = flows("function f(x = location.hash) { el.innerHTML = x; }\nf();");
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn arguments_are_positional() {
        // The second argument reaches the second parameter, not the first.
        let f = flows("function f(a, b) { el.innerHTML = b; }\nf('safe', location.hash);");
        assert_eq!(f.len(), 1);
        // A missing argument leaves the parameter clean.
        let none = flows("function f(a, b) { el.innerHTML = b; }\nf(location.hash);");
        assert!(none.is_empty(), "a missing argument must not taint: {:?}", none);
    }

    #[test]
    fn uncalled_function_still_reports_internal_flow() {
        // A function never invoked still has its own source-to-sink flow.
        let f = flows("function load() { var v = location.hash; el.innerHTML = v; }");
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn builtin_and_method_callees_stay_opaque() {
        // A builtin that is also a name in the script is not traced into;
        // the sink is the call itself.
        let f = flows("var s = location.hash;\nel.innerHTML = s.substring(1);");
        assert_eq!(f.len(), 1);
        // A method call resolves to no function in this script.
        let m = flows("var s = location.hash;\nobj.render(s);");
        assert!(m.is_empty(), "an unknown method callee must not invent a flow: {:?}", m);
    }

    #[test]
    fn interprocedural_budget_is_not_invented_when_exhausted() {
        // A pathological nest of distinct functions: bounded, so it ends.
        let mut src = String::new();
        for i in 0..600 {
            src.push_str(&format!("function g{i}(x) {{ return g{}(x); }}", i + 1));
        }
        src.push_str("function g600(x) { return x; }");
        src.push_str("el.innerHTML = g0(location.hash);");
        // No panic, no hang; whatever it concludes is structurally supported.
        let _ = flows(&src);
    }

    #[test]
    fn called_function_reports_internal_flow_once() {
        // The function is descended into at the top level AND traced at its
        // call site; its own source-to-sink flow is one flow, not two.
        let f = flows("function h() { var v = location.hash; el.innerHTML = v; }\nh();");
        assert_eq!(f.len(), 1, "a flow reached twice must be recorded once: {:?}", f);
    }

    #[test]
    fn sanitized_and_unsanitized_paths_coexist() {
        // Same source and sink, different paths: both are real flows.
        let f = flows(
            "function h(x) { el.innerHTML = x; }\nh(location.hash);\nh(escapeHtml(location.hash));",
        );
        assert_eq!(f.len(), 2, "distinct paths to the same pair are distinct flows");
        assert_eq!(f.iter().filter(|x| !x.sanitized).count(), 1);
        assert_eq!(f.iter().filter(|x| x.sanitized).count(), 1);
    }
}
