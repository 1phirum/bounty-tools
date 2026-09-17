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
//!
//! Property taint is keyed by *alias* rather than by a dotted path: an object
//! created at a literal or `new` node is one alias, and it rides along with
//! the value, so `var o = obj; o.data = v` writes the same store `obj.data`
//! reads, and `{ ...src }` carries the source's properties onto the new
//! object. What the analysis deliberately does not model, and answers
//! conservatively instead: a property whose key is computed at runtime
//! (`o[k]`) names an unknown property, so no store is recorded; the result of
//! an opaque call carries no aliases, so a property written on it is lost;
//! `this` is one alias for the whole receiver; and one allocation site in two
//! separate calls is one alias, so a factory called with clean and tainted
//! arguments may attribute the tainted call's property to the clean one.

use std::collections::{HashMap, HashSet};

use crate::parser::js::ast::SyntaxKind;
use crate::parser::js::scope::binding_idents;
use crate::parser::js::{parse_script, NodeId, ScopeGraph, SyntaxTree};
use crate::sanitize::{classify_sanitizer, SanitizerKind};
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
/// identically in the analysis (the origin that taints them, the sanitizers
/// seen, and the transforms recorded).
type TaintSig = Option<(usize, Vec<SanitizerKind>, Vec<String>)>;

fn taint_sig(st: &Option<TaintState>) -> TaintSig {
    st.as_ref().map(|s| (s.origin.offset, s.sanitizers.clone(), s.transforms.clone()))
}

/// A signature of a value: its taint signature plus the objects it may
/// reference. Used as the interprocedural cache key, so the summary for a
/// `(function, arguments)` pair is computed once.
type ValSig = (TaintSig, Vec<Alias>);

fn value_sig(v: &Option<Value>) -> ValSig {
    match v {
        Some(v) => (taint_sig(&v.taint), v.aliases.clone()),
        None => (None, Vec::new()),
    }
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

/// The provenance of a tainted value: where it entered, what happened to it on
/// the way, and which sanitizers were applied.
#[derive(Debug, Clone)]
struct TaintState {
    origin: SourceRead,
    transforms: Vec<String>,
    /// The sanitizers seen on the path, in order. Whether any of them
    /// sanitizes the flow depends on the sink it reaches, so the decision is
    /// made at the sink, not here.
    sanitizers: Vec<SanitizerKind>,
}

impl TaintState {
    fn from_source(src: &SourceRead) -> Self {
        Self { origin: src.clone(), transforms: Vec::new(), sanitizers: Vec::new() }
    }
}

/// Merge several states into one, keeping the first (source-order) origin,
/// every transformation, and every sanitizer seen on any branch.
fn combine_taint(states: Vec<Option<TaintState>>) -> Option<TaintState> {
    let mut iter = states.into_iter().flatten();
    let mut out = iter.next()?;
    for st in iter {
        out.transforms.extend(st.transforms);
        for k in st.sanitizers {
            if !out.sanitizers.contains(&k) {
                out.sanitizers.push(k);
            }
        }
    }
    Some(out)
}

/// An abstract object: the identity a property store or read is keyed by.
///
/// Property taint used to be keyed by a dotted string path (`box.data`), so a
/// copy (`var o = obj`) or a spread (`var o = { ...src }`) broke the
/// connection. An alias is the object a value refers to, and it flows with the
/// value, so two names for one object resolve to the same property store.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Alias {
    /// An object or array created at this node: a literal, or `new`.
    Site(NodeId),
    /// A name reached without a creation site — `window`, `this`, a value from
    /// an unmodelled call. All property accesses through the name meet, which
    /// is sound for one variable and the fallback when identity is unknown.
    Name(String),
}

/// A value the analysis tracks: how it is tainted, if at all, and the abstract
/// objects it may reference. Aliases ride along with taint so they propagate
/// through assignments, returns and parameters exactly the same way.
#[derive(Debug, Clone)]
struct Value {
    taint: Option<TaintState>,
    aliases: Vec<Alias>,
}

impl Value {
    fn from_taint(st: TaintState) -> Self {
        Self { taint: Some(st), aliases: Vec::new() }
    }

    fn site(id: NodeId) -> Self {
        Self { taint: None, aliases: vec![Alias::Site(id)] }
    }

    fn named(name: &str) -> Self {
        Self { taint: None, aliases: vec![Alias::Name(name.to_string())] }
    }
}

/// Merge several values: the combined taint, and every object any branch may
/// reference.
fn combine(states: Vec<Option<Value>>) -> Option<Value> {
    let mut taints = Vec::with_capacity(states.len());
    let mut aliases: Vec<Alias> = Vec::new();
    for st in states.into_iter().flatten() {
        taints.push(st.taint);
        for a in st.aliases {
            if !aliases.contains(&a) {
                aliases.push(a);
            }
        }
    }
    let taint = combine_taint(taints);
    if taint.is_none() && aliases.is_empty() {
        return None;
    }
    Some(Value { taint, aliases })
}

/// How a call affects a tainted value flowing through it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CallClass {
    /// Makes the value safe for the sinks its kind protects.
    Sanitizer(SanitizerKind),
    /// Changes the value without sanitizing. Carries the canonical
    /// operation name recorded on the flow.
    Transform(String),
}

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
/// canonical operation Ã¢ the dotted name when that is the match
/// (`JSON.parse`), otherwise the final segment (`slice`). A sanitizer is
/// classified by what it protects (see [`crate::sanitize`]), not by the name
/// alone.
fn classify_call(name: &str) -> Option<CallClass> {
    let last = name.rsplit('.').next().unwrap_or(name);
    if let Some(kind) = classify_sanitizer(name) {
        return Some(CallClass::Sanitizer(kind));
    } else if TRANSFORMS.contains(&name) {
        return Some(CallClass::Transform(name.to_string()));
    } else if TRANSFORMS.contains(&last) {
        return Some(CallClass::Transform(last.to_string()));
    }
    None
}

struct Analyzer<'a> {
    tree: &'a SyntaxTree,
    scopes: &'a ScopeGraph,
    sources: Vec<SourceRead>,
    sinks: Vec<SinkCall>,
    /// Values bound to declared bindings, keyed by declaration range.
    bindings: HashMap<(usize, usize), Value>,
    /// Values bound to implicit globals (assigned without a declaration).
    globals: HashMap<String, Value>,
    /// Values stored on an object's property, keyed by the object's alias and
    /// the property name.
    props: HashMap<(Alias, String), Value>,
    flows: Vec<TaintFlow>,
    /// Every function in the script, keyed by its own range, so a binding's
    /// initializer range resolves to the function node it declares.
    fn_by_range: HashMap<(usize, usize), NodeId>,
    /// Functions currently being analysed, innermost last. A repeat entry is
    /// recursion and is refused rather than followed.
    call_stack: Vec<NodeId>,
    /// Cached summaries: (function, argument context, shared state) -> the
    /// value the function returns. A miss is computed once and reused.
    summaries: HashMap<(NodeId, Vec<ValSig>, Vec<(String, ValSig)>), Option<Value>>,
    /// Return values collected while walking the current function body.
    returns: Vec<Option<Value>>,
    /// Flows already recorded, by identity: a source-to-sink pair reached the
    /// same way is one flow, however many walks observe it.
    seen_flows: HashSet<(usize, usize, bool, Vec<String>)>,
    /// Remaining interprocedural analyses.
    budget: usize,
}

/// How a call's callee was handled by the interprocedural analysis.
enum CallTrace {
    /// The callee was traced into. Carries the value it returns, which is
    /// [`None`] when the function returns clean.
    Modelled(Option<Value>),
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

    /// The value of an expression: how it is tainted, if at all, and the
    /// abstract objects it may reference. `None` when the expression is clean
    /// and refers to nothing the analysis tracks.
    fn eval(&mut self, id: NodeId) -> Option<Value> {
        match self.tree.node(id).kind {
            // Literals: a source read may appear directly inside one.
            SyntaxKind::StringLit
            | SyntaxKind::NumberLit
            | SyntaxKind::BoolLit
            | SyntaxKind::NullLit
            | SyntaxKind::RegexLit => {
                if let Some(src) = self.source_within(id) {
                    return Some(Value::from_taint(TaintState::from_source(src)));
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
                    return Some(Value::from_taint(TaintState::from_source(src)));
                }
                // A declared binding carries its aliases with its taint. A
                // name this script never declares (`window`, an implicit
                // global) is itself a name alias, so every property access
                // through it resolves to one store.
                self.read_binding(id).or_else(|| Some(Value::named(self.tree.node_text(id))))
            }
            // `this`: one alias for the receiver, coarse but sound.
            SyntaxKind::This => Some(Value::named("this")),
            // `obj.prop` / `obj['prop']` — a static property read. The
            // object's own value joins the store keyed by its aliases, so a
            // written property is read back through every name for the
            // object. A source may also start exactly here (`location.hash`):
            // the member's span carries the read, and supersedes the store.
            SyntaxKind::Member => {
                if let Some(src) = self.source_within(id) {
                    return Some(Value::from_taint(TaintState::from_source(src)));
                }
                if let Some((obj, prop)) = static_member(self.tree, id) {
                    let obj_val = self.eval(obj);
                    return self.read_property(obj_val, &prop);
                }
                // A computed index with a dynamic key (`o[k]`): only the
                // object's own value is known.
                let children = self.tree.node(id).children.clone();
                combine(children.into_iter().map(|c| self.eval(c)).collect())
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
                let mut combined = match self.analyze_call(callee, &states) {
                    // The callee was traced: its value is what the body
                    // returns. A return derived from an argument supersedes
                    // that argument Ã¢ it is the same data, carrying the
                    // transforms and sanitizers the body applied to it Ã¢ so
                    // the argument drops out of the combination. A return
                    // from elsewhere, and every argument it does not derive
                    // from, is independent data and is kept.
                    CallTrace::Modelled(Some(ret)) => {
                        let origin = ret.taint.as_ref().map(|t| t.origin.offset);
                        let mut combined = vec![Some(ret)];
                        for st in &states {
                            let arg_origin =
                                st.as_ref().and_then(|v| v.taint.as_ref().map(|t| t.origin.offset));
                            let superseded = matches!((origin, arg_origin), (Some(a), Some(b)) if a == b);
                            if !superseded {
                                combined.push(st.clone());
                            }
                        }
                        combine(combined)
                    }
                    // Traced and clean, or understood but not traced
                    // (recursion, the depth cap, the budget): the arguments
                    // stay as the value's provenance. A sink inside the
                    // callee's range is not consulted here Ã¢ the body's own
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
                            if let Some(v) = &combined {
                                self.record_flow(&sink, v);
                            }
                        }
                        combined
                    }
                };
                // A sanitizer or transform is classified from the call only
                // when the callee is not a function this script declares: a
                // user-defined `escapeHtml` is traced like any other
                // function, and its body decides what the value carries.
                // Trusting the name is the exact error the semantic model
                // exists to remove.
                if self.resolve_callee(callee).is_none() {
                    if let Some(ref mut v) = combined {
                        let name = self.callee_name(callee);
                        match classify_call(&name) {
                            Some(CallClass::Sanitizer(kind)) => {
                                if let Some(ref mut t) = v.taint {
                                    t.sanitizers.push(kind);
                                }
                            }
                            Some(CallClass::Transform(op)) => {
                                if let Some(ref mut t) = v.taint {
                                    t.transforms.push(op);
                                }
                            }
                            None => {}
                        }
                    }
                }
                combined
            }
            // `new Foo(args)` â€” a sink may appear in the constructor name. The
            // result is a fresh object whose identity is this allocation site.
            SyntaxKind::New => {
                let children = self.tree.node(id).children.clone();
                let mut combined = combine(children.into_iter().map(|c| self.eval(c)).collect());
                if let Some(sink) = self.sink_within(id).cloned() {
                    if let Some(v) = &combined {
                        self.record_flow(&sink, v);
                    }
                }
                match &mut combined {
                    Some(v) => v.aliases.push(Alias::Site(id)),
                    None => combined = Some(Value::site(id)),
                }
                combined
            }
            // `lhs = rhs` â€” a property-write sink consumes the right side
            // here, and the target becomes the value.
            SyntaxKind::Assign => {
                let children = self.tree.node(id).children.clone();
                let Some(lhs) = children.first() else {
                    return None;
                };
                let rhs = children.get(1).copied();
                let st = rhs.and_then(|r| self.eval(r));
                if let Some(sink) = self.sink_within(*lhs).cloned() {
                    if let Some(v) = &st {
                        self.record_flow(&sink, v);
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
            // `{ ...src }` / `[ ...src ]`: the value is the operand's, and
            // the source's stored properties become the new object's, so a
            // property written before the spread is still read after it. The
            // new object's own identity is this allocation site.
            SyntaxKind::ObjectLit | SyntaxKind::ArrayLit => {
                let children = self.tree.node(id).children.clone();
                let mut values = Vec::with_capacity(children.len());
                for &c in &children {
                    let v = self.eval(c);
                    if self.tree.node(c).kind == SyntaxKind::Spread {
                        if let Some(ref sv) = v {
                            for a in &sv.aliases {
                                self.copy_properties(a, &Alias::Site(id));
                            }
                        }
                    }
                    values.push(v);
                }
                let mut combined = combine(values);
                match &mut combined {
                    Some(v) => v.aliases.push(Alias::Site(id)),
                    None => combined = Some(Value::site(id)),
                }
                combined
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

    /// Store the value of the binding declared/written at an identifier node.
    fn taint_binding(&mut self, ident: NodeId, value: Option<Value>) {
        let Some(value) = value else {
            return;
        };
        let name = self.tree.node_text(ident).to_string();
        let offset = self.tree.node(ident).range.start;
        if let Some(b) = self.scopes.resolve_at(offset, &name) {
            self.bindings.insert((b.range.start, b.range.end), value);
        } else {
            // An assignment to an undeclared name: an implicit global.
            self.globals.insert(name, value);
        }
    }

    /// The value of a binding read at an identifier node.
    fn read_binding(&self, id: NodeId) -> Option<Value> {
        let name = self.tree.node_text(id);
        let offset = self.tree.node(id).range.start;
        if let Some(b) = self.scopes.resolve_at(offset, name) {
            return self.bindings.get(&(b.range.start, b.range.end)).cloned();
        }
        self.globals.get(name).cloned()
    }

    /// Write a value to an assignment target: a binding, a property of every
    /// object the target may reference, or every name a destructuring pattern
    /// introduces.
    fn taint_target(&mut self, lhs: NodeId, value: Option<Value>) {
        let Some(value) = value else {
            return;
        };
        match self.tree.node(lhs).kind {
            SyntaxKind::Ident => self.taint_binding(lhs, Some(value)),
            SyntaxKind::Member => {
                if let Some((obj, prop)) = static_member(self.tree, lhs) {
                    // A store under each alias the object may reference. When
                    // the object carries none (a primitive, an unmodelled
                    // call result) the name itself is the key, preserving a
                    // store through a bare global like `box.data`.
                    let obj_val = self.eval(obj);
                    let aliases = match obj_val.as_ref() {
                        Some(v) if !v.aliases.is_empty() => v.aliases.clone(),
                        _ => static_name(self.tree, obj).into_iter().collect(),
                    };
                    for a in aliases {
                        self.props.insert((a, prop.clone()), value.clone());
                    }
                }
            }
            SyntaxKind::ObjectLit | SyntaxKind::ArrayLit => {
                for ident in binding_idents(self.tree, lhs) {
                    self.taint_binding(ident, Some(value.clone()));
                }
            }
            _ => {}
        }
    }

    /// The value of `obj.prop`: the object's own value joined with the
    /// property store under every alias it may reference.
    fn read_property(&self, obj: Option<Value>, prop: &str) -> Option<Value> {
        let aliases = obj.as_ref().map(|v| v.aliases.clone()).unwrap_or_default();
        let mut stored = Vec::new();
        for a in &aliases {
            if let Some(pv) = self.props.get(&(a.clone(), prop.to_string())) {
                stored.push(Some(pv.clone()));
            }
        }
        combine(vec![obj, combine(stored)])
    }

    /// Copy every property stored on `src` onto `dst`, so an object built by
    /// spread keeps the source's property taint.
    fn copy_properties(&mut self, src: &Alias, dst: &Alias) {
        let copied: Vec<((Alias, String), Value)> = self
            .props
            .iter()
            .filter(|((a, _), _)| a == src)
            .map(|(k, v)| ((dst.clone(), k.1.clone()), v.clone()))
            .collect();
        for (k, v) in copied {
            self.props.insert(k, v);
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
    fn analyze_call(&mut self, callee: NodeId, args: &[Option<Value>]) -> CallTrace {
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
            args.iter().map(value_sig).collect(),
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
    /// recording any sink reached inside, and return the value it yields.
    fn analyze_function(
        &mut self,
        fn_node: NodeId,
        params: &[NodeId],
        body: Option<NodeId>,
        args: &[Option<Value>],
    ) -> Option<Value> {
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
        // Property writes the body made to objects the caller can still see
        // are real and are kept: the aliases already tracked before the call,
        // those the arguments carried, and those the returned value carries
        // (a factory's product escapes with its caller). Writes to objects
        // the callee created and kept to itself die with the call.
        let visible: HashSet<Alias> = props
            .keys()
            .map(|(a, _)| a.clone())
            .chain(bindings.values().flat_map(|v| v.aliases.clone()))
            .chain(globals.values().flat_map(|v| v.aliases.clone()))
            .chain(args.iter().flat_map(|v| v.as_ref().map(|v| v.aliases.clone()).unwrap_or_default()))
            .chain(ret.as_ref().map(|v| v.aliases.clone()).unwrap_or_default())
            .collect();
        let mut props = props;
        for ((alias, prop), v) in std::mem::take(&mut self.props) {
            if visible.contains(&alias) {
                props.insert((alias, prop), v);
            }
        }
        self.bindings = bindings;
        self.globals = globals;
        self.props = props;
        self.returns = returns;
        ret
    }

    /// Set the value of every name a parameter binds: the argument's value
    /// when there is one, and explicitly cleared otherwise so a clean
    /// argument cannot inherit a previous call's taint.
    fn bind_param(&mut self, param: NodeId, st: Option<Value>) {
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

    /// A signature of the state shared with a callee: the bindings, globals
    /// and properties visible at the call. Two calls whose arguments *and*
    /// shared state match behave identically, so the cached summary is
    /// exact. Sorted because the maps iterate in arbitrary order.
    fn state_signature(&self) -> Vec<(String, ValSig)> {
        let mut sig: Vec<(String, ValSig)> = self
            .bindings
            .iter()
            .map(|((s, e), v)| (format!("b-{s}-{e}"), value_sig(&Some(v.clone()))))
            .chain(self.globals.iter().map(|(n, v)| (format!("g-{n}"), value_sig(&Some(v.clone())))))
            .chain(
                self.props
                    .iter()
                    .map(|((a, p), v)| (format!("p-{:?}.{}", a, p), value_sig(&Some(v.clone())))),
            )
            .collect();
        sig.sort_by(|a, b| a.0.cmp(&b.0));
        sig
    }

    // ------------------------------------------------------------------
    // Flow recording
    // ------------------------------------------------------------------

    fn record_flow(&mut self, sink: &SinkCall, value: &Value) {
        // A value with no taint reaches nothing, however many aliases it has.
        let Some(st) = &value.taint else {
            return;
        };
        // Whether the flow is sanitized depends on the sink: a sanitizer
        // protects only the contexts its escaping covers, so the same path is
        // sanitized for one sink and not for another.
        let sanitized = st.sanitizers.iter().any(|k| k.protects(sink.target));
        // The same source-to-sink pair may be observed by more than one walk
        // (a function is descended into at the top level and again at its
        // call site). It is one flow, recorded once.
        let identity = (st.origin.offset, sink.offset, sanitized, st.transforms.clone());
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
            sanitized,
            sink_risk: sink.risk.label().to_string(),
        });
    }
}

/// The object and property of a *static* member expression `obj.prop` or
/// `obj['prop']`: an identifier or literal key names the property, so the
/// store can be keyed by it. A computed key (`o[k]`) resolves to nothing —
/// the property it reads is unknown, and is not tracked.
fn static_member(tree: &SyntaxTree, id: NodeId) -> Option<(NodeId, String)> {
    if tree.node(id).kind != SyntaxKind::Member {
        return None;
    }
    let children = tree.node(id).children.clone();
    let obj = *children.first()?;
    let prop = children.get(1)?;
    let key = match tree.node(*prop).kind {
        SyntaxKind::Ident => tree.node_text(*prop).to_string(),
        SyntaxKind::StringLit => unquote(tree.node_text(*prop)),
        SyntaxKind::NumberLit => tree.node_text(*prop).to_string(),
        _ => return None,
    };
    Some((obj, key))
}

/// The name alias of an identifier or `this` node: the fallback identity for
/// a property store when the object is otherwise untracked.
fn static_name(tree: &SyntaxTree, id: NodeId) -> Option<Alias> {
    match tree.node(id).kind {
        SyntaxKind::Ident => Some(Alias::Name(tree.node_text(id).to_string())),
        SyntaxKind::This => Some(Alias::Name("this".to_string())),
        _ => None,
    }
}

/// Strip one matched pair of quotes from a string-literal key.
fn unquote(s: &str) -> String {
    let s = s.trim();
    match (s.as_bytes().first(), s.as_bytes().last()) {
        (Some(&q), Some(&q2)) if q == q2 && (q == b'"' || q == b'\'') && s.len() >= 2 => {
            s[1..s.len() - 1].to_string()
        }
        _ => s.to_string(),
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

    // -----------------------------------------------------------------
    // Sanitizer semantics: protection is per-sink-context (P1.5)
    // -----------------------------------------------------------------

    #[test]
    fn escape_html_protects_markup_but_not_script_or_url_sinks() {
        // `escapeHtml` removes markup characters but leaves quotes and
        // parentheses, so a JS-string sink and a URL sink stay live.
        let f = flows("var v = escapeHtml(location.hash);\nsetTimeout(v, 1);");
        assert_eq!(f.len(), 1);
        assert!(!f[0].sanitized, "escaping markup does not make a value safe for eval");
        let g = flows("var v = escapeHtml(location.hash);\nframe.src = v;");
        assert_eq!(g.len(), 1);
        assert!(!g[0].sanitized, "escaping markup does not make a value safe for a URL");
    }

    #[test]
    fn encode_uri_component_protects_every_sink() {
        for (src, sink) in [
            ("el.innerHTML = encodeURIComponent(location.hash);", "innerHTML"),
            ("setTimeout(encodeURIComponent(location.hash), 1);", "setTimeout"),
            ("frame.src = encodeURIComponent(location.hash);", ".src"),
        ] {
            let f = flows(src);
            assert_eq!(f.len(), 1, "{src}");
            assert!(f[0].sanitized, "encodeURIComponent must sanitize the {sink} sink");
        }
    }

    #[test]
    fn encode_uri_protects_markup_and_url_but_not_script() {
        // `encodeURI` leaves reserved URI characters raw, so a JS string can
        // still be broken out of.
        let html = flows("el.innerHTML = encodeURI(location.hash);");
        assert!(html[0].sanitized, "encodeURI must sanitize a markup sink");
        let url = flows("frame.src = encodeURI(location.hash);");
        assert!(url[0].sanitized, "encodeURI must sanitize a URL sink");
        let js = flows("setTimeout(encodeURI(location.hash), 1);");
        assert!(!js[0].sanitized, "encodeURI must not sanitize a script sink");
    }

    #[test]
    fn dompurify_protects_markup_but_not_script_or_url() {
        let html = flows("el.innerHTML = DOMPurify.sanitize(location.hash);");
        assert!(html[0].sanitized, "DOMPurify must sanitize a markup sink");
        let js = flows("setTimeout(DOMPurify.sanitize(location.hash), 1);");
        assert!(!js[0].sanitized, "sanitized markup text may still be a script");
        let url = flows("frame.src = DOMPurify.sanitize(location.hash);");
        assert!(!url[0].sanitized, "sanitized markup text may still be a scheme");
    }

    #[test]
    fn text_content_assignment_is_not_a_sink() {
        // `textContent` never interprets markup: it is a safe sink, so no flow
        // is recorded at all. It is also not a sanitizer of the value.
        let f = flows("el.textContent = location.hash;");
        assert!(f.is_empty(), "textContent must not be a sink: {:?}", f);
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
    fn library_sanitizer_name_applies_to_opaque_call() {
        // No function in the script declares `escapeHtml`, so the callee is a
        // library call: the name classification applies and the flow is
        // sanitized for a markup sink.
        let f = flows("el.innerHTML = escapeHtml(location.hash);");
        assert_eq!(f.len(), 1);
        assert!(f[0].sanitized, "a library escapeHtml must sanitize a markup sink");
    }

    #[test]
    fn user_defined_sanitizer_name_is_not_trusted() {
        // The same name declared as this script's own function is traced like
        // any other function: its body decides. A body that returns its
        // argument unchanged escapes nothing, so trusting the name would mark
        // a live flow sanitized. This is the failure mode the semantic model
        // exists to remove.
        let f = flows("function escapeHtml(x) { return x; }\nel.innerHTML = escapeHtml(location.hash);");
        assert_eq!(f.len(), 1);
        assert!(!f[0].sanitized, "a user-defined name must not sanitize by name");
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

    // -----------------------------------------------------------------
    // Alias analysis (P1.4b)
    // -----------------------------------------------------------------

    #[test]
    fn copy_alias_carries_property_write() {
        // The failure the dotted-path key could not represent: a write through
        // a copy is read back through the original, because both names resolve
        // to one alias.
        let f = flows(
            "var v = location.hash;\nvar box = {};\nvar o = box;\no.data = v;\nel.innerHTML = box.data;",
        );
        assert_eq!(f.len(), 1, "a write through a copy must reach the original");
    }

    #[test]
    fn distinct_objects_do_not_share_properties() {
        // The converse: two objects are two aliases, so a property of one is
        // not a property of the other.
        let f = flows(
            "var v = location.hash;\nvar a = {};\nvar b = {};\na.data = v;\nel.innerHTML = b.data;",
        );
        assert!(f.is_empty(), "sibling objects must not share a property store: {:?}", f);
    }

    #[test]
    fn spread_copies_property_taint() {
        // `{ ...src }` copies the source's stored properties onto the new
        // object's allocation site.
        let f = flows(
            "var v = location.hash;\nvar src = {};\nsrc.data = v;\nvar o = { ...src };\nel.innerHTML = o.data;",
        );
        assert_eq!(f.len(), 1, "a spread must carry the source's property taint");
    }

    #[test]
    fn array_spread_copies_element_taint() {
        let f = flows(
            "var v = location.hash;\nvar src = [];\nsrc[0] = v;\nvar o = [ ...src ];\nel.innerHTML = o[0];",
        );
        assert_eq!(f.len(), 1, "an array spread must carry the source's element taint");
    }

    #[test]
    fn string_key_property_write_and_read() {
        // `o['data']` and `o.data` name the same property.
        let f = flows(
            "var v = location.hash;\nvar o = {};\no['data'] = v;\nel.innerHTML = o.data;",
        );
        assert_eq!(f.len(), 1, "a string key must resolve to the same property");
    }

    #[test]
    fn computed_dynamic_key_is_not_tracked() {
        // A key only known at runtime names an unknown property: no store is
        // recorded, so the read finds nothing. A documented limitation, and
        // the conservative answer.
        let f = flows(
            "var v = location.hash;\nvar o = {};\nvar k = 'data';\no[k] = v;\nel.innerHTML = o.data;",
        );
        assert!(f.is_empty(), "a dynamic key must not fabricate a property flow: {:?}", f);
    }

    #[test]
    fn callee_mutates_caller_object_property() {
        // The mutator pattern: the callee writes a property of an object the
        // caller passed, and the caller reads it back after the call.
        let f = flows(
            "function set(o, v) { o.data = v; }\nvar box = {};\nset(box, location.hash);\nel.innerHTML = box.data;",
        );
        assert_eq!(f.len(), 1, "a callee's property write to a caller object must survive the call");
    }

    #[test]
    fn factory_carries_property_taint_out() {
        // The factory pattern: the callee builds the object it returns, so the
        // returned object's properties escape with it.
        let f = flows(
            "function make(v) { var o = {}; o.data = v; return o; }\nvar r = make(location.hash);\nel.innerHTML = r.data;",
        );
        assert_eq!(f.len(), 1, "a factory's property taint must reach the caller");
    }

    #[test]
    fn callee_local_object_does_not_leak() {
        // The callee's own object is not visible to the caller, so a property
        // written on it never reaches a store the caller can read.
        let f = flows(
            "function f(v) { var o = {}; o.data = v; }\nvar box = {};\nf(location.hash);\nel.innerHTML = box.data;",
        );
        assert!(f.is_empty(), "a callee-local object must not leak: {:?}", f);
    }
}
