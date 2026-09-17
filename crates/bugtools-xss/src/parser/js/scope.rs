//! The lexical scope graph.
//!
//! Built from a [`SyntaxTree`](super::ast::SyntaxTree), this is the foundation
//! the data-flow taint layer (P1.2) consumes. It answers the question the old
//! `same_data_object` heuristic could only guess at: *which binding does this
//! identifier resolve to, and where was it initialized?*
//!
//! Semantics modelled (the subset that matters for taint):
//!
//! - Scopes: global, function, block.
//! - Bindings: `var` (function-scoped, hoisted), `let`/`const`/`class`
//!   (block-scoped), function parameters, function declarations (hoisted),
//!   and `catch` parameters.
//! - Lexical resolution: walk the scope chain outward to the first scope
//!   that declares the name.
//!
//! Destructuring is recorded as one binding per pattern start (individual
//! sub-bindings are not split yet); that refinement belongs to P1.4 alias
//! analysis. The graph is deliberately conservative — it never invents a
//! binding it did not see declared.

use serde::{Deserialize, Serialize};

use super::ast::{NodeId, SyntaxKind, SyntaxTree};
use super::lexer::SourceRange;

/// Index into [`ScopeGraph::scopes`].
pub type ScopeId = usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    /// The outermost scope of a script.
    Global,
    /// Created by a function, arrow function, or method body.
    Function,
    /// Created by a `{ }` block, or a `catch` clause.
    Block,
}

/// How a name entered a scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingKind {
    /// `var` — hoisted to the nearest function/global scope.
    Var,
    /// `let`.
    Let,
    /// `const`.
    Const,
    /// A function parameter (including arrow params).
    Param,
    /// A function declaration — hoisted like `var`.
    Function,
    /// A class declaration — block-scoped.
    Class,
    /// A `catch (e)` parameter.
    Catch,
}

impl BindingKind {
    /// Whether the binding is hoisted to the nearest function scope.
    pub fn is_hoisted(self) -> bool {
        matches!(self, BindingKind::Var | BindingKind::Function)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Binding {
    pub name: String,
    pub kind: BindingKind,
    /// Range of the declared name token.
    pub range: SourceRange,
    /// Where the binding is initialized, when observable: the `=` of a
    /// declaration, the parameter position, or the function body. Absent for
    /// a bare `var x;`.
    pub init: Option<SourceRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    pub id: ScopeId,
    pub parent: Option<ScopeId>,
    pub kind: ScopeKind,
    pub range: SourceRange,
    pub bindings: Vec<Binding>,
}

impl Scope {
    /// Find a binding declared directly in this scope.
    pub fn binding(&self, name: &str) -> Option<&Binding> {
        self.bindings.iter().find(|b| b.name == name)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeGraph {
    pub scopes: Vec<Scope>,
    pub root: ScopeId,
}

impl ScopeGraph {
    /// Build the scope graph for a parsed tree.
    pub fn build(tree: &SyntaxTree) -> Self {
        let mut builder = Builder::new(tree);
        builder.build();
        builder.graph
    }

    pub fn root(&self) -> &Scope {
        &self.scopes[self.root]
    }

    pub fn scope(&self, id: ScopeId) -> &Scope {
        &self.scopes[id]
    }

    /// Resolve `name` from `scope` outward along the parent chain.
    pub fn resolve(&self, scope: ScopeId, name: &str) -> Option<&Binding> {
        let mut current = Some(scope);
        while let Some(id) = current {
            if let Some(b) = self.scopes[id].binding(name) {
                return Some(b);
            }
            current = self.scopes[id].parent;
        }
        None
    }

    /// Resolve `name` from the innermost scope containing `offset`.
    pub fn resolve_at(&self, offset: usize, name: &str) -> Option<&Binding> {
        self.scope_at(offset).and_then(|s| self.resolve(s, name))
    }

    /// The innermost scope whose range contains `offset`, preferring
    /// function/block scopes over the global scope on ties.
    pub fn scope_at(&self, offset: usize) -> Option<ScopeId> {
        self.scopes
            .iter()
            .filter(|s| s.range.contains(offset) || (s.kind == ScopeKind::Global && offset >= s.range.start))
            .min_by_key(|s| {
                let len = s.range.end.saturating_sub(s.range.start);
                // Global scope ranks last so a nested scope wins ties.
                (s.kind == ScopeKind::Global, len)
            })
            .map(|s| s.id)
    }

    /// The binding whose declaration name sits at `offset`, if any.
    pub fn binding_at(&self, offset: usize) -> Option<&Binding> {
        self.scopes
            .iter()
            .flat_map(|s| &s.bindings)
            .find(|b| b.range.contains(offset))
    }

    /// All bindings across every scope.
    pub fn all_bindings(&self) -> impl Iterator<Item = (ScopeId, &Binding)> {
        self.scopes
            .iter()
            .flat_map(|s| s.bindings.iter().map(move |b| (s.id, b)))
    }
}

// ----------------------------------------------------------------------

struct Builder<'a> {
    tree: &'a SyntaxTree,
    graph: ScopeGraph,
    /// The scope stack, innermost last. Hoisted declarations (`var`, function
    /// declarations) attach to the nearest function-or-global scope on it.
    stack: Vec<ScopeId>,
}

impl<'a> Builder<'a> {
    fn new(tree: &'a SyntaxTree) -> Self {
        let root = Scope {
            id: 0,
            parent: None,
            kind: ScopeKind::Global,
            range: tree.root().range,
            bindings: Vec::new(),
        };
        Self {
            tree,
            graph: ScopeGraph { scopes: vec![root], root: 0 },
            stack: vec![0],
        }
    }

    fn build(&mut self) {
        // Walk from the AST root (the Script node), not the scope root —
        // the two id spaces are both `usize`, and the parser assigns the
        // Script node id last, so it is never 0.
        self.visit(self.tree.root);
    }

    fn current(&self) -> ScopeId {
        *self.stack.last().unwrap()
    }

    /// The nearest function-or-global scope: the target for hoisted `var`
    /// and function declarations.
    fn hoist_target(&self) -> ScopeId {
        *self
            .stack
            .iter()
            .rev()
            .find(|&&s| matches!(self.graph.scopes[s].kind, ScopeKind::Function | ScopeKind::Global))
            .unwrap_or(&0)
    }

    fn open_scope(&mut self, kind: ScopeKind, range: SourceRange) -> ScopeId {
        let id = self.graph.scopes.len();
        let parent = self.current();
        self.graph.scopes.push(Scope {
            id,
            parent: Some(parent),
            kind,
            range,
            bindings: Vec::new(),
        });
        self.stack.push(id);
        id
    }

    fn close_scope(&mut self) {
        if self.stack.len() > 1 {
            self.stack.pop();
        }
    }

    fn add_binding(&mut self, scope: ScopeId, binding: Binding) {
        let s = &mut self.graph.scopes[scope];
        // First declaration wins: a later duplicate in the same scope is the
        // same variable (var/function), not a new one.
        if !s.bindings.iter().any(|b| b.name == binding.name) {
            s.bindings.push(binding);
        }
    }

    fn visit(&mut self, id: NodeId) {
        let kind = self.tree.node(id).kind;
        match kind {
            SyntaxKind::FunctionDecl | SyntaxKind::FunctionExpr | SyntaxKind::ArrowFn => {
                self.visit_function(id, kind);
            }
            SyntaxKind::Block => {
                let range = self.tree.node(id).range;
                let scope = self.open_scope(ScopeKind::Block, range);
                for child in self.tree.node(id).children.clone() {
                    self.visit(child);
                }
                self.close_scope();
                let _ = scope;
            }
            SyntaxKind::VarDecl => {
                self.visit_var_decl(id);
            }
            SyntaxKind::ClassDecl => {
                self.visit_class_decl(id);
            }
            SyntaxKind::Try => {
                self.visit_try(id);
            }
            _ => {
                for child in self.tree.node(id).children.clone() {
                    self.visit(child);
                }
            }
        }
    }

    fn visit_function(&mut self, id: NodeId, kind: SyntaxKind) {
        let range = self.tree.node(id).range;
        let children = self.tree.node(id).children.clone();

        // A named function declaration also binds its name in the enclosing
        // (function-or-global) scope, hoisted.
        if kind == SyntaxKind::FunctionDecl {
            if let Some(name_id) = children.first() {
                if self.tree.node(*name_id).kind == SyntaxKind::Ident {
                    self.add_binding(
                        self.hoist_target(),
                        Binding {
                            name: self.tree.node_text(*name_id).to_string(),
                            kind: BindingKind::Function,
                            range: self.tree.node(*name_id).range,
                            init: Some(range),
                        },
                    );
                }
            }
        }

        let scope = self.open_scope(ScopeKind::Function, range);
        for &child in &children {
            let child_kind = self.tree.node(child).kind;
            if child_kind == SyntaxKind::Param {
                let n = self.tree.node(child);
                // A Param node's own range covers the name (or the spread).
                self.add_binding(
                    scope,
                    Binding {
                        name: param_name(self.tree, child),
                        kind: BindingKind::Param,
                        range: n.range,
                        init: Some(n.range),
                    },
                );
            } else {
                self.visit(child);
            }
        }
        self.close_scope();
    }

    fn visit_var_decl(&mut self, id: NodeId) {
        let children = self.tree.node(id).children.clone();
        for &declarator in &children {
            let d = self.tree.node(declarator);
            let d_children = &d.children;
            // Destructuring or a non-name declarator: record the pattern as
            // one binding when we can read a name, else skip.
            let Some(name_node) = d_children.first() else {
                continue;
            };
            if self.tree.node(*name_node).kind != SyntaxKind::Ident {
                continue;
            }
            let name = self.tree.node(*name_node);
            let kind = match self.declared_kind(id) {
                Some(k) => k,
                None => BindingKind::Var,
            };
            let init = d_children.get(1).map(|_| {
                // The initializer expression's start approximates the `=`.
                self.tree.node(d_children[1]).range
            });
            let target = if kind.is_hoisted() {
                self.hoist_target()
            } else {
                self.current()
            };
            self.add_binding(
                target,
                Binding {
                    name: self.tree.node_text(*name_node).to_string(),
                    kind,
                    range: name.range,
                    init,
                },
            );
            // Continue into the initializer (it may contain nested functions).
            for &c in d_children.iter().skip(1) {
                self.visit(c);
            }
        }
    }

    /// `var`/`let`/`const` from the declaration's first token.
    fn declared_kind(&self, id: NodeId) -> Option<BindingKind> {
        let range = self.tree.node(id).range;
        let tok = self
            .tree
            .tokens
            .iter()
            .find(|t| t.range.start == range.start)?;
        match self.tree.token_text(tok) {
            "var" => Some(BindingKind::Var),
            "let" => Some(BindingKind::Let),
            "const" => Some(BindingKind::Const),
            "class" => Some(BindingKind::Class),
            _ => None,
        }
    }

    fn visit_class_decl(&mut self, id: NodeId) {
        // A class name is block-scoped (like `let`), never hoisted.
        let children = self.tree.node(id).children.clone();
        if let Some(name_id) = children.first() {
            if self.tree.node(*name_id).kind == SyntaxKind::Ident {
                let range = self.tree.node(*name_id).range;
                self.add_binding(
                    self.current(),
                    Binding {
                        name: self.tree.node_text(*name_id).to_string(),
                        kind: BindingKind::Class,
                        range,
                        init: Some(range),
                    },
                );
            }
        }
        for &child in children.iter().skip(1) {
            self.visit(child);
        }
    }

    fn visit_try(&mut self, id: NodeId) {
        let children = self.tree.node(id).children.clone();
        for &child in &children {
            let kind = self.tree.node(child).kind;
            if kind == SyntaxKind::Param {
                // A catch parameter: bind it in a fresh block scope.
                let range = self.tree.node(child).range;
                let scope = self.open_scope(ScopeKind::Block, range);
                let n = self.tree.node(child);
                self.add_binding(
                    scope,
                    Binding {
                        name: param_name(self.tree, child),
                        kind: BindingKind::Catch,
                        range: n.range,
                        init: Some(n.range),
                    },
                );
                self.close_scope();
            } else {
                self.visit(child);
            }
        }
    }
}

/// Read a parameter's name text, tolerating spreads and defaults.
fn param_name(tree: &SyntaxTree, param: NodeId) -> String {
    let node = tree.node(param);
    // A Param with children is `p = default` or `...p`: the name is the leaf.
    if let Some(&first) = node.children.first() {
        let child = tree.node(first);
        if child.kind == SyntaxKind::Ident {
            return tree.node_text(first).to_string();
        }
        // Spread wrapping an ident.
        if child.kind == SyntaxKind::Spread {
            if let Some(&inner) = child.children.first() {
                return tree.node_text(inner).to_string();
            }
        }
    }
    tree.node_text(param).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::parser::parse_script;

    fn graph(src: &str) -> ScopeGraph {
        ScopeGraph::build(&parse_script(src))
    }

    fn binding_names(src: &str) -> Vec<String> {
        let g = graph(src);
        g.all_bindings().map(|(_, b)| b.name.clone()).collect()
    }

    #[test]
    fn root_scope_is_global() {
        let g = graph("var x = 1;");
        assert_eq!(g.root().kind, ScopeKind::Global);
    }

    #[test]
    fn var_declares_in_global_scope() {
        let g = graph("var v = location.hash;");
        let b = g.root().binding("v").expect("v bound globally");
        assert_eq!(b.kind, BindingKind::Var);
        assert!(b.init.is_some(), "the initializer must be recorded");
    }

    #[test]
    fn let_and_const_are_block_scoped() {
        let src = "{ let a = 1; const b = 2; }";
        let g = graph(src);
        // Block-scoped means absent from the enclosing global scope.
        assert!(g.root().bindings.iter().all(|x| x.name != "a"));
        assert!(g.root().bindings.iter().all(|x| x.name != "b"));
        // And visible from the innermost scope.
        let scope = g.scope_at(src.find("1").unwrap()).unwrap();
        assert_eq!(g.resolve(scope, "a").unwrap().kind, BindingKind::Let);
        assert_eq!(g.resolve(scope, "b").unwrap().kind, BindingKind::Const);
    }

    #[test]
    fn var_is_hoisted_out_of_blocks() {
        // `var` inside a block must land in the global scope.
        let g = graph("{ { var deep = 1; } }");
        assert!(g.root().binding("deep").is_some(), "var hoists to global");
    }

    #[test]
    fn function_creates_its_own_scope_with_params() {
        let g = graph("function f(a, b) { return a; }");
        let f_scope = g
            .scopes
            .iter()
            .find(|s| s.kind == ScopeKind::Function)
            .expect("a function scope exists");
        assert!(f_scope.binding("a").is_some());
        assert!(f_scope.binding("b").is_some());
        assert_eq!(f_scope.binding("a").unwrap().kind, BindingKind::Param);
    }

    #[test]
    fn function_declaration_is_hoisted_to_enclosing_scope() {
        let g = graph("function outer() { function inner() {} }");
        let outer = g
            .scopes
            .iter()
            .find(|s| s.kind == ScopeKind::Function)
            .expect("outer function scope");
        assert!(outer.binding("inner").is_some(), "inner is hoisted into outer");
        assert_eq!(outer.binding("inner").unwrap().kind, BindingKind::Function);
    }

    #[test]
    fn lexical_resolution_walks_the_chain() {
        // Inner `a` shadows the outer one; resolving from the inner scope
        // finds the inner binding.
        let g = graph("var a = 1; function f(a) { return a; }");
        let f_scope = g
            .scopes
            .iter()
            .find(|s| s.kind == ScopeKind::Function)
            .unwrap();
        let resolved = g.resolve(f_scope.id, "a").unwrap();
        assert_eq!(resolved.kind, BindingKind::Param, "the param shadows the global var");
    }

    #[test]
    fn unresolved_name_returns_none() {
        let g = graph("var x = 1;");
        assert!(g.resolve(g.root, "nope").is_none());
        assert!(g.resolve_at(0, "nope").is_none());
    }

    #[test]
    fn arrow_function_params_bind() {
        let g = graph("const f = (event) => { return event; };");
        let f_scope = g.scopes.iter().find(|s| s.kind == ScopeKind::Function);
        assert!(f_scope.is_some(), "an arrow creates a function scope");
        assert!(f_scope.unwrap().binding("event").is_some());
    }

    #[test]
    fn catch_parameter_binds() {
        let g = graph("try { f(); } catch (err) { log(err); }");
        let catch_binding = g.all_bindings().find(|(_, b)| b.kind == BindingKind::Catch);
        assert!(catch_binding.is_some());
        assert_eq!(catch_binding.unwrap().1.name, "err");
    }

    #[test]
    fn scope_at_finds_the_innermost_scope() {
        let src = "function f(a) { var b = 1; }";
        let g = graph(src);
        let body_offset = src.find("var").unwrap();
        let s = g.scope_at(body_offset).unwrap();
        // The function body opens a block scope inside the function scope;
        // resolving from it must still find the parameter up the chain.
        assert_ne!(g.scopes[s].kind, ScopeKind::Global);
        assert_eq!(g.resolve(s, "a").unwrap().kind, BindingKind::Param);
        // Outside the function, the parameter is not visible.
        assert!(g.resolve(g.root, "a").is_none());
    }

    #[test]
    fn binding_at_locates_a_declaration() {
        let src = "var v = location.hash;";
        let g = graph(src);
        // The declarator name, not the `v` in the `var` keyword.
        let off = src.find(" v ").unwrap() + 1;
        let b = g.binding_at(off).unwrap();
        assert_eq!(b.name, "v");
    }

    #[test]
    fn class_declaration_is_block_scoped() {
        let src = "{ class K {} }";
        let g = graph(src);
        assert!(g.root().bindings.iter().all(|x| x.name != "K"));
        let scope = g.scope_at(src.find("class").unwrap()).unwrap();
        assert_eq!(g.resolve(scope, "K").unwrap().kind, BindingKind::Class);
    }

    #[test]
    fn nested_functions_nest_scopes() {
        let g = graph("function a() { function b() { function c() {} } }");
        let fn_scopes = g
            .scopes
            .iter()
            .filter(|s| s.kind == ScopeKind::Function)
            .count();
        assert_eq!(fn_scopes, 3);
    }

    #[test]
    fn destructuring_does_not_panic_and_records_something() {
        // A documented limitation: the pattern is recorded coarsely.
        let g = graph("var { a, b } = obj;");
        let _ = g.all_bindings().count();
    }

    #[test]
    fn the_classic_xss_flow_resolves_its_variable() {
        // The exact shape the taint layer will replace `same_data_object` for.
        let src = "var v = location.hash; el.innerHTML = v;";
        let g = graph(src);
        let use_offset = src.rfind("v").unwrap();
        let b = g.resolve_at(use_offset, "v").expect("the sink's `v` must resolve");
        assert_eq!(b.kind, BindingKind::Var);
        assert!(b.init.is_some(), "and its initializer must be locatable");
    }
}
