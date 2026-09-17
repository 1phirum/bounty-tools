//! Offset-annotated JavaScript syntax tree.
//!
//! An arena of [`SyntaxNode`]s addressed by [`NodeId`] (a `usize` index).
//! An arena keeps the tree cheap to build and traverse, and lets any node
//! reference any other (parents, siblings, scopes) without lifetime
//! gymnastics — which matters because the scope and data-flow layers walk
//! the tree out of order.
//!
//! Every node carries the byte [`SourceRange`](super::lexer::SourceRange) it
//! was parsed from. Reflection analysis resolves byte offsets, and the AST
//! must answer those same queries, so offsets are structural here, not
//! metadata.

use serde::{Deserialize, Serialize};

use super::lexer::{SourceRange, Token};

/// Index into [`SyntaxTree::nodes`].
pub type NodeId = usize;

/// The kind of a syntax node.
///
/// A deliberately incomplete subset of the JavaScript grammar: it covers the
/// constructs that create bindings, move data, or call sinks — everything
/// the scope graph and the data-flow layer need. Unrecognized input becomes
/// [`SyntaxKind::Raw`], which still carries a range, so a partial tree is
/// always a usable tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyntaxKind {
    // Structure.
    Script,
    // Statements.
    VarDecl,
    /// One declarator inside a `var`/`let`/`const` declaration: the name and
    /// its optional initializer.
    VarDeclarator,
    FunctionDecl,
    /// A `class K { ... }` declaration. The body is parsed coarsely (members
    /// degrade to statements) — enough for scope structure, not for method
    /// semantics, which belong to interprocedural analysis (P1.3).
    ClassDecl,
    Block,
    ExprStmt,
    Return,
    If,
    For,
    While,
    Throw,
    Try,
    Empty,
    /// Unparsed source span (best-effort recovery).
    Raw,

    // Expressions.
    Ident,
    Member,
    Call,
    New,
    Assign,
    Binary,
    Unary,
    Update,
    Conditional,
    Sequence,
    ArrowFn,
    FunctionExpr,
    ArrayLit,
    ObjectLit,
    /// A `key: value` pair inside an object literal.
    Property,
    Spread,
    This,
    Super,

    // Literals.
    StringLit,
    NumberLit,
    RegexLit,
    TemplateLit,
    BoolLit,
    NullLit,
    /// A function parameter.
    Param,
}

impl SyntaxKind {
    /// Whether this node is a declaration that introduces a binding.
    pub fn declares(self) -> bool {
        matches!(
            self,
            SyntaxKind::VarDecl
                | SyntaxKind::FunctionDecl
                | SyntaxKind::ClassDecl
                | SyntaxKind::Param
                | SyntaxKind::VarDeclarator
                | SyntaxKind::FunctionExpr
                | SyntaxKind::ArrowFn
        )
    }

    /// Whether this node is an expression (something that yields a value).
    pub fn is_expression(self) -> bool {
        matches!(
            self,
            SyntaxKind::Ident
                | SyntaxKind::Member
                | SyntaxKind::Call
                | SyntaxKind::New
                | SyntaxKind::Assign
                | SyntaxKind::Binary
                | SyntaxKind::Unary
                | SyntaxKind::Update
                | SyntaxKind::Conditional
                | SyntaxKind::Sequence
                | SyntaxKind::ArrowFn
                | SyntaxKind::FunctionExpr
                | SyntaxKind::ArrayLit
                | SyntaxKind::ObjectLit
                | SyntaxKind::Property
                | SyntaxKind::Spread
                | SyntaxKind::This
                | SyntaxKind::Super
                | SyntaxKind::StringLit
                | SyntaxKind::NumberLit
                | SyntaxKind::RegexLit
                | SyntaxKind::TemplateLit
                | SyntaxKind::BoolLit
                | SyntaxKind::NullLit
        )
    }
}

/// One node in the tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyntaxNode {
    pub id: NodeId,
    pub kind: SyntaxKind,
    pub range: SourceRange,
    /// Child node ids, in source order.
    pub children: Vec<NodeId>,
}

impl SyntaxNode {
    /// The node's source text.
    pub fn text<'a>(&self, source: &'a str) -> &'a str {
        self.range.text(source)
    }

    /// Whether `offset` lands inside this node.
    pub fn contains(&self, offset: usize) -> bool {
        self.range.contains(offset)
    }
}

/// A parsed script: an arena of nodes plus the tokens it was built from.
///
/// The source text is retained (cheaply, in an `Arc`) so node and token text
/// is recoverable without the caller holding the string — the scope and
/// data-flow layers look up names by node id.
#[derive(Debug, Clone)]
pub struct SyntaxTree {
    pub nodes: Vec<SyntaxNode>,
    pub tokens: Vec<Token>,
    pub root: NodeId,
    pub source: std::sync::Arc<str>,
}

impl SyntaxTree {
    pub fn root(&self) -> &SyntaxNode {
        &self.nodes[self.root]
    }

    pub fn node(&self, id: NodeId) -> &SyntaxNode {
        &self.nodes[id]
    }

    /// The source text of a node.
    pub fn node_text(&self, id: NodeId) -> &str {
        self.nodes[id].range.text(&self.source)
    }

    /// The source text of a token.
    pub fn token_text(&self, token: &Token) -> &str {
        token.range.text(&self.source)
    }

    /// The deepest node whose range contains `offset`, preferring leaves.
    ///
    /// This is the query reflection analysis needs: given a byte offset in
    /// the script, what kind of JS construct is it in? The smallest
    /// containing range wins, which naturally selects the leaf.
    pub fn node_at(&self, offset: usize) -> Option<&SyntaxNode> {
        self.nodes
            .iter()
            .filter(|n| n.contains(offset))
            .min_by_key(|n| n.range.end - n.range.start)
    }

    /// The ancestors of `id` from the node itself up to the root.
    pub fn ancestors(&self, id: NodeId) -> Vec<NodeId> {
        let mut path = Vec::new();
        self.ancestors_in(self.root, id, &mut path);
        path
    }

    fn ancestors_in(&self, current: NodeId, target: NodeId, path: &mut Vec<NodeId>) -> bool {
        let node = self.node(current);
        path.push(current);
        if current == target {
            return true;
        }
        for &child in &node.children {
            if self.ancestors_in(child, target, path) {
                return true;
            }
        }
        path.pop();
        false
    }

    /// Every node in source order (pre-order walk).
    pub fn all_nodes(&self) -> Vec<NodeId> {
        let mut out = Vec::with_capacity(self.nodes.len());
        self.collect(self.root, &mut out);
        out
    }

    fn collect(&self, id: NodeId, out: &mut Vec<NodeId>) {
        out.push(id);
        for &child in &self.node(id).children {
            self.collect(child, out);
        }
    }

    /// All descendants of `id` (not including `id`), pre-order.
    pub fn descendants(&self, id: NodeId) -> Vec<NodeId> {
        let mut out = Vec::new();
        for &child in &self.node(id).children {
            self.collect(child, &mut out);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(src: &str, needle: &str) -> NodeId {
        let tree = parse_helper(src);
        let off = src.find(needle).expect("needle");
        tree.node_at(off).expect("node at offset").id
    }

    #[test]
    fn node_at_finds_the_deepest_node() {
        // `location` is an Ident inside a VarDeclarator inside a VarDecl.
        let src = "var v = location.hash;";
        let tree = parse_helper(src);
        let off = src.find("location").unwrap();
        let n = tree.node_at(off).unwrap();
        assert_eq!(n.kind, SyntaxKind::Ident);
        assert_eq!(n.text(src), "location");
    }

    #[test]
    fn node_at_returns_none_outside_source() {
        let tree = parse_helper("var x = 1;");
        assert!(tree.node_at(999).is_none());
    }

    #[test]
    fn ancestors_walk_to_the_root() {
        let src = "var v = location.hash;";
        let tree = parse_helper(src);
        let id = node(src, "location");
        let chain = tree.ancestors(id);
        // The chain runs from the root down to the node itself.
        assert_eq!(chain.first().copied(), Some(tree.root));
        assert_eq!(chain.last().copied(), Some(id));
        assert!(chain.len() >= 3);
    }

    #[test]
    fn ranges_are_source_text() {
        let src = "var v = location.hash;";
        let tree = parse_helper(src);
        let id = node(src, "hash");
        assert_eq!(tree.node(id).text(src), "hash");
    }

    fn parse_helper(src: &str) -> SyntaxTree {
        super::super::parser::parse_script(src)
    }
}
