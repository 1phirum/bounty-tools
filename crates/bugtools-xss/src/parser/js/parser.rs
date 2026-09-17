//! Best-effort recursive-descent parser: token stream → [`SyntaxTree`].
//!
//! Design constraints (see the architecture audit, §10 migration risks):
//!
//! - **Offsets are structural.** Every node carries the byte range it was
//!   parsed from, because reflection analysis resolves byte offsets and the
//!   AST must answer those same queries. Leaves map 1:1 to tokens.
//! - **The parser is total.** Real inline scripts are frequently malformed
//!   or use syntax this subset does not cover. Unrecognized input degrades
//!   to [`SyntaxKind::Raw`] nodes that still carry a range, so a partial tree
//!   is always a usable tree and [`SyntaxTree::node_at`] always has an
//!   answer. The driver loop guarantees forward progress.
//! - **The grammar is a deliberately incomplete subset** covering the
//!   constructs that create bindings, move data, or call sinks.
//!
//! The old token-scan context resolution remains available as a fallback, so
//! an AST miss degrades to the previous behaviour rather than to nothing.

use super::ast::{NodeId, SyntaxKind, SyntaxNode, SyntaxTree};
use super::lexer::{lex, Cursor, SourceRange, Token, TokenKind};

/// Parse a script source into a syntax tree. Always succeeds.
pub fn parse_script(source: &str) -> SyntaxTree {
    let tokens = lex(source);
    let mut parser = Parser::new(source, &tokens);
    let root = parser.parse_program();
    let nodes = parser.finish();
    SyntaxTree {
        nodes,
        tokens,
        root,
        source: std::sync::Arc::from(source),
    }
}

struct Parser<'a> {
    source: &'a str,
    cur: Cursor<'a>,
    nodes: Vec<SyntaxNode>,
}

impl<'a> Parser<'a> {
    fn new(source: &'a str, tokens: &'a [Token]) -> Self {
        Self {
            source,
            cur: Cursor::new(source, tokens),
            nodes: Vec::new(),
        }
    }

    fn finish(self) -> Vec<SyntaxNode> {
        self.nodes
    }

    fn push(&mut self, kind: SyntaxKind, children: Vec<NodeId>, range: SourceRange) -> NodeId {
        let id = self.nodes.len();
        self.nodes.push(SyntaxNode { id, kind, range, children });
        id
    }

    /// Union range of several node ids; for the empty case the current token.
    fn span(&self, ids: &[NodeId]) -> SourceRange {
        if ids.is_empty() {
            return self.cur.peek().range;
        }
        let start = ids.iter().map(|&i| self.nodes[i].range.start).min().unwrap();
        let end = ids.iter().map(|&i| self.nodes[i].range.end).max().unwrap();
        SourceRange { start, end }
    }

    fn span2(&self, a: NodeId, b: NodeId) -> SourceRange {
        let ra = self.nodes[a].range;
        let rb = self.nodes[b].range;
        SourceRange { start: ra.start.min(rb.start), end: ra.end.max(rb.end) }
    }

    // ------------------------------------------------------------------
    // Program / statements
    // ------------------------------------------------------------------

    fn parse_program(&mut self) -> NodeId {
        let start = self.cur.peek().range.start;
        let mut statements = Vec::new();
        while !self.cur.at_eof() {
            let before = self.cur.pos;
            if let Some(id) = self.parse_statement() {
                statements.push(id);
            } else {
                // Nothing parsed (e.g. a stray `}`): record one raw token so
                // the offset is still represented, and advance.
                let t = self.cur.bump();
                let id = self.push(SyntaxKind::Raw, vec![], t.range);
                statements.push(id);
            }
            if self.cur.pos == before {
                // Guarantee forward progress under any recovery path.
                self.cur.bump();
            }
        }
        let end = self.source.len().max(start);
        self.push(SyntaxKind::Script, statements, SourceRange { start, end })
    }

    fn parse_statement(&mut self) -> Option<NodeId> {
        let t = self.cur.peek();
        let text = t.text(self.source);
        match (t.kind, text) {
            (TokenKind::Keyword, "function") => Some(self.parse_function_decl()),
            (TokenKind::Keyword, "class") => Some(self.parse_class_decl()),
            (TokenKind::Keyword, "var" | "let" | "const") => Some(self.parse_var_decl(true)),
            (TokenKind::Punct, "{") => Some(self.parse_block()),
            (TokenKind::Punct, ";") => {
                let range = self.cur.bump().range;
                Some(self.push(SyntaxKind::Empty, vec![], range))
            }
            (TokenKind::Keyword, "return") => Some(self.parse_return()),
            (TokenKind::Keyword, "if") => Some(self.parse_if()),
            (TokenKind::Keyword, "for") => Some(self.parse_for()),
            (TokenKind::Keyword, "while") => Some(self.parse_while()),
            (TokenKind::Keyword, "throw") => Some(self.parse_throw()),
            (TokenKind::Keyword, "try") => Some(self.parse_try()),
            // A `}` here ends an enclosing block; the caller handles it.
            (TokenKind::Punct, "}") => None,
            _ => Some(self.parse_expr_statement()),
        }
    }

    /// Parse a statement, or a Raw node if the statement parser declines.
    fn parse_statement_or_raw(&mut self) -> NodeId {
        if let Some(id) = self.parse_statement() {
            return id;
        }
        let t = self.cur.bump();
        self.push(SyntaxKind::Raw, vec![], t.range)
    }

    fn parse_function_decl(&mut self) -> NodeId {
        let start = self.cur.bump().range.start; // function
        let mut children = Vec::new();
        if self.cur.at_name() {
            let t = self.cur.bump();
            children.push(self.push(SyntaxKind::Ident, vec![], t.range));
        }
        if self.cur.at_punct("(") {
            children.extend(self.parse_params());
        }
        if self.cur.at_punct("{") {
            children.push(self.parse_block());
        }
        let end = self.span(&children).end.max(start);
        self.push(SyntaxKind::FunctionDecl, children, SourceRange { start, end })
    }

    fn parse_class_decl(&mut self) -> NodeId {
        let start = self.cur.bump().range.start; // class
        let mut children = Vec::new();
        if self.cur.at_name() {
            let t = self.cur.bump();
            children.push(self.push(SyntaxKind::Ident, vec![], t.range));
        }
        // `class K extends Base { ... }`
        if self.cur.at_kw("extends") {
            self.cur.bump();
            if let Some(base) = self.parse_postfix() {
                children.push(base);
            }
        }
        if self.cur.at_punct("{") {
            children.push(self.parse_block());
        }
        let end = self.span(&children).end.max(start);
        self.push(SyntaxKind::ClassDecl, children, SourceRange { start, end })
    }

    fn parse_function_expr(&mut self) -> NodeId {
        let start = self.cur.bump().range.start; // function
        let mut children = Vec::new();
        if self.cur.at_name() {
            let t = self.cur.bump();
            children.push(self.push(SyntaxKind::Ident, vec![], t.range));
        }
        if self.cur.at_punct("(") {
            children.extend(self.parse_params());
        }
        if self.cur.at_punct("{") {
            children.push(self.parse_block());
        }
        let end = self.span(&children).end.max(start);
        self.push(SyntaxKind::FunctionExpr, children, SourceRange { start, end })
    }

    /// `(` p1, p2 = d, ...rest )` — parameters as [`SyntaxKind::Param`] nodes
    /// (or a destructuring literal, whose individual bindings the scope layer
    /// does not yet split — a documented limitation).
    fn parse_params(&mut self) -> Vec<NodeId> {
        if !self.cur.at_punct("(") {
            return vec![];
        }
        self.cur.bump(); // (
        let mut params = Vec::new();
        while !self.cur.at_punct(")") && !self.cur.at_eof() {
            if self.cur.eat(TokenKind::Punct, ",") {
                continue;
            }
            if let Some(p) = self.parse_param() {
                params.push(p);
            } else {
                self.cur.bump(); // recovery
            }
        }
        self.cur.eat(TokenKind::Punct, ")");
        params
    }

    fn parse_param(&mut self) -> Option<NodeId> {
        if self.cur.at_op("...") {
            let spread_start = self.cur.bump().range.start;
            let inner = self.parse_param_name()?;
            let range = SourceRange { start: spread_start, end: self.nodes[inner].range.end };
            return Some(self.push(SyntaxKind::Spread, vec![inner], range));
        }
        let name = self.parse_param_name()?;
        // Default value: `p = expr`.
        if self.cur.at_op("=") {
            self.cur.bump();
            if let Some(default) = self.parse_assignment() {
                let range = self.span2(name, default);
                return Some(self.push(SyntaxKind::Param, vec![name, default], range));
            }
        }
        Some(name)
    }

    fn parse_param_name(&mut self) -> Option<NodeId> {
        if self.cur.at_name() {
            let t = self.cur.bump();
            return Some(self.push(SyntaxKind::Param, vec![], t.range));
        }
        // Destructuring parameter: parse the literal and use it as the param.
        if self.cur.at_punct("{") {
            return self.parse_object_lit();
        }
        if self.cur.at_punct("[") {
            return self.parse_array_lit();
        }
        None
    }

    /// `var a = 1, b;` — [`SyntaxKind::VarDecl`] with one
    /// [`SyntaxKind::VarDeclarator`] per target. Destructuring targets are
    /// recorded as object/array literals (their individual sub-bindings are
    /// not split into bindings yet — that refinement belongs to P1.4), so the
    /// pattern is still present in the tree instead of being silently
    /// dropped.
    fn parse_var_decl(&mut self, statement: bool) -> NodeId {
        let start = self.cur.bump().range.start; // var | let | const
        let mut declarators = Vec::new();
        loop {
            let target = if self.cur.at_punct("{") {
                self.parse_object_lit()
            } else if self.cur.at_punct("[") {
                self.parse_array_lit()
            } else if self.cur.at_name() {
                let t = self.cur.bump();
                Some(self.push(SyntaxKind::Ident, vec![], t.range))
            } else {
                None
            };
            let Some(target) = target else { break };
            let mut children = vec![target];
            if self.cur.at_op("=") {
                self.cur.bump();
                if let Some(init) = self.parse_assignment() {
                    children.push(init);
                }
            }
            let range = self.span(&children);
            declarators.push(self.push(SyntaxKind::VarDeclarator, children, range));
            if !self.cur.eat(TokenKind::Punct, ",") {
                break;
            }
        }
        // A `;` is optional (ASI); consume it when present.
        if statement {
            self.cur.eat(TokenKind::Punct, ";");
        }
        let end = self.span(&declarators).end.max(start);
        self.push(SyntaxKind::VarDecl, declarators, SourceRange { start, end })
    }

    fn parse_block(&mut self) -> NodeId {
        if !self.cur.at_punct("{") {
            return self.push(SyntaxKind::Block, vec![], self.cur.peek().range);
        }
        let start = self.cur.bump().range.start;
        let mut statements = Vec::new();
        while !self.cur.at_punct("}") && !self.cur.at_eof() {
            let before = self.cur.pos;
            if let Some(id) = self.parse_statement() {
                statements.push(id);
            } else {
                let t = self.cur.bump();
                statements.push(self.push(SyntaxKind::Raw, vec![], t.range));
            }
            if self.cur.pos == before {
                self.cur.bump();
            }
        }
        let end = if self.cur.at_punct("}") {
            self.cur.bump().range.end
        } else {
            self.source.len()
        };
        self.push(SyntaxKind::Block, statements, SourceRange { start, end })
    }

    fn parse_return(&mut self) -> NodeId {
        let start = self.cur.bump().range.start; // return
        let mut children = Vec::new();
        // ASI: `return\n` with no value, or `return;` / `return}`.
        let t = self.cur.peek();
        if !matches!(t.kind, TokenKind::Punct) || !matches!(t.text(self.source), ";" | "}") {
            if !self.cur.at_eof() {
                if let Some(e) = self.parse_expression() {
                    children.push(e);
                }
            }
        }
        self.cur.eat(TokenKind::Punct, ";");
        let end = self.span(&children).end.max(start);
        self.push(SyntaxKind::Return, children, SourceRange { start, end })
    }

    fn parse_if(&mut self) -> NodeId {
        let start = self.cur.bump().range.start; // if
        let mut children = Vec::new();
        if self.cur.eat(TokenKind::Punct, "(") {
            if let Some(c) = self.parse_expression() {
                children.push(c);
            }
            self.skip_to_close_paren();
        }
        children.push(self.parse_statement_or_raw());
        if self.cur.at_kw("else") {
            self.cur.bump();
            children.push(self.parse_statement_or_raw());
        }
        let end = self.span(&children).end.max(start);
        self.push(SyntaxKind::If, children, SourceRange { start, end })
    }

    fn parse_while(&mut self) -> NodeId {
        let start = self.cur.bump().range.start; // while
        let mut children = Vec::new();
        if self.cur.eat(TokenKind::Punct, "(") {
            if let Some(c) = self.parse_expression() {
                children.push(c);
            }
            self.skip_to_close_paren();
        }
        children.push(self.parse_statement_or_raw());
        let end = self.span(&children).end.max(start);
        self.push(SyntaxKind::While, children, SourceRange { start, end })
    }

    fn parse_for(&mut self) -> NodeId {
        let start = self.cur.bump().range.start; // for
        let mut children = Vec::new();
        if self.cur.eat(TokenKind::Punct, "(") {
            // Optional declaration, then the condition/update sections.
            if self.cur.at_kw("var") || self.cur.at_kw("let") || self.cur.at_kw("const") {
                children.push(self.parse_var_decl(false));
            }
            while !self.cur.at_punct(")") && !self.cur.at_eof() {
                if self.cur.eat(TokenKind::Punct, ";") {
                    continue;
                }
                match self.parse_expression() {
                    Some(e) => children.push(e),
                    None => {
                        self.cur.bump();
                    }
                }
            }
            self.cur.eat(TokenKind::Punct, ")");
        }
        children.push(self.parse_statement_or_raw());
        let end = self.span(&children).end.max(start);
        self.push(SyntaxKind::For, children, SourceRange { start, end })
    }

    fn parse_throw(&mut self) -> NodeId {
        let start = self.cur.bump().range.start; // throw
        let mut children = Vec::new();
        if let Some(e) = self.parse_expression() {
            children.push(e);
        }
        self.cur.eat(TokenKind::Punct, ";");
        let end = self.span(&children).end.max(start);
        self.push(SyntaxKind::Throw, children, SourceRange { start, end })
    }

    fn parse_try(&mut self) -> NodeId {
        let start = self.cur.bump().range.start; // try
        let mut children = Vec::new();
        if self.cur.at_punct("{") {
            children.push(self.parse_block());
        }
        if self.cur.at_kw("catch") {
            self.cur.bump();
            if self.cur.eat(TokenKind::Punct, "(") {
                if let Some(p) = self.parse_param() {
                    children.push(p);
                }
                self.skip_to_close_paren();
            }
            if self.cur.at_punct("{") {
                children.push(self.parse_block());
            }
        }
        if self.cur.at_kw("finally") {
            self.cur.bump();
            if self.cur.at_punct("{") {
                children.push(self.parse_block());
            }
        }
        let end = self.span(&children).end.max(start);
        self.push(SyntaxKind::Try, children, SourceRange { start, end })
    }

    fn parse_expr_statement(&mut self) -> NodeId {
        let start = self.cur.peek().range.start;
        let mut children = Vec::new();
        if let Some(e) = self.parse_expression() {
            children.push(e);
        } else {
            // Not even an expression: record the token raw and move on.
            let t = self.cur.bump();
            children.push(self.push(SyntaxKind::Raw, vec![], t.range));
        }
        self.cur.eat(TokenKind::Punct, ";");
        let end = self.span(&children).end.max(start);
        self.push(SyntaxKind::ExprStmt, children, SourceRange { start, end })
    }

    /// Consume tokens up to the matching `)` at paren depth zero. Used for
    /// headers whose contents this subset does not fully model.
    fn skip_to_close_paren(&mut self) {
        let mut depth = 0i32;
        while !self.cur.at_eof() {
            let t = self.cur.peek();
            match t.text(self.source) {
                "(" => depth += 1,
                ")" if depth == 0 => {
                    self.cur.bump();
                    return;
                }
                ")" => depth -= 1,
                _ => {}
            }
            self.cur.bump();
        }
    }

    // ------------------------------------------------------------------
    // Expressions
    // ------------------------------------------------------------------

    fn parse_expression(&mut self) -> Option<NodeId> {
        self.parse_assignment()
    }

    fn parse_assignment(&mut self) -> Option<NodeId> {
        if let Some(arrow) = self.try_parse_arrow() {
            return Some(arrow);
        }
        let lhs = self.parse_conditional()?;
        if is_assign_op(self.cur.peek(), self.source) {
            self.cur.bump();
            let rhs = self.parse_assignment()?;
            let range = self.span2(lhs, rhs);
            return Some(self.push(SyntaxKind::Assign, vec![lhs, rhs], range));
        }
        Some(lhs)
    }

    fn parse_conditional(&mut self) -> Option<NodeId> {
        let cond = self.parse_binary(0)?;
        if self.cur.at_op("?") {
            self.cur.bump();
            let then = self.parse_assignment();
            self.cur.eat(TokenKind::Punct, ":");
            let else_ = self.parse_assignment();
            let mut children = vec![cond];
            children.extend(then);
            children.extend(else_);
            let range = self.span(&children);
            return Some(self.push(SyntaxKind::Conditional, children, range));
        }
        Some(cond)
    }

    /// Precedence-climbing binary parser.
    fn parse_binary(&mut self, min_prec: u8) -> Option<NodeId> {
        let mut lhs = self.parse_unary()?;
        loop {
            let t = self.cur.peek();
            let text = t.text(self.source);
            let prec = binary_prec(t.kind, text);
            match prec {
                Some(p) if p >= min_prec => {
                    self.cur.bump();
                    let rhs = self.parse_binary(p + 1)?;
                    let range = self.span2(lhs, rhs);
                    lhs = self.push(SyntaxKind::Binary, vec![lhs, rhs], range);
                }
                _ => return Some(lhs),
            }
        }
    }

    fn parse_unary(&mut self) -> Option<NodeId> {
        let t = self.cur.peek();
        let text = t.text(self.source);
        // Prefix operators.
        if is_prefix_op(t.kind, text) {
            let op = self.cur.bump();
            let arg = self.parse_unary()?;
            let range = SourceRange { start: op.range.start, end: self.nodes[arg].range.end };
            return Some(self.push(SyntaxKind::Unary, vec![arg], range));
        }
        // `new` has call semantics: `new Foo(args)` / `new Foo`.
        if t.kind == TokenKind::Keyword && text == "new" {
            return Some(self.parse_new());
        }
        let expr = self.parse_postfix()?;
        // Postfix `++` / `--`.
        let t = self.cur.peek();
        if t.kind == TokenKind::Op && matches!(t.text(self.source), "++" | "--") {
            self.cur.bump();
            let range = SourceRange { start: self.nodes[expr].range.start, end: t.range.end };
            return Some(self.push(SyntaxKind::Update, vec![expr], range));
        }
        Some(expr)
    }

    fn parse_new(&mut self) -> NodeId {
        let start = self.cur.bump().range.start; // new
        let callee = self.parse_postfix_no_call().unwrap_or_else(|| {
            let t = self.cur.bump();
            self.push(SyntaxKind::Ident, vec![], t.range)
        });
        let mut children = vec![callee];
        if self.cur.at_punct("(") {
            children.extend(self.parse_args());
        }
        let end = self.span(&children).end.max(start);
        self.push(SyntaxKind::New, children, SourceRange { start, end })
    }

    /// Member access and call chains: `a.b.c(x)[y](z)`.
    fn parse_postfix(&mut self) -> Option<NodeId> {
        let mut expr = self.parse_primary()?;
        loop {
            let t = self.cur.peek();
            match (t.kind, t.text(self.source)) {
                (TokenKind::Punct, ".") => {
                    self.cur.bump();
                    if let Some(prop) = self.parse_property_name() {
                        let range = self.span2(expr, prop);
                        expr = self.push(SyntaxKind::Member, vec![expr, prop], range);
                    } else {
                        return Some(expr);
                    }
                }
                (TokenKind::Punct, "[") => {
                    self.cur.bump();
                    let index = self.parse_expression();
                    self.cur.eat(TokenKind::Punct, "]");
                    let mut children = vec![expr];
                    children.extend(index);
                    let range = self.span(&children);
                    expr = self.push(SyntaxKind::Member, children, range);
                }
                (TokenKind::Punct, "(") => {
                    let args = self.parse_args();
                    let mut children = vec![expr];
                    children.extend(args);
                    let range = self.span(&children);
                    expr = self.push(SyntaxKind::Call, children, range);
                }
                (TokenKind::Op, "?.") if self.cur.peek2().kind == TokenKind::Punct
                    && self.cur.peek2().text(self.source) == "(" =>
                {
                    self.cur.bump(); // ?.
                    let args = self.parse_args();
                    let mut children = vec![expr];
                    children.extend(args);
                    let range = self.span(&children);
                    expr = self.push(SyntaxKind::Call, children, range);
                }
                (TokenKind::Op, "?.") => {
                    self.cur.bump();
                    if let Some(prop) = self.parse_property_name() {
                        let range = self.span2(expr, prop);
                        expr = self.push(SyntaxKind::Member, vec![expr, prop], range);
                    } else {
                        return Some(expr);
                    }
                }
                // Tagged template: `` tag`...` ``
                (TokenKind::TemplateHead | TokenKind::TemplateTail, _) => {
                    let tmpl = self.parse_template();
                    let range = self.span2(expr, tmpl);
                    expr = self.push(SyntaxKind::Call, vec![expr, tmpl], range);
                }
                _ => return Some(expr),
            }
        }
    }

    /// Member chain without the final call, for `new Foo.Bar()`.
    fn parse_postfix_no_call(&mut self) -> Option<NodeId> {
        let mut expr = self.parse_primary()?;
        loop {
            let t = self.cur.peek();
            match (t.kind, t.text(self.source)) {
                (TokenKind::Punct, ".") => {
                    self.cur.bump();
                    let prop = self.parse_property_name()?;
                    let range = self.span2(expr, prop);
                    expr = self.push(SyntaxKind::Member, vec![expr, prop], range);
                }
                (TokenKind::Punct, "[") => {
                    self.cur.bump();
                    let index = self.parse_expression();
                    self.cur.eat(TokenKind::Punct, "]");
                    let mut children = vec![expr];
                    children.extend(index);
                    let range = self.span(&children);
                    expr = self.push(SyntaxKind::Member, children, range);
                }
                _ => return Some(expr),
            }
        }
    }

    fn parse_property_name(&mut self) -> Option<NodeId> {
        let t = self.cur.peek();
        match t.kind {
            TokenKind::Ident | TokenKind::Keyword => {
                let t = self.cur.bump();
                Some(self.push(SyntaxKind::Ident, vec![], t.range))
            }
            TokenKind::String => {
                let t = self.cur.bump();
                Some(self.push(SyntaxKind::StringLit, vec![], t.range))
            }
            TokenKind::Number => {
                let t = self.cur.bump();
                Some(self.push(SyntaxKind::NumberLit, vec![], t.range))
            }
            TokenKind::TemplateHead => Some(self.parse_template()),
            // Computed property on a member access is handled by the caller.
            _ => None,
        }
    }
    /// A template literal, with or without interpolations. The lexer emits a
    /// lone tail for `` `text` `` (no `${`) and a head/middle/tail sequence
    /// otherwise; both shapes become one [`SyntaxKind::TemplateLit`] node,
    /// its interpolations as children.
    fn parse_template(&mut self) -> NodeId {
        if self.cur.peek().kind == TokenKind::TemplateHead {
            return self.parse_template_segments();
        }
        let t = self.cur.bump();
        self.push(SyntaxKind::TemplateLit, vec![], t.range)
    }

    /// `` `head ${ expr } … tail` `` — a template with interpolations. The
    /// lexer hands over head/middle/tail segment tokens interleaved with the
    /// interpolations' own tokens; each expression parses as a child, so a
    /// value interpolated into a template is traceable like any other
    /// expression.
    fn parse_template_segments(&mut self) -> NodeId {
        let start = self.cur.bump().range.start; // TemplateHead
        let mut children = Vec::new();
        loop {
            // The expression of one interpolation. An empty interpolation
            // (`${}`) parses to nothing and the tail follows immediately.
            if let Some(expr) = self.parse_assignment() {
                children.push(expr);
            }
            match self.cur.peek().kind {
                TokenKind::TemplateMiddle => {
                    self.cur.bump();
                }
                TokenKind::TemplateTail => {
                    self.cur.bump();
                    break;
                }
                // Malformed (unterminated) input: stop rather than spin.
                _ => break,
            }
        }
        let end = self.span(&children).end.max(start);
        self.push(SyntaxKind::TemplateLit, children, SourceRange { start, end })
    }

    fn parse_args(&mut self) -> Vec<NodeId> {
        if !self.cur.at_punct("(") {
            return vec![];
        }
        self.cur.bump(); // (
        let mut args = Vec::new();
        while !self.cur.at_punct(")") && !self.cur.at_eof() {
            if self.cur.eat(TokenKind::Punct, ",") {
                continue;
            }
            if self.cur.at_op("...") {
                let spread_start = self.cur.bump().range.start;
                if let Some(inner) = self.parse_assignment() {
                    let range = SourceRange {
                        start: spread_start,
                        end: self.nodes[inner].range.end,
                    };
                    args.push(self.push(SyntaxKind::Spread, vec![inner], range));
                }
                continue;
            }
            match self.parse_assignment() {
                Some(a) => args.push(a),
                None => {
                    self.cur.bump();
                }
            }
        }
        self.cur.eat(TokenKind::Punct, ")");
        args
    }

    fn parse_primary(&mut self) -> Option<NodeId> {
        let t = self.cur.peek();
        let text = t.text(self.source);
        match (t.kind, text) {
            (TokenKind::Ident, _) => {
                let t = self.cur.bump();
                Some(self.push(SyntaxKind::Ident, vec![], t.range))
            }
            (TokenKind::Keyword, "this") => {
                let t = self.cur.bump();
                Some(self.push(SyntaxKind::This, vec![], t.range))
            }
            (TokenKind::Keyword, "super") => {
                let t = self.cur.bump();
                Some(self.push(SyntaxKind::Super, vec![], t.range))
            }
            (TokenKind::Keyword, "true" | "false") => {
                let t = self.cur.bump();
                Some(self.push(SyntaxKind::BoolLit, vec![], t.range))
            }
            (TokenKind::Keyword, "null") => {
                let t = self.cur.bump();
                Some(self.push(SyntaxKind::NullLit, vec![], t.range))
            }
            (TokenKind::Keyword, "function") => Some(self.parse_function_expr()),
            (TokenKind::String, _) => {
                let t = self.cur.bump();
                Some(self.push(SyntaxKind::StringLit, vec![], t.range))
            }
            // A template literal: `` `head ${ expr } tail` ``. The lexer emits
            // head/middle/tail segments around the interpolation tokens, so the
            // expressions between them parse as real children. A template with
            // no interpolation is a lone tail segment.
            (TokenKind::TemplateHead | TokenKind::TemplateTail, _) => Some(self.parse_template()),
            (TokenKind::Number, _) => {
                let t = self.cur.bump();
                Some(self.push(SyntaxKind::NumberLit, vec![], t.range))
            }
            (TokenKind::Regex, _) => {
                let t = self.cur.bump();
                Some(self.push(SyntaxKind::RegexLit, vec![], t.range))
            }
            (TokenKind::Punct, "(") => {
                self.cur.bump();
                let inner = self.parse_expression();
                // A parenthesized arrow body/expr: `(...)` is also possible as
                // a grouping; the inner expression stands for the group.
                self.cur.eat(TokenKind::Punct, ")");
                inner
            }
            (TokenKind::Punct, "[") => self.parse_array_lit(),
            (TokenKind::Punct, "{") => self.parse_object_lit(),
            _ => None,
        }
    }

    fn parse_array_lit(&mut self) -> Option<NodeId> {
        if !self.cur.at_punct("[") {
            return None;
        }
        let start = self.cur.bump().range.start;
        let mut elements = Vec::new();
        while !self.cur.at_punct("]") && !self.cur.at_eof() {
            if self.cur.eat(TokenKind::Punct, ",") {
                continue;
            }
            if self.cur.at_op("...") {
                let spread_start = self.cur.bump().range.start;
                if let Some(inner) = self.parse_assignment() {
                    let range = SourceRange {
                        start: spread_start,
                        end: self.nodes[inner].range.end,
                    };
                    elements.push(self.push(SyntaxKind::Spread, vec![inner], range));
                }
                continue;
            }
            match self.parse_assignment() {
                Some(e) => elements.push(e),
                None => {
                    self.cur.bump();
                }
            }
        }
        let end = if self.cur.at_punct("]") {
            self.cur.bump().range.end
        } else {
            self.source.len()
        };
        Some(self.push(
            SyntaxKind::ArrayLit,
            elements,
            SourceRange { start, end },
        ))
    }

    fn parse_object_lit(&mut self) -> Option<NodeId> {
        if !self.cur.at_punct("{") {
            return None;
        }
        let start = self.cur.bump().range.start;
        let mut properties = Vec::new();
        while !self.cur.at_punct("}") && !self.cur.at_eof() {
            let before = self.cur.pos;
            if self.cur.eat(TokenKind::Punct, ",") {
                continue;
            }
            // Spread in an object literal: `{ ...src }`.
            if self.cur.at_op("...") {
                let spread_start = self.cur.bump().range.start;
                if let Some(inner) = self.parse_assignment() {
                    let range = SourceRange {
                        start: spread_start,
                        end: self.nodes[inner].range.end,
                    };
                    properties.push(self.push(SyntaxKind::Spread, vec![inner], range));
                }
                continue;
            }
            // Computed key: `{ [expr]: value }`.
            if self.cur.at_punct("[") {
                self.cur.bump();
                let key = self.parse_assignment();
                self.cur.eat(TokenKind::Punct, "]");
                let mut children = Vec::new();
                children.extend(key);
                if self.cur.eat(TokenKind::Punct, ":") {
                    if let Some(val) = self.parse_assignment() {
                        children.push(val);
                    }
                }
                let range = self.span(&children);
                properties.push(self.push(SyntaxKind::Property, children, range));
                continue;
            }
            // Key: identifier, keyword, string, number or template.
            let key = self.parse_property_name();
            let mut children = Vec::new();
            children.extend(key);
            // Shorthand `{ a }` has no value; `{ a: v }` does.
            if self.cur.eat(TokenKind::Punct, ":") {
                if let Some(val) = self.parse_assignment() {
                    children.push(val);
                }
            }
            let range = self.span(&children);
            properties.push(self.push(SyntaxKind::Property, children, range));
            // Guarantee forward progress on any unrecognized token.
            if self.cur.pos == before {
                self.cur.bump();
            }
        }
        let end = if self.cur.at_punct("}") {
            self.cur.bump().range.end
        } else {
            self.source.len()
        };
        Some(self.push(
            SyntaxKind::ObjectLit,
            properties,
            SourceRange { start, end },
        ))
    }

    // ------------------------------------------------------------------
    // Arrow functions
    // ------------------------------------------------------------------

    /// Detect and parse an arrow function at the current position, restoring
    /// the cursor if it is not one.
    fn try_parse_arrow(&mut self) -> Option<NodeId> {
        let save = self.cur.pos;
        // `ident => ...`
        if self.cur.at_name()
            && self.cur.peek2().kind == TokenKind::Op
            && self.cur.peek2().text(self.source) == "=>"
        {
            let name = self.cur.bump();
            let param = self.push(SyntaxKind::Param, vec![], name.range);
            self.cur.eat(TokenKind::Op, "=>");
            return Some(self.finish_arrow(save, vec![param]));
        }
        // `( params ) => ...`
        if self.cur.at_punct("(") {
            if let Some(close) = self.matching_paren(self.cur.pos) {
                let after = self.cur.tokens.get(close + 1);
                let is_arrow = after.map(|t| t.kind == TokenKind::Op && t.text(self.source) == "=>")
                    .unwrap_or(false);
                if !is_arrow {
                    self.cur.pos = save;
                    return None;
                }
                let params = self.parse_params();
                self.cur.eat(TokenKind::Op, "=>");
                return Some(self.finish_arrow(save, params));
            }
        }
        self.cur.pos = save;
        None
    }

    fn finish_arrow(&mut self, start_pos: usize, params: Vec<NodeId>) -> NodeId {
        let start = self.cur.tokens.get(start_pos).map(|t| t.range.start).unwrap_or(0);
        let mut children = params;
        if self.cur.at_punct("{") {
            children.push(self.parse_block());
        } else {
            // Expression body.
            if let Some(body) = self.parse_assignment() {
                children.push(body);
            }
        }
        let end = self.span(&children).end.max(start);
        self.push(SyntaxKind::ArrowFn, children, SourceRange { start, end })
    }

    /// Index of the token matching the `(` at `open`, or `None` if unbalanced.
    fn matching_paren(&self, open: usize) -> Option<usize> {
        let mut depth = 0i32;
        let mut i = open;
        while i < self.cur.tokens.len() {
            let t = self.cur.tokens[i];
            match t.text(self.source) {
                "(" => depth += 1,
                ")" => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            }
            i += 1;
        }
        None
    }
}

// ----------------------------------------------------------------------
// Operator tables
// ----------------------------------------------------------------------

fn is_assign_op(t: Token, source: &str) -> bool {
    t.kind == TokenKind::Op
        && matches!(
            t.text(source),
            "=" | "+=" | "-=" | "*=" | "/=" | "%=" | "&=" | "|=" | "^=" | "**=" | "<<=" | ">>="
                | ">>>=" | "&&=" | "||=" | "??="
        )
}

fn is_prefix_op(kind: TokenKind, text: &str) -> bool {
    match kind {
        TokenKind::Op => matches!(text, "!" | "~" | "+" | "-" | "typeof" | "void" | "delete"),
        TokenKind::Keyword => matches!(text, "typeof" | "void" | "delete" | "await" | "yield"),
        _ => false,
    }
}

/// Binary precedence (higher binds tighter). `in`/`instanceof` are keywords.
fn binary_prec(kind: TokenKind, text: &str) -> Option<u8> {
    match kind {
        TokenKind::Op => match text {
            "??" | "||" => Some(1),
            "&&" => Some(2),
            "|" => Some(3),
            "^" => Some(4),
            "&" => Some(5),
            "==" | "!=" | "===" | "!==" => Some(6),
            "<" | ">" | "<=" | ">=" => Some(7),
            "<<" | ">>" | ">>>" => Some(8),
            "+" | "-" => Some(9),
            "*" | "/" | "%" => Some(10),
            "**" => Some(11),
            _ => None,
        },
        TokenKind::Keyword if matches!(text, "in" | "instanceof") => Some(7),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::ast::SyntaxKind;

    fn tree(src: &str) -> SyntaxTree {
        parse_script(src)
    }

    #[test]
    fn root_is_a_script_over_statements() {
        let t = tree("var x = 1;");
        assert_eq!(t.root().kind, SyntaxKind::Script);
        assert!(t.root().children.iter().all(|&c| t.node(c).kind == SyntaxKind::VarDecl));
    }

    #[test]
    fn var_declaration_produces_declarator_and_initializer() {
        let t = tree("var v = location.hash;");
        let decl = t.root().children[0];
        assert_eq!(t.node(decl).kind, SyntaxKind::VarDecl);
        let declarator = t.node(decl).children[0];
        assert_eq!(t.node(declarator).kind, SyntaxKind::VarDeclarator);
        let children = &t.node(declarator).children;
        assert_eq!(t.node(children[0]).kind, SyntaxKind::Ident);
        assert_eq!(t.node(children[0]).text("var v = location.hash;"), "v");
        // Initializer is a Member chain.
        let init = t.node(children[1]);
        assert!(matches!(init.kind, SyntaxKind::Member));
    }

    #[test]
    fn member_chain_parses_left_associatively() {
        let t = tree("a.b.c");
        // The outermost member is .b.c; its object operand is .b.
        let top = t.all_nodes().into_iter()
            .map(|i| t.node(i))
            .filter(|n| n.kind == SyntaxKind::Member)
            .max_by_key(|n| n.range.end - n.range.start)
            .unwrap();
        assert_eq!(top.text("a.b.c"), "a.b.c");
        let obj = t.node(top.children[0]);
        assert_eq!(obj.text("a.b.c"), "a.b");
    }

    /// The first node of a given kind in source order.
    fn first_kind(t: &SyntaxTree, kind: SyntaxKind) -> NodeId {
        t.all_nodes()
            .into_iter()
            .find(|&i| t.node(i).kind == kind)
            .unwrap_or_else(|| panic!("no {:?} node", kind))
    }

    #[test]
    fn call_node_has_callee_and_args() {
        let t = tree("el.innerHTML = escape(v);");
        let call = first_kind(&t, SyntaxKind::Call);
        assert_eq!(t.node(call).children.len(), 2);
        let arg = t.node(t.node(call).children[1]);
        assert_eq!(arg.kind, SyntaxKind::Ident);
    }

    #[test]
    fn assignment_is_right_associative() {
        let t = tree("a = b = 1");
        let top = first_kind(&t, SyntaxKind::Assign);
        // The outermost assignment's RHS is the inner `b = 1`, not an Ident.
        assert_eq!(t.node(t.node(top).children[1]).kind, SyntaxKind::Assign);
    }

    #[test]
    fn binary_precedence_binds_tighter_operators_deeper() {
        // `a + b * c` → the `*` sits deeper in the tree than the `+`.
        let t = tree("a + b * c");
        let top = first_kind(&t, SyntaxKind::Binary);
        assert_eq!(t.node(t.node(top).children[0]).kind, SyntaxKind::Ident);
        // RHS is `b * c`.
        assert_eq!(t.node(t.node(top).children[1]).kind, SyntaxKind::Binary);
    }

    #[test]
    fn function_decl_makes_params_and_body() {
        let t = tree("function f(a, b) { return a; }");
        let f = t.root().children[0];
        assert_eq!(t.node(f).kind, SyntaxKind::FunctionDecl);
        let children = &t.node(f).children;
        // name, a, b, body
        assert_eq!(children.len(), 4);
        assert_eq!(t.node(children[1]).kind, SyntaxKind::Param);
        assert_eq!(t.node(children[2]).kind, SyntaxKind::Param);
        assert_eq!(t.node(children[3]).kind, SyntaxKind::Block);
    }

    #[test]
    fn arrow_function_with_expression_body() {
        let t = tree("const f = (x) => x * 2;");
        let arrow = first_kind(&t, SyntaxKind::ArrowFn);
        // The param and the expression body are both children of the arrow.
        assert!(t
            .node(arrow)
            .children
            .iter()
            .any(|&c| t.node(c).kind == SyntaxKind::Param));
        assert!(t
            .node(arrow)
            .children
            .iter()
            .any(|&c| t.node(c).kind == SyntaxKind::Binary));
    }

    #[test]
    fn arrow_function_with_block_body() {
        let t = tree("const f = (x) => { return x; };");
        let arrow = t.root().children[0];
        let init = t.node(arrow);
        // VarDecl → VarDeclarator → ArrowFn
        let mut found = false;
        for c in t.descendants(init.id) {
            if t.node(c).kind == SyntaxKind::ArrowFn {
                found = true;
                assert!(t.node(c).children.iter().any(|&k| t.node(k).kind == SyntaxKind::Param));
                assert!(t.node(c).children.iter().any(|&k| t.node(k).kind == SyntaxKind::Block));
            }
        }
        assert!(found, "arrow function must exist");
    }

    #[test]
    fn if_statement_has_condition_consequence_and_alternate() {
        let t = tree("if (a) { b(); } else { c(); }");
        let ifnode = t.root().children[0];
        assert_eq!(t.node(ifnode).kind, SyntaxKind::If);
        assert_eq!(t.node(ifnode).children.len(), 3);
    }

    #[test]
    fn nested_blocks_nest() {
        let t = tree("function f() { if (a) { b(); } }");
        let mut blocks = 0;
        for id in t.all_nodes() {
            if t.node(id).kind == SyntaxKind::Block {
                blocks += 1;
            }
        }
        assert_eq!(blocks, 2, "function body and if body");
    }

    #[test]
    fn object_and_array_literals_parse() {
        let t = tree("var o = { a: 1, b: 'x' }; var arr = [1, 2];");
        let mut objects = 0;
        let mut arrays = 0;
        let mut props = 0;
        for id in t.all_nodes() {
            match t.node(id).kind {
                SyntaxKind::ObjectLit => objects += 1,
                SyntaxKind::ArrayLit => arrays += 1,
                SyntaxKind::Property => props += 1,
                _ => {}
            }
        }
        assert_eq!(objects, 1);
        assert_eq!(arrays, 1);
        assert_eq!(props, 2);
    }

    #[test]
    fn spread_parses_in_args_and_arrays() {
        let t = tree("f(...rest); var a = [...items];");
        let spreads = t
            .all_nodes()
            .iter()
            .filter(|&&i| t.node(i).kind == SyntaxKind::Spread)
            .count();
        assert_eq!(spreads, 2);
    }

    #[test]
    fn malformed_input_recovers_without_panicking() {
        // Unbalanced, mid-expression, exotic syntax: must produce a tree.
        let t = tree("function ( { var >>> ... ");
        let _ = t.root();
        let t = tree("a = ; } } )");
        let _ = t.root();
        let t = tree("");
        assert!(t.root().children.is_empty());
    }

    #[test]
    fn offsets_of_leaves_match_token_ranges() {
        let src = "var v = location.hash;";
        let t = tree(src);
        let off = src.find("location").unwrap();
        let node = t.node_at(off).unwrap();
        assert_eq!(node.range.start, off);
        assert_eq!(node.range.end, off + "location".len());
    }

    #[test]
    fn regex_and_template_literals_are_leaves() {
        let src = "var r = /x/g; var s = `hi`;";
        let t = tree(src);
        let re = t.node_at(src.find("/x/").unwrap()).unwrap();
        assert_eq!(re.kind, SyntaxKind::RegexLit);
        let tm = t.node_at(src.find("hi").unwrap()).unwrap();
        assert_eq!(tm.kind, SyntaxKind::TemplateLit);
    }

    #[test]
    fn try_catch_parses() {
        let t = tree("try { a(); } catch (e) { b(e); }");
        let trynode = t.root().children[0];
        assert_eq!(t.node(trynode).kind, SyntaxKind::Try);
        // try block, catch param, catch block
        assert_eq!(t.node(trynode).children.len(), 3);
    }

    #[test]
    fn new_expression_parses() {
        let t = tree("var x = new Foo(1);");
        assert!(t.all_nodes().iter().any(|&i| t.node(i).kind == SyntaxKind::New));
    }

    #[test]
    fn ternary_parses() {
        let t = tree("var x = a ? b : c;");
        let mut found = false;
        for id in t.all_nodes() {
            if t.node(id).kind == SyntaxKind::Conditional {
                found = true;
            }
        }
        assert!(found);
    }
}
