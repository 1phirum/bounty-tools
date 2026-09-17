//! Source detection: identify where client-side code reads attacker data.
//!
//! A *source* is an API that returns data an attacker can influence. Detection
//! is static and syntax-level: we find the read, not the flow — flow is the
//! taint module's job.

use crate::parser::js::{NodeId, SyntaxKind, SyntaxTree};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Where attacker-controlled data can enter client-side code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    LocationHash,
    LocationSearch,
    LocationHref,
    LocationPathname,
    DocumentReferrer,
    WindowName,
    PostMessage,
    LocalStorage,
    SessionStorage,
    DocumentCookie,
    IndexedDb,
    UrlFragment,
}

impl SourceKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::LocationHash => "location.hash",
            Self::LocationSearch => "location.search",
            Self::LocationHref => "location.href",
            Self::LocationPathname => "location.pathname",
            Self::DocumentReferrer => "document.referrer",
            Self::WindowName => "window.name",
            Self::PostMessage => "postMessage",
            Self::LocalStorage => "localStorage",
            Self::SessionStorage => "sessionStorage",
            Self::DocumentCookie => "document.cookie",
            Self::IndexedDb => "IndexedDB",
            Self::UrlFragment => "URL fragment",
        }
    }

    /// How directly an attacker controls this source's value.
    pub fn attacker_control(&self) -> f32 {
        match self {
            Self::LocationHash | Self::LocationSearch | Self::LocationHref
            | Self::LocationPathname | Self::UrlFragment => 1.0,
            Self::WindowName | Self::PostMessage => 0.9,
            Self::DocumentReferrer => 0.7,
            Self::DocumentCookie => 0.6,
            Self::LocalStorage | Self::SessionStorage | Self::IndexedDb => 0.5,
        }
    }
}

/// A source read found in client-side code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceRead {
    pub kind: SourceKind,
    /// Byte offset of the read in the analyzed script.
    pub offset: usize,
    /// The line of code containing the read.
    pub context_line: String,
}

/// Detect source reads in JavaScript source text.
///
/// Recognizes the standard DOM sources by their access patterns. Each
/// detection records the offset so the taint module can trace onward.
pub fn detect_sources(script: &str) -> Vec<SourceRead> {
    const PATTERNS: &[(&str, SourceKind)] = &[
        ("location.hash", SourceKind::LocationHash),
        ("location.search", SourceKind::LocationSearch),
        ("location.href", SourceKind::LocationHref),
        ("location.pathname", SourceKind::LocationPathname),
        ("document.referrer", SourceKind::DocumentReferrer),
        ("window.name", SourceKind::WindowName),
        ("postMessage", SourceKind::PostMessage),
        ("localStorage", SourceKind::LocalStorage),
        ("sessionStorage", SourceKind::SessionStorage),
        ("document.cookie", SourceKind::DocumentCookie),
        ("indexedDB", SourceKind::IndexedDb),
    ];

    let mut out = Vec::new();
    for (needle, kind) in PATTERNS {
        let lower = script.to_lowercase();
        let mut from = 0;
        while let Some(pos) = lower[from..].find(&needle.to_lowercase()) {
            let offset = from + pos;
            let line = line_at(script, offset);
            out.push(SourceRead {
                kind: *kind,
                offset,
                context_line: line.to_string(),
            });
            from = offset + needle.len();
        }
    }
    out.sort_by_key(|s| s.offset);
    out
}

fn line_at(script: &str, offset: usize) -> &str {
    let start = script[..offset].rfind('\n').map(|p| p + 1).unwrap_or(0);
    let end = script[offset..]
        .find('\n')
        .map(|p| offset + p)
        .unwrap_or(script.len());
    &script[start..end]
}

// ----------------------------------------------------------------------
// Syntax-tree detection
// ----------------------------------------------------------------------

/// A source read found in the tree, anchored to the node that reads it.
pub type TreeSource = (NodeId, SourceRead);

/// The object and property of a static member node (`obj.prop`).
fn member_prop(tree: &SyntaxTree, id: NodeId) -> Option<(NodeId, String)> {
    if tree.node(id).kind != SyntaxKind::Member {
        return None;
    }
    let children = tree.node(id).children.clone();
    let obj = *children.first()?;
    let prop = children.get(1)?;
    (tree.node(*prop).kind == SyntaxKind::Ident).then_some((obj, tree.node_text(*prop).to_string()))
}

/// The dotted name of a member chain (`window.location` from `window.location.hash`).
fn dotted_name(tree: &SyntaxTree, id: NodeId) -> String {
    match tree.node(id).kind {
        SyntaxKind::Ident => tree.node_text(id).to_string(),
        SyntaxKind::This => "this".to_string(),
        SyntaxKind::Member => {
            let children = tree.node(id).children.clone();
            let obj = children.first().map(|&o| dotted_name(tree, o)).unwrap_or_default();
            let prop = children.get(1).map(|&p| tree.node_text(p).to_string()).unwrap_or_default();
            if obj.is_empty() { prop } else { format!("{obj}.{prop}") }
        }
        _ => tree.node_text(id).to_string(),
    }
}

/// Detect source reads by walking the syntax tree.
///
/// A source is a *read* of an attacker-influenced API: a member expression
/// (`location.hash`, `document.referrer`) or a storage global (`localStorage`).
/// A mention inside a string literal or a comment is not a read, and writing
/// to a name is not reading it, so neither is a source. Each read is anchored
/// to the node that performs it, which is what the taint analysis looks up.
///
/// `postMessage` is deliberately not a source of a script: sending a message
/// is not reading one, and the read side is an event handler's `data`, which
/// the async-flow model (not this one) has to carry. The text-scanning
/// [`detect_sources`] still reports it for other consumers.
pub fn detect_sources_in_tree(tree: &SyntaxTree) -> Vec<TreeSource> {
    // A node written to is not a read: `location.hash = x` does not bring
    // attacker data in. Every assignment's target is excluded first.
    let written: HashSet<NodeId> = tree
        .all_nodes()
        .into_iter()
        .filter(|&id| tree.node(id).kind == SyntaxKind::Assign)
        .filter_map(|id| tree.node(id).children.first().copied())
        .collect();

    let mut out = Vec::new();
    for id in tree.all_nodes() {
        if written.contains(&id) {
            continue;
        }
        let node = tree.node(id);
        match node.kind {
            SyntaxKind::Member => {
                let Some((obj, prop)) = member_prop(tree, id) else { continue };
                // Accept `location.hash` and `window.location.hash` alike.
                let obj_name = dotted_name(tree, obj);
                let obj_name = obj_name.strip_prefix("window.").unwrap_or(&obj_name);
                let Some(kind) = source_kind(obj_name, &prop) else { continue };
                out.push((id, source_read(tree, id, kind)));
            }
            SyntaxKind::Ident => {
                let Some(kind) = storage_kind(tree.node_text(id)) else { continue };
                out.push((id, source_read(tree, id, kind)));
            }
            _ => {}
        }
    }
    out.sort_by_key(|(_, s)| s.offset);
    out
}

fn source_kind(obj: &str, prop: &str) -> Option<SourceKind> {
    match (obj, prop) {
        ("location", "hash") => Some(SourceKind::LocationHash),
        ("location", "search") => Some(SourceKind::LocationSearch),
        ("location", "href") => Some(SourceKind::LocationHref),
        ("location", "pathname") => Some(SourceKind::LocationPathname),
        ("document", "referrer") => Some(SourceKind::DocumentReferrer),
        ("document", "cookie") => Some(SourceKind::DocumentCookie),
        ("window", "name") => Some(SourceKind::WindowName),
        _ => None,
    }
}

fn storage_kind(name: &str) -> Option<SourceKind> {
    match name {
        "localStorage" => Some(SourceKind::LocalStorage),
        "sessionStorage" => Some(SourceKind::SessionStorage),
        "indexedDB" => Some(SourceKind::IndexedDb),
        _ => None,
    }
}

fn source_read(tree: &SyntaxTree, node: NodeId, kind: SourceKind) -> SourceRead {
    let offset = tree.node(node).range.start;
    SourceRead { kind, offset, context_line: line_at(&tree.source, offset).to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn location_hash_detected() {
        let src = "var v = location.hash.slice(1);";
        let found = detect_sources(src);
        assert!(found.iter().any(|s| s.kind == SourceKind::LocationHash));
    }

    #[test]
    fn multiple_sources_sorted_by_offset() {
        let src = "var a = location.search; var b = document.referrer;";
        let found = detect_sources(src);
        assert!(found.len() >= 2);
        for w in found.windows(2) {
            assert!(w[0].offset <= w[1].offset);
        }
    }

    #[test]
    fn context_line_is_captured() {
        let src = "var x = 1;\nvar v = location.hash;";
        let found = detect_sources(src);
        let hash = found.iter().find(|s| s.kind == SourceKind::LocationHash).unwrap();
        assert!(hash.context_line.contains("location.hash"));
    }

    #[test]
    fn no_sources_in_plain_code() {
        assert!(detect_sources("var x = 1 + 2;").is_empty());
    }

    #[test]
    fn attacker_control_is_rated() {
        assert_eq!(SourceKind::LocationHash.attacker_control(), 1.0);
        assert!(SourceKind::LocalStorage.attacker_control() < 1.0);
    }

    #[test]
    fn window_name_and_postmessage_detected() {
        let src = "window.addEventListener('message', e => use(e.data)); postMessage('x','*');";
        let found = detect_sources(src);
        assert!(found.iter().any(|s| s.kind == SourceKind::PostMessage));
    }

    // ------------------------------------------------------------------
    // Syntax-tree detection
    // ------------------------------------------------------------------

    fn tree_sources(src: &str) -> Vec<TreeSource> {
        detect_sources_in_tree(&crate::parser::js::parse_script(src))
    }

    #[test]
    fn tree_finds_location_hash_and_window_prefix() {
        let found = tree_sources("var v = location.hash;\nvar w = window.location.hash;");
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|(_, s)| s.kind == SourceKind::LocationHash));
    }

    #[test]
    fn tree_finds_document_and_window_members() {
        let found = tree_sources("var a = document.referrer; var b = window.name;");
        assert!(found.iter().any(|(_, s)| s.kind == SourceKind::DocumentReferrer));
        assert!(found.iter().any(|(_, s)| s.kind == SourceKind::WindowName));
    }

    #[test]
    fn tree_finds_storage_globals() {
        let found = tree_sources("var a = localStorage; var b = sessionStorage.getItem('k');");
        assert!(found.iter().any(|(_, s)| s.kind == SourceKind::LocalStorage));
        assert!(found.iter().any(|(_, s)| s.kind == SourceKind::SessionStorage));
    }

    #[test]
    fn tree_ignores_sources_in_strings_and_comments() {
        // A source named in a string literal or a comment is not a read.
        assert!(tree_sources("var s = \"location.hash\";").is_empty());
        assert!(tree_sources("// location.hash\nvar x = 1;").is_empty());
    }

    #[test]
    fn tree_ignores_a_write_to_a_source_name() {
        // Writing to the API is not reading it.
        assert!(tree_sources("location.hash = 'x';").is_empty());
        assert!(tree_sources("localStorage = {};").is_empty());
    }

    #[test]
    fn tree_ignores_unrelated_members() {
        assert!(tree_sources("var v = location.length;").is_empty());
        assert!(tree_sources("var v = element.hash;").is_empty());
    }
}
