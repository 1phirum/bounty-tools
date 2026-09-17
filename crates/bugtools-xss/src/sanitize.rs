//! Sanitizer semantics: what a sanitizer actually protects against.
//!
//! A sanitizer is context-sensitive, never a name match. A call named
//! `escapeHtml` is only a sanitizer for the contexts its escaping covers: the
//! same call feeding `eval` protects nothing, because escaping markup leaves
//! quotes and parentheses intact. So each known sanitizer declares the safety
//! it provides, each sink declares the safety it requires, and a flow counts
//! as sanitized only when some sanitizer on the path covers the sink's
//! requirement.
//!
//! A name this script declares as its own function is never a sanitizer by
//! name: the interprocedural analysis traces the body and the body's own calls
//! decide. Trusting a user-defined `escapeHtml` to sanitize is exactly the
//! name match this module exists to remove.
//!
//! Not modelled yet (audit item 13 remainder): sanitizer *configuration* — a
//! `DOMPurify.sanitize(v, { ALLOWED_TAGS: [...] })` may be weaker than the
//! default — and the *encoding stack*: a decode after an encode restores the
//! original, which a pair of transform names cannot express.

use crate::sink::SinkTarget;

/// The characters a value may no longer use to break out of a context. Each
/// flag is a guarantee a sanitizer can make about the value it produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Safety {
    /// No raw `<`, `>`, `&` or quotes: the value cannot form markup, so it is
    /// safe in HTML text, in an attribute, and inside a `<script>` block.
    pub markup: bool,
    /// No raw quotes or backslashes: the value cannot break out of a JavaScript
    /// string literal, so it is safe in `eval`, `setTimeout`, `new Function`.
    pub js_string: bool,
    /// No scheme injection: the value cannot introduce `javascript:` (or any
    /// other URI scheme) into a URL context.
    pub url: bool,
}

impl Safety {
    fn all() -> Self {
        Self { markup: true, js_string: true, url: true }
    }

    /// Whether `self` covers everything `required` demands; a sink needs every
    /// one of its requirements met.
    fn covers(self, required: Safety) -> bool {
        (!required.markup || self.markup)
            && (!required.js_string || self.js_string)
            && (!required.url || self.url)
    }

    /// The safety a sink requires of the value that reaches it.
    pub fn required_for(target: SinkTarget) -> Safety {
        match target {
            SinkTarget::HtmlInsertion
            | SinkTarget::DocumentWrite
            | SinkTarget::IframeContent
            | SinkTarget::JqueryHtml
            | SinkTarget::FrameworkRawHtml => Self { markup: true, ..Self::default() },
            SinkTarget::ScriptExecution => Self { js_string: true, ..Self::default() },
            SinkTarget::UrlAssignment => Self { url: true, ..Self::default() },
        }
    }
}

/// The kind of sanitizer a known API is. The kind decides which contexts the
/// value is safe in; the name alone never does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SanitizerKind {
    /// Escapes markup characters: `escapeHtml`, `htmlEscape`.
    HtmlEscape,
    /// Percent-encodes every reserved character: `encodeURIComponent`.
    PercentAll,
    /// Percent-encodes but leaves URI-reserved characters raw: `encodeURI`.
    PercentReserved,
    /// Parses markup and re-serializes it, dropping unsafe constructs:
    /// `DOMPurify.sanitize`, `sanitizeHtml`, `sanitize`.
    SanitizingParse,
}

impl SanitizerKind {
    /// The safety this sanitizer guarantees about its result.
    pub fn safety(self) -> Safety {
        match self {
            // Markup characters are gone, but a backslash is not escaped, so a
            // JS string can still be broken out of; a URL scheme is untouched.
            Self::HtmlEscape => Safety { markup: true, js_string: false, url: false },
            // Every character except `A-Za-z0-9-_.!~*'()` is encoded: no markup,
            // no quotes, no scheme.
            Self::PercentAll => Safety::all(),
            // `!#$&'()*+,/:;=?@[]` stay raw: no markup characters, but quotes
            // and parentheses survive, so a JS string still breaks.
            Self::PercentReserved => Safety { markup: true, js_string: false, url: true },
            // Unsafe markup is parsed away, but the surviving text is arbitrary
            // and may still be a script or a scheme.
            Self::SanitizingParse => Safety { markup: true, js_string: false, url: false },
        }
    }

    /// Whether this sanitizer makes a value safe for the given sink.
    pub fn protects(self, target: SinkTarget) -> bool {
        self.safety().covers(Safety::required_for(target))
    }
}

/// The known sanitizer APIs, by full dotted name. A name not in this table is
/// not a sanitizer by name.
const SANITIZER_TABLE: &[(&str, SanitizerKind)] = &[
    ("escapeHtml", SanitizerKind::HtmlEscape),
    ("escapeHTML", SanitizerKind::HtmlEscape),
    ("htmlEscape", SanitizerKind::HtmlEscape),
    ("encodeURIComponent", SanitizerKind::PercentAll),
    ("encodeURI", SanitizerKind::PercentReserved),
    ("DOMPurify.sanitize", SanitizerKind::SanitizingParse),
    ("sanitizeHtml", SanitizerKind::SanitizingParse),
    ("sanitize", SanitizerKind::SanitizingParse),
];

/// Classify a known library sanitizer by its callee name, accepting either the
/// full dotted name (`DOMPurify.sanitize`) or the final segment
/// (`.sanitize(`). Returns [`None`] for any name the table does not know.
///
/// Note that a DOM property that never interprets markup — `textContent`,
/// `createTextNode`, `innerText` — is deliberately absent: such a property is
/// a *safe sink*, not a value transform, and it is not a sanitizer of the
/// value that passes through it.
pub fn classify_sanitizer(name: &str) -> Option<SanitizerKind> {
    let last = name.rsplit('.').next().unwrap_or(name);
    SANITIZER_TABLE
        .iter()
        .find(|&&(api, _)| api == name || api == last)
        .map(|&(_, kind)| kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_html_protects_markup_but_not_scripts_or_urls() {
        assert!(SanitizerKind::HtmlEscape.protects(SinkTarget::HtmlInsertion));
        assert!(SanitizerKind::HtmlEscape.protects(SinkTarget::DocumentWrite));
        assert!(!SanitizerKind::HtmlEscape.protects(SinkTarget::ScriptExecution));
        assert!(!SanitizerKind::HtmlEscape.protects(SinkTarget::UrlAssignment));
    }

    #[test]
    fn encode_uri_component_protects_every_context() {
        for target in [
            SinkTarget::HtmlInsertion,
            SinkTarget::DocumentWrite,
            SinkTarget::ScriptExecution,
            SinkTarget::UrlAssignment,
        ] {
            assert!(SanitizerKind::PercentAll.protects(target), "{:?} must be protected", target);
        }
    }

    #[test]
    fn encode_uri_protects_markup_and_urls_but_not_scripts() {
        assert!(SanitizerKind::PercentReserved.protects(SinkTarget::HtmlInsertion));
        assert!(SanitizerKind::PercentReserved.protects(SinkTarget::UrlAssignment));
        assert!(!SanitizerKind::PercentReserved.protects(SinkTarget::ScriptExecution));
    }

    #[test]
    fn sanitizing_parse_protects_markup_only() {
        assert!(SanitizerKind::SanitizingParse.protects(SinkTarget::HtmlInsertion));
        assert!(SanitizerKind::SanitizingParse.protects(SinkTarget::IframeContent));
        assert!(!SanitizerKind::SanitizingParse.protects(SinkTarget::ScriptExecution));
        assert!(!SanitizerKind::SanitizingParse.protects(SinkTarget::UrlAssignment));
    }

    #[test]
    fn known_names_classify_by_full_or_last_segment() {
        assert_eq!(classify_sanitizer("DOMPurify.sanitize"), Some(SanitizerKind::SanitizingParse));
        assert_eq!(classify_sanitizer("sanitize"), Some(SanitizerKind::SanitizingParse));
        assert_eq!(classify_sanitizer("encodeURIComponent"), Some(SanitizerKind::PercentAll));
        assert_eq!(classify_sanitizer("someObj.escapeHtml"), Some(SanitizerKind::HtmlEscape));
    }

    #[test]
    fn unknown_name_is_not_a_sanitizer() {
        assert!(classify_sanitizer("escapeHtml2").is_none());
        assert!(classify_sanitizer("mySanitize").is_none());
        assert!(classify_sanitizer("textContent").is_none(), "textContent is a safe sink, not a sanitizer");
        assert!(classify_sanitizer("createTextNode").is_none());
    }

    #[test]
    fn html_sinks_require_markup_only() {
        let required = Safety::required_for(SinkTarget::HtmlInsertion);
        assert!(required.markup);
        assert!(!required.js_string);
        assert!(!required.url);
    }
}
