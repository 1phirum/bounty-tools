//! Reflection normalization: make values comparable when the response has
//! transformed them (case, whitespace, entity folding).

/// Normalize text for comparison: collapse runs of whitespace to a single
/// space, trim, and case-fold. Entity folding is intentionally NOT applied
/// here — the detector handles encoded forms explicitly so a genuine encoding
/// step is never mistaken for normalization.
pub fn normalize_for_comparison(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapses_whitespace_runs() {
        assert_eq!(
            normalize_for_comparison("a   b\t\tc\n\nd"),
            "a b c d"
        );
    }

    #[test]
    fn case_folds() {
        assert_eq!(normalize_for_comparison("XyZzY42"), "xyzzy42");
    }

    #[test]
    fn trims_edges() {
        assert_eq!(normalize_for_comparison("  padded  "), "padded");
    }

    #[test]
    fn empty_stays_empty() {
        assert_eq!(normalize_for_comparison("   "), "");
    }

    #[test]
    fn entities_are_not_folded_here() {
        // &lt; must NOT become '<' during normalization — that would hide a
        // real encoding step from the detector.
        assert_eq!(normalize_for_comparison("a&lt;b"), "a&lt;b");
    }
}
