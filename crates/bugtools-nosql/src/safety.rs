//! NoSQL payload safety gate.
//!
//! Detection must never mutate the target. This gate rejects any payload that
//! carries a write, administrative, or server-side-execution operator that
//! could change state or run unbounded work, and caps the `$where` sleep and
//! overall payload size. It mirrors the discipline of the SQL `safety` module:
//! a payload that cannot be proven non-destructive is refused, not sent.

/// The maximum `$where`/`sleep(N)` delay a timing probe may request, in
/// milliseconds. A detection delay only needs to clear timing noise; anything
/// larger edges toward denial-of-service and is refused.
pub const MAX_WHERE_SLEEP_MS: u64 = 5_000;

/// The maximum serialized payload length. Guards against oversized bodies.
pub const MAX_PAYLOAD_LEN: usize = 4_096;

/// Operators and keywords that write, administer, or run unbounded work.
/// Their presence in a payload is a hard rejection.
const FORBIDDEN_OPERATORS: &[&str] = &[
    // Aggregation write stages.
    "$out",
    "$merge",
    // Update operators.
    "$set",
    "$unset",
    "$inc",
    "$mul",
    "$rename",
    "$push",
    "$pull",
    "$pop",
    "$addtoset",
    "$pullall",
    "$bit",
    "$currentdate",
    "$setoninsert",
    // Server-side / admin commands.
    "mapreduce",
    "dropdatabase",
    "createcollection",
    "renamecollection",
    "$function", // arbitrary server-side JS in aggregation
    "$accumulator",
    "eval(", // db.eval / legacy server-side eval
];

/// Substrings inside a `$where`/JS payload that indicate a write or
/// destructive intent rather than a read-only predicate.
const FORBIDDEN_JS_FRAGMENTS: &[&str] = &[
    ".remove(",
    ".drop(",
    ".insert(",
    ".update(",
    ".save(",
    ".deleteone(",
    ".deletemany(",
    ".updateone(",
    ".updatemany(",
    ".replaceone(",
    ".findandmodify(",
    ".bulkwrite(",
    "while(true)",
    "while (true)",
    "for(;;)",
];

/// The reason a payload was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    ForbiddenOperator(String),
    ForbiddenJsFragment(String),
    SleepTooLong { requested_ms: u64, cap_ms: u64 },
    TooLarge { len: usize, cap: usize },
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ForbiddenOperator(op) => {
                write!(f, "payload carries a state-changing operator '{op}' — refused (detection is read-only)")
            }
            Self::ForbiddenJsFragment(frag) => {
                write!(f, "payload carries a destructive/unbounded JS fragment '{frag}' — refused")
            }
            Self::SleepTooLong { requested_ms, cap_ms } => {
                write!(f, "requested delay {requested_ms}ms exceeds the {cap_ms}ms cap — refused (avoids DoS)")
            }
            Self::TooLarge { len, cap } => {
                write!(f, "payload length {len} exceeds the {cap}-byte cap — refused")
            }
        }
    }
}

/// Validate a serialized payload string. `Ok(())` means it is safe to send.
pub fn validate(payload: &str) -> Result<(), Rejection> {
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(Rejection::TooLarge { len: payload.len(), cap: MAX_PAYLOAD_LEN });
    }
    let lower = payload.to_lowercase();
    for op in FORBIDDEN_OPERATORS {
        if lower.contains(op) {
            return Err(Rejection::ForbiddenOperator((*op).to_string()));
        }
    }
    for frag in FORBIDDEN_JS_FRAGMENTS {
        if lower.contains(frag) {
            return Err(Rejection::ForbiddenJsFragment((*frag).to_string()));
        }
    }
    Ok(())
}

/// Clamp a requested `$where` sleep to the cap.
pub fn clamp_sleep_ms(requested_ms: u64) -> u64 {
    requested_ms.min(MAX_WHERE_SLEEP_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_operator_injection_is_allowed() {
        assert!(validate("{\"user\":{\"$ne\":null}}").is_ok());
        assert!(validate("user[$gt]=").is_ok());
        assert!(validate("{\"pw\":{\"$regex\":\"^a\"}}").is_ok());
    }

    #[test]
    fn update_operator_is_rejected() {
        assert!(matches!(
            validate("{\"$set\":{\"role\":\"admin\"}}"),
            Err(Rejection::ForbiddenOperator(_))
        ));
    }

    #[test]
    fn aggregation_write_stage_is_rejected() {
        assert!(validate("[{\"$out\":\"stolen\"}]").is_err());
        assert!(validate("[{\"$merge\":\"users\"}]").is_err());
    }

    #[test]
    fn destructive_where_js_is_rejected() {
        assert!(matches!(
            validate("{\"$where\":\"db.users.drop()\"}"),
            Err(Rejection::ForbiddenJsFragment(_))
        ));
    }

    #[test]
    fn unbounded_loop_is_rejected() {
        assert!(validate("{\"$where\":\"while(true){}\"}").is_err());
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let big = "a".repeat(MAX_PAYLOAD_LEN + 1);
        assert!(matches!(validate(&big), Err(Rejection::TooLarge { .. })));
    }

    #[test]
    fn sleep_is_clamped() {
        assert_eq!(clamp_sleep_ms(999_999), MAX_WHERE_SLEEP_MS);
        assert_eq!(clamp_sleep_ms(250), 250);
    }
}
