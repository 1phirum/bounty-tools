use super::GeneratedPayload;
use crate::types::ProbeType;

pub fn generate() -> Vec<GeneratedPayload> {
    let probes: Vec<(&str, &str)> = vec![
        // Unbalanced quote — triggers dialect-specific unterminated string errors
        ("error-unbalanced-quote", "'"),
        // Double quote with garbage — triggers syntax error in all dialects
        ("error-double-quote-garbage", "\"'"),
        // Backslash escape — MySQL accepts \' but PG/MSSQL/Oracle do not
        ("error-backslash-escape", "\\'"),
        // Pipe pipe — triggers concatenation error in PG/Oracle, harmless in MySQL
        ("error-pipe-pipe", "'||'"),
        // Double dash — comment marker in most, arithmetic in some
        ("error-double-dash", "'--"),
        // Semicolon — statement terminator, error in some contexts
        ("error-semicolon", "';"),
    ];

    probes
        .into_iter()
        .map(|(name, payload)| GeneratedPayload {
            name: name.to_string(),
            probe_type: ProbeType::ErrorInjection,
            payload_str: payload.to_string(),
            expected_dbms: None,
            clause: None,
        })
        .collect()
}
