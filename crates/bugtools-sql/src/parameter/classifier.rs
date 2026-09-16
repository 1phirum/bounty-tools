//! Parameter value-type inference.
//!
//! Infers the likely data type of an input from its *observed value*, not
//! its name. The brief is explicit that names must not be trusted — an
//! `id` parameter holding `abc` is a string, not an integer.

use serde::{Deserialize, Serialize};

/// The inferred data type of an input value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataType {
    Integer,
    Decimal,
    Boolean,
    Uuid,
    Date,
    Enum,
    IdentifierLike,
    JsonObject,
    JsonArray,
    String,
    Empty,
    Unknown,
}

/// Infer a data type from a single observed value.
pub fn infer_type(value: &str) -> DataType {
    let v = value.trim();
    if v.is_empty() {
        return DataType::Empty;
    }
    // Boolean
    if matches!(v.to_lowercase().as_str(), "true" | "false") {
        return DataType::Boolean;
    }
    // Integer (optionally signed)
    if v.parse::<i64>().is_ok() {
        return DataType::Integer;
    }
    // Decimal
    if v.parse::<f64>().is_ok() && v.contains('.') {
        return DataType::Decimal;
    }
    // UUID (8-4-4-4-12 hex)
    if is_uuid(v) {
        return DataType::Uuid;
    }
    // ISO-8601-ish date/time
    if is_iso_date(v) {
        return DataType::Date;
    }
    // JSON object / array
    if v.starts_with('{') && v.ends_with('}') {
        return DataType::JsonObject;
    }
    if v.starts_with('[') && v.ends_with(']') {
        return DataType::JsonArray;
    }
    // Identifier-like: short token of [A-Za-z0-9_-] with no spaces.
    if v.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return DataType::IdentifierLike;
    }
    DataType::String
}

fn is_uuid(v: &str) -> bool {
    let parts: Vec<&str> = v.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    let lens = [8, 4, 4, 4, 12];
    parts
        .iter()
        .zip(lens)
        .all(|(p, l)| p.len() == l && p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Accepts `YYYY-MM-DD` and `YYYY-MM-DDTHH:MM:SS(Z|+HH:MM)`.
fn is_iso_date(v: &str) -> bool {
    if v.len() < 10 {
        return false;
    }
    let (date, rest) = v.split_at(10);
    let ok_date = date.len() == 10
        && date.as_bytes()[4] == b'-'
        && date.as_bytes()[7] == b'-'
        && date[..4].chars().all(|c| c.is_ascii_digit())
        && date[5..7].chars().all(|c| c.is_ascii_digit())
        && date[8..10].chars().all(|c| c.is_ascii_digit());
    if !ok_date {
        return false;
    }
    if rest.is_empty() {
        return true;
    }
    rest.starts_with('T') || rest.starts_with(' ')
}

/// Infer a type from several observations, preferring a stable answer.
/// If observations disagree, the type is reported as `Unknown` rather than
/// picking one arbitrarily.
pub fn infer_type_from_samples(values: &[String]) -> DataType {
    let types: Vec<DataType> = values
        .iter()
        .filter(|v| infer_type(v) != DataType::Empty)
        .map(|v| infer_type(v))
        .collect();
    if types.is_empty() {
        return DataType::Empty;
    }
    let first = types[0];
    if types.iter().all(|t| *t == first) {
        first
    } else {
        DataType::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_and_decimals() {
        assert_eq!(infer_type("42"), DataType::Integer);
        assert_eq!(infer_type("-7"), DataType::Integer);
        assert_eq!(infer_type("3.14"), DataType::Decimal);
    }

    #[test]
    fn booleans() {
        assert_eq!(infer_type("true"), DataType::Boolean);
        assert_eq!(infer_type("FALSE"), DataType::Boolean);
    }

    #[test]
    fn uuid_and_date() {
        assert_eq!(
            infer_type("550e8400-e29b-41d4-a716-446655440000"),
            DataType::Uuid
        );
        assert_eq!(infer_type("2026-09-16"), DataType::Date);
        assert_eq!(infer_type("2026-09-16T08:40:00Z"), DataType::Date);
    }

    #[test]
    fn json_shapes() {
        assert_eq!(infer_type("{\"a\":1}"), DataType::JsonObject);
        assert_eq!(infer_type("[1,2,3]"), DataType::JsonArray);
    }

    #[test]
    fn identifier_like_vs_string() {
        assert_eq!(infer_type("phone_case_01"), DataType::IdentifierLike);
        assert_eq!(infer_type("hello world"), DataType::String);
    }

    #[test]
    fn name_is_not_consulted() {
        // An `id`-named parameter carrying text is a String, not an Integer.
        assert_eq!(infer_type("not-a-number value"), DataType::String);
    }

    #[test]
    fn sample_agreement() {
        assert_eq!(
            infer_type_from_samples(&["1".into(), "2".into(), "3".into()]),
            DataType::Integer
        );
        assert_eq!(
            infer_type_from_samples(&["1".into(), "x".into()]),
            DataType::Unknown
        );
        assert_eq!(infer_type_from_samples(&[]), DataType::Empty);
    }

    #[test]
    fn non_uuid_hyphenated_is_not_uuid() {
        assert_eq!(infer_type("abc-def"), DataType::IdentifierLike);
    }
}
