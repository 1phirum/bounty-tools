use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawDiff {
    pub byte_length_delta: i64,
    pub exact_match: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuralDiff {
    pub is_json: bool,
    pub is_html: bool,
    pub schema_changed: bool,
    pub dom_structure_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticDiff {
    pub array_cardinality_delta: i64,
    pub missing_keys: Vec<String>,
    pub new_keys: Vec<String>,
    pub type_changes: Vec<String>,
    pub error_object_present: bool,
    pub significance_score: f32, // How meaningful is this difference?
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialResult {
    pub raw: RawDiff,
    pub structural: StructuralDiff,
    pub semantic: SemanticDiff,
}

impl DifferentialResult {
    pub fn is_semantically_different(&self) -> bool {
        self.semantic.significance_score > 0.6
    }
}
