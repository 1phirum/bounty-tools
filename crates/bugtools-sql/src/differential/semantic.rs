use super::models::{DifferentialResult, RawDiff, SemanticDiff, StructuralDiff};
use bugtools_core::http::HttpResponse;
use serde_json::Value;

pub struct SemanticDifferentialEngine;

impl SemanticDifferentialEngine {
    pub fn compare(baseline: &HttpResponse, candidate: &HttpResponse) -> DifferentialResult {
        let exact_match = baseline.body == candidate.body;
        let byte_length_delta = (candidate.size_bytes as i64) - (baseline.size_bytes as i64);

        let raw = RawDiff {
            byte_length_delta,
            exact_match,
        };

        let (structural, semantic) = Self::analyze_semantics(&baseline.body, &candidate.body);

        DifferentialResult {
            raw,
            structural,
            semantic,
        }
    }

    fn analyze_semantics(baseline_body: &str, candidate_body: &str) -> (StructuralDiff, SemanticDiff) {
        let mut structural = StructuralDiff {
            is_json: false,
            is_html: false,
            schema_changed: false,
            dom_structure_changed: false,
        };

        let mut semantic = SemanticDiff {
            array_cardinality_delta: 0,
            missing_keys: Vec::new(),
            new_keys: Vec::new(),
            type_changes: Vec::new(),
            error_object_present: false,
            significance_score: 0.0,
        };

        // Attempt JSON Parsing
        if let (Ok(base_json), Ok(cand_json)) = (serde_json::from_str::<Value>(baseline_body), serde_json::from_str::<Value>(candidate_body)) {
            structural.is_json = true;

            // Simple Array Cardinality Check
            if let (Some(base_arr), Some(cand_arr)) = (base_json.as_array(), cand_json.as_array()) {
                semantic.array_cardinality_delta = (cand_arr.len() as i64) - (base_arr.len() as i64);
                if semantic.array_cardinality_delta != 0 {
                    semantic.significance_score += 0.8;
                }
            }

            // Simple Object Schema Check
            if let (Some(base_obj), Some(cand_obj)) = (base_json.as_object(), cand_json.as_object()) {
                for key in base_obj.keys() {
                    if !cand_obj.contains_key(key) {
                        semantic.missing_keys.push(key.clone());
                        structural.schema_changed = true;
                    }
                }
                for key in cand_obj.keys() {
                    if !base_obj.contains_key(key) {
                        semantic.new_keys.push(key.clone());
                        structural.schema_changed = true;
                    }
                    if key.to_lowercase().contains("error") || key.to_lowercase().contains("message") {
                        semantic.error_object_present = true;
                    }
                }

                if structural.schema_changed {
                    semantic.significance_score += 0.9;
                }
                if semantic.error_object_present && !base_obj.contains_key("error") {
                    semantic.significance_score += 0.7;
                }
            }
        } else {
            // Very naive HTML/Text fallback
            structural.is_html = baseline_body.contains("<html") || baseline_body.contains("<body");
            if baseline_body != candidate_body {
                // For raw text, we just assign a basic significance based on length change for now.
                // An advanced DOM differ would go here.
                if (baseline_body.len() as i64 - candidate_body.len() as i64).abs() > 50 {
                    structural.dom_structure_changed = true;
                    semantic.significance_score += 0.5;
                }
            }
        }

        (structural, semantic)
    }
}
