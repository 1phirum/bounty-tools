//! Technology → XSS strategy matrix (brief §2).
//!
//! After fingerprinting, the technology determines *which* XSS classes and
//! test approaches are relevant. This is the module that makes BugTools
//! technology-aware rather than payload-oriented: React is not tested like
//! a Twig-rendered page.

use crate::technology::{TechCategory, TechnologyFinding};
use serde::{Deserialize, Serialize};

/// The rendering model implied by a technology stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RenderingModel {
    /// Server renders finished HTML (templates).
    ServerSideHtml,
    /// Client renders from JS (SPA); initial HTML is a shell.
    ClientSideSpa,
    /// Server renders HTML then the client hydrates it.
    HybridHydration,
    /// Response is structured data (JSON/XML) rendered elsewhere.
    StructuredData,
    Unknown,
}

/// A relevant XSS class or investigation area for a technology.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StrategyItem {
    /// What to investigate, e.g. "dangerouslySetInnerHTML".
    pub focus: String,
    /// Why this technology makes it relevant.
    pub rationale: String,
    /// How much attention it deserves (0–1).
    pub priority: f32,
}

/// The XSS investigation strategy derived from detected technologies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssStrategy {
    pub rendering_model: RenderingModel,
    pub items: Vec<StrategyItem>,
    /// Technologies that drove this strategy, for the evidence trail.
    pub driven_by: Vec<String>,
}

impl XssStrategy {
    /// True when nothing technology-specific was found, so only generic
    /// context testing applies. The engine must not pretend otherwise.
    pub fn is_generic(&self) -> bool {
        self.items.is_empty()
    }
}

/// Build a strategy from detected technologies.
///
/// When no technology crossed the reporting threshold, the strategy is
/// explicitly generic — the engine does not invent a stack.
pub fn build_strategy(findings: &[TechnologyFinding]) -> XssStrategy {
    let mut items: Vec<StrategyItem> = Vec::new();
    let mut driven_by = Vec::new();
    let mut rendering_model = RenderingModel::Unknown;

    for f in findings {
        driven_by.push(format!("{} ({:?})", f.technology, f.category));
        let name = f.technology.as_str();

        match name {
            "React" => {
                rendering_model = RenderingModel::ClientSideSpa;
                items.push(StrategyItem {
                    focus: "dangerouslySetInnerHTML usage".into(),
                    rationale: "React escapes by default; raw-HTML props bypass that".into(),
                    priority: 0.9,
                });
                items.push(StrategyItem {
                    focus: "hydration sink divergence".into(),
                    rationale: "server-rendered markup can differ from client hydration".into(),
                    priority: 0.7,
                });
            }
            "Next.js" => {
                rendering_model = RenderingModel::HybridHydration;
                items.push(StrategyItem {
                    focus: "__NEXT_DATA__ / hydration props".into(),
                    rationale: "serialized page props feed client rendering".into(),
                    priority: 0.85,
                });
                items.push(StrategyItem {
                    focus: "URL/query/fragment sources into client sinks".into(),
                    rationale: "Next reads router state client-side".into(),
                    priority: 0.75,
                });
            }
            "Angular" => {
                rendering_model = RenderingModel::ClientSideSpa;
                items.push(StrategyItem {
                    focus: "template binding vs bypassSecurityTrust*".into(),
                    rationale: "Angular sanitizes interpolation; explicit bypass APIs do not".into(),
                    priority: 0.9,
                });
                items.push(StrategyItem {
                    focus: "interpolation context escaping".into(),
                    rationale: "double-brace interpolation is context-encoded".into(),
                    priority: 0.6,
                });
            }
            // AngularJS 1.x is CSTI-prone in a way Angular 2+ is not: any user
            // input that reaches a `{{ }}` interpolation context is evaluated.
            "AngularJS" => {
                rendering_model = RenderingModel::ClientSideSpa;
                items.push(StrategyItem {
                    focus: "client-side template injection in {{ }} interpolation".into(),
                    rationale: "AngularJS evaluates expressions; input reaching an interpolation context is CSTI, not just reflected text".into(),
                    priority: 0.95,
                });
                items.push(StrategyItem {
                    focus: "ng-app scope: locate an interpolated reflection".into(),
                    rationale: "CSTI only fires inside the ng-app root; confirm the reflection sits within it".into(),
                    priority: 0.7,
                });
            }
            "Vue.js" | "Nuxt.js" => {
                rendering_model = RenderingModel::ClientSideSpa;
                items.push(StrategyItem {
                    focus: "v-html / dangerouslyUseHTMLString".into(),
                    rationale: "Vue escapes mustaches; v-html bypasses escaping".into(),
                    priority: 0.9,
                });
                if name == "Nuxt.js" {
                    items.push(StrategyItem {
                        focus: "Nuxt payload/hydration flow".into(),
                        rationale: "Nuxt serializes server state into the client".into(),
                        priority: 0.7,
                    });
                }
            }
            "WordPress" | "Drupal" | "Joomla" => {
                rendering_model = RenderingModel::ServerSideHtml;
                items.push(StrategyItem {
                    focus: "stored XSS via post/comment/profile fields".into(),
                    rationale: "CMS content is persisted then rendered to other users".into(),
                    priority: 0.9,
                });
                items.push(StrategyItem {
                    focus: "shortcode/block/template rendering".into(),
                    rationale: "CMS-specific renderers may bypass the default escaping".into(),
                    priority: 0.7,
                });
            }
            "Laravel" | "Rails" | "Django" | "Spring" | "ASP.NET" | "Express" => {
                if matches!(rendering_model, RenderingModel::Unknown) {
                    rendering_model = RenderingModel::ServerSideHtml;
                }
                items.push(StrategyItem {
                    focus: "reflected value in template output".into(),
                    rationale: format!("{name} renders server-side; check template auto-escaping gaps"),
                    priority: 0.8,
                });
                items.push(StrategyItem {
                    focus: "JSON responses rendered client-side".into(),
                    rationale: "API frameworks often return data a client inserts into the DOM".into(),
                    priority: 0.6,
                });
            }
            "Twig" | "Handlebars" | "Jinja2" => {
                rendering_model = RenderingModel::ServerSideHtml;
                items.push(StrategyItem {
                    focus: "raw/unescaped output directives".into(),
                    rationale: format!("{name} has explicit unescaped-output constructs worth locating"),
                    priority: 0.9,
                });
            }
            // A client-side sanitizer changes the whole approach: sinks are
            // defended, so testing shifts to configuration gaps and bypasses
            // rather than raw injection.
            "DOMPurify" => {
                items.push(StrategyItem {
                    focus: "DOMPurify configuration gaps (ALLOWED_ATTR/ADD_TAGS, RETURN_DOM)".into(),
                    rationale: "sinks are sanitized; look for permissive config, unsanitized SVG/MathML islands, and post-sanitize DOM mutation".into(),
                    priority: 0.8,
                });
            }
            _ => {}
        }

        // Expert layer: when the *observed* version is a known-affected build,
        // promote the concrete weakness + gadget into the strategy. These are
        // the highest-priority items — a version-matched weakness is a far
        // stronger lead than a generic context probe. Gadgets are detection
        // guidance; confirmation against the live build is still required.
        for w in &f.known_weaknesses {
            let version = f.version.as_deref().unwrap_or("observed");
            items.push(StrategyItem {
                focus: format!("{} in {} {} [{}]", w.class.label(), f.technology, version, w.id),
                rationale: format!("{} — Gadget: {}", w.summary, w.gadget),
                priority: 0.97,
            });
        }
    }

    // Derive the rendering model from categories when no framework-specific
    // rule fired. A server-side template/admin stack renders HTML on the
    // server; a client framework implies a SPA. Deterministic and derived
    // from what was detected, never guessed.
    if matches!(rendering_model, RenderingModel::Unknown) {
        let has_frontend_framework = findings
            .iter()
            .any(|f| f.category == TechCategory::FrontendFramework);
        let has_server_rendering = findings.iter().any(|f| {
            matches!(
                f.category,
                TechCategory::TemplateEngine
                    | TechCategory::BackendFramework
                    | TechCategory::Cms
                    | TechCategory::WebServer
            )
        });
        rendering_model = if has_frontend_framework {
            RenderingModel::ClientSideSpa
        } else if has_server_rendering {
            RenderingModel::ServerSideHtml
        } else {
            RenderingModel::Unknown
        };
    }

    // A server-rendered stack with no specific rule still deserves the
    // generic server-side investigation items rather than an empty strategy.
    if items.is_empty() && rendering_model == RenderingModel::ServerSideHtml {
        items.push(StrategyItem {
            focus: "reflected value in server-rendered HTML output".into(),
            rationale: "server-rendered stack detected; check output escaping in each context".into(),
            priority: 0.7,
        });
        items.push(StrategyItem {
            focus: "attribute and JavaScript context escaping".into(),
            rationale: "server templates often escape HTML text but not attribute/JS contexts".into(),
            priority: 0.6,
        });
    }

    // A WAF is not a rendering model but does change testing: representation
    // variation matters more, and blocks must not read as findings.
    if findings.iter().any(|f| f.category == TechCategory::Waf) {
        items.push(StrategyItem {
            focus: "edge-layer discrimination before interpreting responses".into(),
            rationale: "a WAF is present; a block is not an XSS result".into(),
            priority: 0.95,
        });
    }

    // De-duplicate by focus, keeping the highest priority.
    items.sort_by(|a, b| {
        b.priority
            .partial_cmp(&a.priority)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    items.dedup_by(|a, b| a.focus == b.focus);

    XssStrategy {
        rendering_model,
        items,
        driven_by,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::technology::{detect, Observation};

    fn finding(name: &str, category: TechCategory) -> TechnologyFinding {
        TechnologyFinding {
            technology: name.into(),
            category,
            version: None,
            confidence: 0.9,
            evidence: vec![],
            distinct_sources: 1,
            known_weaknesses: vec![],
        }
    }

    #[test]
    fn react_strategy_targets_raw_html() {
        let strategy = build_strategy(&[finding("React", TechCategory::FrontendFramework)]);
        assert_eq!(strategy.rendering_model, RenderingModel::ClientSideSpa);
        assert!(strategy.items.iter().any(|i| i.focus.contains("dangerouslySetInnerHTML")));
    }

    #[test]
    fn angular_strategy_targets_bypass_api() {
        let strategy = build_strategy(&[finding("Angular", TechCategory::FrontendFramework)]);
        assert!(strategy.items.iter().any(|i| i.focus.contains("bypassSecurityTrust")));
    }

    #[test]
    fn vue_strategy_targets_v_html() {
        let strategy = build_strategy(&[finding("Vue.js", TechCategory::FrontendFramework)]);
        assert!(strategy.items.iter().any(|i| i.focus.contains("v-html")));
    }

    #[test]
    fn wordpress_strategy_targets_stored_content() {
        let strategy = build_strategy(&[finding("WordPress", TechCategory::Cms)]);
        assert!(strategy.items.iter().any(|i| i.focus.contains("stored XSS")));
        assert_eq!(strategy.rendering_model, RenderingModel::ServerSideHtml);
    }

    #[test]
    fn laravel_strategy_targets_template_output() {
        let strategy = build_strategy(&[finding("Laravel", TechCategory::BackendFramework)]);
        assert!(strategy.items.iter().any(|i| i.focus.contains("template output")));
    }

    #[test]
    fn waf_presence_adds_edge_discrimination() {
        let strategy = build_strategy(&[finding("Cloudflare", TechCategory::Waf)]);
        assert!(strategy.items.iter().any(|i| i.focus.contains("edge-layer")));
    }

    #[test]
    fn no_technology_yields_generic_strategy() {
        let strategy = build_strategy(&[]);
        assert!(strategy.is_generic());
        assert_eq!(strategy.rendering_model, RenderingModel::Unknown);
    }

    #[test]
    fn different_stacks_produce_different_strategies() {
        let react = build_strategy(&[finding("React", TechCategory::FrontendFramework)]);
        let twig = build_strategy(&[finding("Twig", TechCategory::TemplateEngine)]);
        let react_focus: Vec<&str> = react.items.iter().map(|i| i.focus.as_str()).collect();
        let twig_focus: Vec<&str> = twig.items.iter().map(|i| i.focus.as_str()).collect();
        assert_ne!(react_focus, twig_focus, "strategies must differ by technology");
    }

    #[test]
    fn items_are_sorted_by_priority() {
        let strategy = build_strategy(&[
            finding("React", TechCategory::FrontendFramework),
            finding("Cloudflare", TechCategory::Waf),
        ]);
        for w in strategy.items.windows(2) {
            assert!(w[0].priority >= w[1].priority);
        }
    }

    #[test]
    fn integration_with_detector() {
        let obs = vec![Observation::header("x-powered-by", "Next.js")];
        let findings = detect(&obs);
        let strategy = build_strategy(&findings);
        assert!(!strategy.is_generic());
        assert!(strategy.driven_by.iter().any(|d| d.contains("Next.js")));
    }

    #[test]
    fn known_weakness_is_promoted_to_a_top_priority_item() {
        use crate::technology::{KnownWeakness, WeaknessClass};
        let mut f = finding("jQuery", TechCategory::ThirdPartyLibrary);
        f.version = Some("3.4.1".into());
        f.known_weaknesses = vec![KnownWeakness {
            id: "CVE-2020-11022".into(),
            class: WeaknessClass::MutationXss,
            affected: "<3.5.0".into(),
            summary: "htmlPrefilter mutation XSS".into(),
            gadget: "$(html) with crafted markup".into(),
        }];
        let strategy = build_strategy(&[f]);
        let item = strategy
            .items
            .iter()
            .find(|i| i.focus.contains("CVE-2020-11022"))
            .expect("version-matched weakness must become a strategy item");
        assert!((item.priority - 0.97).abs() < f32::EPSILON);
        assert!(item.focus.contains("jQuery") && item.focus.contains("3.4.1"));
        assert!(item.rationale.contains("Gadget:"));
        // It must be the highest-priority lead (items are priority-sorted).
        assert_eq!(strategy.items.first().map(|i| i.priority), Some(0.97));
    }

    #[test]
    fn angularjs_strategy_targets_csti() {
        let strategy = build_strategy(&[finding("AngularJS", TechCategory::FrontendFramework)]);
        assert_eq!(strategy.rendering_model, RenderingModel::ClientSideSpa);
        assert!(strategy
            .items
            .iter()
            .any(|i| i.focus.contains("client-side template injection")));
    }
}
