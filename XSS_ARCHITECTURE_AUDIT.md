# XSS Architecture Audit — BugTools

Audit of `crates/bugtools-xss/` and its integration with `bugtools-core`,
`bugtools-http`, `bugtools-parser`, `bugtools-runtime`, `bugtools-events`,
`bugtools-output` and `apps/bugtools-cli`, performed against commit `8648a92`
(before any changes requested by the deep-exploitability brief).

---

## 1. Current architecture

The XSS engine is a single crate implementing a linear, single-request pipeline:

```text
AnalyzeRequest (one request/response pair)
   │
   ├─ technology.rs      fingerprint (45 weighted signatures, threshold 0.6)
   ├─ strategy.rs        tech → rendering model + strategy items
   ├─ reflection/        detect + correlate reflected value
   │     ├─ detector     exact / html-encoded / url-encoded / partial / normalized
   │     ├─ correlation  resolve each point via parser/html + parser/javascript
   │     ├─ encoding     decode transforms (entity/percent/backslash/unicode)
   │     └─ normalizer   whitespace + case folding for comparison
   ├─ source/            DOM source reads (11 patterns)
   ├─ sink/              DOM sink calls (16 patterns, 3 risk tiers)
   ├─ taint/graph.rs     source → sink graph (line/substring heuristics)
   ├─ exploitability.rs  state machine, 12 stages
   ├─ confidence.rs      calibrated level (NOT a probability)
   ├─ assessment.rs      builder, confirmed ← ExecutionConfirmed only
   └─ engine.rs          orchestrates the above into XssAssessment
```

The invariant `reflection != injection != execution` is **genuinely enforced**:
`ExploitabilityMachine::observe()` rejects illegal transitions as errors
(`exploitability.rs:184`), `is_finding()` is true only at `ExecutionConfirmed`
(`exploitability.rs:50`), and `AssessmentBuilder` refuses a finding asserted
without limitations (`assessment.rs:143`). The engine cannot confirm execution
without a browser: `engine.rs:146` calls `confirm_on_execution(..., false)`.

**Scale:** 20 source files, ~5,000 lines, ~164 unit tests.

---

## 2. Dependency graph

```text
apps/bugtools-cli
   ├─ bugtools-xss        (analyze, detect, build_strategy, extract_*)
   ├─ bugtools-sql        (program policy — reused by tech for scope!)
   ├─ bugtools-runtime    (pipeline command only)
   └─ reqwest directly    (tech command builds its own client)

crates/bugtools-xss
   ├─ bugtools-core       (workspace types — currently minimal use)
   ├─ scraper             (HTML — see §4, the parse result is discarded)
   ├─ regex
   └─ serde / uuid / tracing

crates/bugtools-runtime
   └─ discovery, dns, http, crawler, output, scope   (NO bugtools-xss dependency)

crates/bugtools-events
   └─ bugtools-core::events  (broadcast EventBus + gRPC — built for the GUI)

crates/bugtools-parser
   └─ regex + url         (endpoint/URL extraction only — no HTML/JS parsing)
```

**Key structural fact:** `bugtools-runtime` does not depend on `bugtools-xss`.
The recon pipeline (discovery → DNS → HTTP → crawl) never invokes XSS analysis.
The only bridge is the `tech` CLI command, which calls `analyze()` directly.

---

## 3. What is wired, and what is not

### Wired

- `tech`/`x` command (`apps/bugtools-cli/src/commands/tech.rs`):
  - resolves program policy, checks host scope (`tech.rs:52`)
  - GETs the URL, fingerprints, builds strategy (`tech.rs:94-98`)
  - sends ONE benign marker probe (`btprobe########`) as `bugtools_probe` query
    parameter (`tech.rs:148-160`)
  - extracts inline scripts, builds `AnalyzeRequest`, calls
    `bugtools_xss::analyze()` (`tech.rs:162-171`)
  - prints reflection, html/js context, uncertainty, confidence, transitions,
    limitations

### Not wired / unwired surfaces

| Surface | Status |
|---|---|
| `bugtools-runtime` Pipeline | **no XSS stage** — recon never triggers analysis |
| `bugtools-output` PipelineEvent | **no XSS event variants** exist |
| `bugtools-core::Finding` | engine never emits a `Finding`; results are printed, not persisted |
| `bugtools-events` EventBus | orphaned since the GUI removal; engine publishes nothing |
| `bugtools-http` SafeHttpClient | **bypassed** — `tech.rs` builds its own reqwest client, so requests are not centrally rate-limited/budgeted/scope-checked |
| POST/cookie/header/path parameters | probe is GET-query-only; one parameter, one reflection site |
| Candidate endpoint discovery | none — the engine analyzes only the exact URL handed to it |
| Browser verification | absent — `confirm_on_execution` is hardcoded `false` |

---

## 4. Dead code

1. **`parser/html.rs:144`** — `let _ = Html::parse_document(html);` parses the
   document and **discards the result**. The actual context resolution is done
   by the hand-rolled `tokenize_with_offsets()`. The `scraper` parse is dead
   weight and actively misleading (the doc comment claims a real parser).
2. **`context.rs` (legacy)** — `analyze_context`, `XssContext`, `ContextType`,
   `Reflection`, `ReflectionEncoding` are the pre-parser heuristic
   (160-char window, quote-parity). The engine no longer uses them —
   `tech.rs` reads `assessment.reflection.html_context` instead. They survive
   only via `lib.rs` re-exports and the `full_phase_one_pipeline` integration
   test.
3. **`taint/graph.rs:182`** — `SourceRead::label_backing(&self, _path)` takes a
   parameter it ignores.
4. **`bugtools-events` (+ gRPC server bin)** — was the GUI's event transport;
   with a CLI-only platform it is unused by any command.
5. **`exploitability.rs` `ExecutionAttempt`/`ExecutionObserved` transitions** —
   reachable in tests only; no production path can produce them.

---

## 5. Duplicated logic

1. **Two context analyzers.** `context.rs::analyze_context` (heuristic) and
   `parser/html.rs::parse_at` (tokenizer). Same purpose, different fidelity.
   The heuristic is now a fallback inside `parse_at` *plus* a standalone
   module — two places to maintain.
2. **Two script extractors** in `technology.rs` (`extract_script_srcs`,
   `extract_inline_scripts`) that duplicate tag-scanning logic also present in
   `parser/html.rs::tokenize_with_offsets`.
3. **Two HTTP paths.** `tech.rs` re-implements client construction, header
   resolution and response collection that `bugtools-http::SafeHttpClient`
   already provides (scope-checked, rate-limited, budgeted).
4. **`bugtools-parser` vs `bugtools-xss/src/parser`** — no functional overlap
   (endpoint regex vs HTML/JS parsing), but the naming collision is confusing
   and will worsen as the XSS parser grows.

---

## 6. Partially implemented

| Area | State | Gap |
|---|---|---|
| JS "parser" | lexer only | no AST, no scope, no CFG; plain expressions resolve to `Unknown` (`javascript.rs` test `plain_expression_context`) |
| Taint graph | line/substring matching (`same_data_object`, `label_backing`) | no variable tracking, no interprocedural flow, no aliasing |
| Sanitizers | name list (`SANITIZERS`) | no context semantics; `textContent` counted as sanitizer *and* excluded as sink |
| Sinks | flat pattern table | no `SinkKind` semantics, no per-context safety model |
| Sources | flat pattern table | `attacker_control()` ratings exist but are unused downstream |
| Encoding | 4 decoders + `classify_encoding` round-trip check | no `EncodingStack`, no canonical value |
| Assessment | single request/response | no cross-request (stored) model at all |
| Confidence | score + level + independence | no evidence-graph backing; sources are string names |

---

## 7. Missing components (vs. the deep-exploitability brief)

P0-critical for the stated goal:

- **Evidence graph** — the taint graph is the only graph; no unified
  Input/Source/Transformation/Variable/Function/DOMMutation/Sink/Execution
  model with provenance on every edge.
- **JS AST + scope graph + CFG + call graph + data flow** — the lexer cannot
  support interprocedural taint, alias analysis, destructuring, closures,
  call chains or async flow.
- **FunctionSummary** — no interprocedural summarization/caching.
- **Alias analysis** — none; string equality only.
- **Context-sensitive taint** — sinks are classified `critical/high/medium`,
  not by HTML/JS/URL/CSS context semantics.
- **Browser verification subsystem** — `VerificationRequest` /
  `VerificationResult` / `ExecutionEvidence` boundary does not exist.
- **CSP / Trusted Types model** — absent.
- **DOM mutation model** — absent.
- **Stored / second-order cross-request evidence** — engine is single-request.
- **Async data flow** (Promise/await/fetch callbacks) — absent.
- **Module graph** — absent.
- **Framework analyzers** — `strategy.rs` produces guidance text only; no
  framework influences source/sink/sanitizer discovery.
- **Candidate prioritization queue** — absent.
- **Impact evidence model** — absent.
- **CLI integration through runtime** — absent (see §3).

---

## 8. What can be reused (do not rewrite)

- `exploitability.rs` state machine — extend, keep as-is. It is the strongest
  part; the brief explicitly says improve, not replace.
- `confidence.rs` calibration philosophy (score ≠ probability, independence
  gates) — extend with evidence-graph backing.
- `assessment.rs` builder + `MissingLimitations` invariant — keep.
- `technology.rs` corroboration model — keep; add framework *analyzers* as a
  separate layer, do not convert signatures into vulnerability claims.
- `reflection/` detection + encoding round-trip classification — solid, reuse
  as the reflection evidence feeder.
- `parser/html.rs` tokenizer — good backbone for the deep context engine
  (needs namespace/MathML/foreign-content, and the dead scraper call removed).
- `parser/javascript.rs` lexer — keep as the *first pass* of an AST pipeline;
  do not discard it.
- `strategy.rs` — keep as advisory layer; never let it imply vulnerability.
- `bugtools-core` `HttpRequest`/`HttpResponse`/`Finding`/`Evidence` types —
  the engine should emit these instead of printing.

---

## 9. Roadmap

### P0 — integrity and wiring (no new analysis)

1. Remove the dead `Html::parse_document` call (or actually consume it).
2. Route `tech` through `SafeHttpClient` so requests are scope-checked,
   rate-limited and budgeted centrally; drop the ad-hoc reqwest client.
3. Retire `context.rs`: fold the integration test onto the real parser and
   delete the module (or gate it behind `#[cfg(test)]` as a comparison
   fixture). Also drop the unused re-exports from `lib.rs`.
4. Define `VerificationRequest` / `VerificationResult` / `ExecutionEvidence`
   trait boundary in a new `verification` module (no browser impl yet) so
   `confirm_on_execution` has a real interface to call.
5. Clean up `label_backing` dead parameter and `decode_percent` boundary logic.
6. Add XSS `PipelineEvent` variants and emit `bugtools-core::Finding` from the
   engine so results are persisted, not just printed.

### P1 — program analysis core

7. JS AST + scope graph (reuse the lexer as pass 1).
8. Data-flow taint replacing `same_data_object`: variables, destructuring,
   assignments, template interpolation, property writes/reads, arrays.
9. Interprocedural analysis with cached `FunctionSummary` (arguments →
   parameters → returns → caller).
10. Alias analysis (`AliasSet`, object/property identity).
11. Context-sensitive taint (`Html`/`Attribute`/`JavaScript`/`Url`/`Css`).
12. Unified evidence graph with provenance-carrying edges; back `confidence`
    with real nodes instead of source-name strings.
13. Sanitizer semantics (kind, context, configuration, confidence) +
    `EncodingStack` / canonical value.
14. CSP + Trusted Types parsing producing `MitigationBlocked` evidence.
15. Semantic sink model (`SinkKind` + required conditions + parser semantics).

### P2 — depth and verification

16. Browser verifier behind the P0 boundary (DOM mutations, execution events,
    CSP/TT violations) — enables real `ExecutionConfirmed`.
17. DOM mutation model (`DOMMutation` with target, provenance, resulting
    context).
18. Stored/second-order cross-request evidence graph with correlation IDs.
19. Async data flow (Promise/await/timer/event listeners/fetch).
20. SPA lifecycle phases; module graph.
21. Framework analyzers (React/Angular/Vue/jQuery/Next/templates) influencing
    source/sink/sanitizer discovery — detection must never imply vuln.
22. Candidate prioritization queue + impact evidence model.
23. `docs/xss/*` documentation set.

---

## 10. Migration risks

- **Breaking the state machine is the biggest risk.** Any refactor that lets
  `confirmed` become true without `ExecutionConfirmed` destroys the engine's
  core value. The machine must be extended, and every new evidence path must
  route through `observe()`.
- **The lexer→AST transition** will change offsets. Reflection offsets feed
  `parse_at`/`lex_at`; an AST must preserve byte offsets or re-derive them,
  or the existing 164 tests break en masse.
- **Scraper dependency** is heavy; if the deep context engine keeps a hand
  tokenizer, evaluate whether `scraper`/`html5ever` should stay at all (the
  GUI that justified much of it is gone).
- **Performance.** Interprocedural analysis on inline scripts can blow up;
  the brief itself demands bounded traversal, memoization and candidate
  pruning — these are architecture constraints, not optimizations.
- **CLI stability.** `tech` output shape is user-facing; keep the current
  human/JSON output while adding the explainability trace alongside.
- **Test volume.** 164 tests currently pass; every refactor step must keep
  them green. The lexer/AST work should land behind the existing lexer as a
  fallback first, mirroring how `parse_at` already keeps `heuristic_context`.

---

## 11. Recommended execution order

Do not attempt P1/P2 as one change. Land in this order, each step
independently shippable and tested:

```text
P0.1 dead scraper call + label_backing + decode_percent   (small, safe)
P0.2 retire context.rs                                     (removes duplication)
P0.3 SafeHttpClient routing for tech                       (security wiring)
P0.4 verification trait boundary                           (interface only)
P0.5 PipelineEvent/Finding emission                        (persistence)
P1.1 AST + scope graph (lexer preserved as fallback)
P1.2 data-flow taint (replace same_data_object)
P1.3 interprocedural + FunctionSummary
P1.4 alias + context-sensitive taint
P1.5 evidence graph backs confidence
P1.6 sanitizer semantics + encoding stack
P1.7 CSP / Trusted Types
P2.+  browser verifier, DOM model, stored, async, frameworks, docs
```

---

## 12. Invariants that must survive every step

```text
1.  reflection != injection != execution
2.  confirmed == ExecutionConfirmed (single source: the machine)
3.  illegal transitions are errors, never silent passes
4.  every finding carries limitations
5.  a weighted score is never a probability
6.  technology detection is never vulnerability evidence
7.  WAF detection is never vulnerability evidence
8.  versions are never invented
9.  a sanitizer is context-sensitive, never a name match
10. no browser evidence ⇒ no execution confirmation
```
