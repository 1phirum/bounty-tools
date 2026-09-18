# BugTools — Three-Language Architecture (v1.0)

Status: **PROPOSED ARCHITECTURE — awaiting review before implementation**
Per the master engineering prompt (§31): no implementation code follows this
document. This is the architecture and repository map for review.

Ground rule: this document is written against **what exists today**, not a
fantasy tree. Every "EXISTS" claim was verified by audit on 2026-09-18.
Every "GAP" is honest.

---

## 0. Current State Audit (the honest baseline)

| Layer | Status | Evidence |
|---|---|---|
| Rust core | **EXISTS, substantial** | 15 crates, ~28,600 LOC, 688 tests. SQLi engine (284 tests) and XSS engine (331 tests) are the strongest subsystems; both already implement baseline → hypothesis → controlled experiment → repetition-verified evidence |
| CLI | **EXISTS** | CLI-only since commit f57da68c; 9 commands, one file per command |
| Go acquisition | **STUB** | 212 LOC total; crawler-go and dns-go are empty directories; http-go is 60 lines; recon-go is 152. A protobuf control-plane contract EXISTS (`contracts/v1`) but no live bridge |
| Python research lab | **DOES NOT EXIST** | Zero .py files in the repository |
| Datasets | **DO NOT EXIST** | `datasets/` is not present |

**Implication:** the Rust core already embodies the brief's central pipeline
(observation → baseline → hypothesis → experiment → differential → evidence →
confidence) in its two research engines. The genuine gaps are (1) the Go
acquisition layer is a stub, (2) the Python lab is absent, (3) the shared
domain-model layer is spread across `bugtools-core`/`bugtools-sql`/
`bugtools-xss` rather than centralized, and (4) no dataset infrastructure.

---

## 1. System Architecture

```
                         BUGTOOLS
                            │
           ┌────────────────┼─────────────────┐
           │                │                 │
         RUST              GO              PYTHON
       CORE/BRAIN       ACQUISITION        RESEARCH
           │                │                 │
     reasoning         concurrency       statistics
     evidence          networking        ML/analysis
     orchestration     DNS/HTTP          datasets
     scope             discovery         modeling
     SQLi/XSS          crawling          experimentation
     scheduler         collectors       visualization
     CLI               streaming
```

**Authority rule (§2):** Rust is the source of truth. Go returns normalized
observations through the event bus; Python returns analytical results that
Rust must fold into evidence as *analyst input*, never as autonomous
findings. Neither language can override Rust's scope or safety decisions.

---

## 2. Responsibility Boundaries (no duplication)

### Rust OWNS (authoritative)
- Domain models: Target, Asset, Endpoint, Parameter, Request/Response,
  Observation, Evidence, Hypothesis, Experiment, Finding, Baseline,
  Differential, TechnologyFingerprint, ScopeRule, WafObservation
- Scope enforcement, rate limiting, request budgets, retry policy
- Session/cookie/auth context (single source of session truth)
- Scheduler, event bus, attack-surface graph, persistence
- SQLi engine, XSS engine, differential engine, confidence engine
- CLI

### Go OWNS (acquisition throughput only)
- High-volume DNS resolution, subdomain collection, HTTP probing,
  crawler workers, passive source collection
- Returns **normalized observations** (typed protobuf), never ad-hoc strings
- No business logic, no findings, no scope decisions — receives scope as
  job constraints and enforces them mechanically

### Python OWNS (offline research lab)
- Statistical analysis, clustering, anomaly detection, feature extraction
- Dataset construction and versioning, experiment replay
- Browser-assisted validation *research* (results fold back as evidence)
- Explicitly NOT a remote-execution surface: it reads exported JSONL/Parquet
  and emits structured analytical results

**Duplication guard:** each capability appears in exactly one language.
Where Rust already implements it (e.g. differential analysis — EXISTS in
bugtools-sql/analysis), Python consumes and studies it rather than
re-implementing it as a second source of truth.

---

## 3. Target Repository Map

Legend: ✅ EXISTS (verified) · 🟡 EXISTS, needs migration · 🔴 GAP (proposed)

```
bug-tools/
├── Cargo.toml                      ✅ workspace root
├── apps/bugtools-cli/              ✅ CLI-only, one file per command
│
├── crates/                         RUST CORE/BRAIN
│   ├── bugtools-domain/            🔴 NEW — extracted typed models
│   │   ├── src/target/             target, host, scheme, port, scope-rule
│   │   ├── src/asset/              asset, service, endpoint, parameter
│   │   ├── src/http/               method, request, response, headers,
│   │   │                           cookies, timing  (migrated from
│   │   │                           bugtools-core/src/http.rs)
│   │   ├── src/technology/         technology, category, version,
│   │   │                           evidence, hypothesis
│   │   ├── src/observation/        observation, signal, source, provenance
│   │   ├── src/experiment/         experiment, hypothesis, control, result
│   │   ├── src/evidence/           evidence, node, edge, graph
│   │   └── src/assessment/         assessment, status, limitation
│   │   RULES: no clap, no tokio, no reqwest, no fs, no terminal
│   │
│   ├── bugtools-errors/            🔴 NEW — typed errors, no anyhow scatter
│   ├── bugtools-ids/               🔴 NEW — stable ID minting (scan, trace,
│   │                               request, response, evidence, experiment,
│   │                               finding); today UUIDs are minted ad hoc
│   │                               in each module — this centralizes them
│   ├── bugtools-config/            🔴 NEW — runtime config (HTTP, proxy,
│   │                               output, profile)
│   ├── bugtools-policy/            🟡 EXISTS as bugtools-sql/policy.rs →
│   │                               promote to its own crate (scope rules +
│   │                               program policy + scanners_allowed)
│   ├── bugtools-budget/            🟡 EXISTS inside bugtools-sql/scheduler
│   │                               → promote (request/time/concurrency caps)
│   ├── bugtools-events/            ✅ EXISTS (protobuf event bus)
│   ├── bugtools-scheduler/         ✅ EXISTS (thin; grows with Go bridge)
│   ├── bugtools-http/              ✅ EXISTS 1507 LOC, 21 tests
│   ├── bugtools-dns/               ✅ EXISTS 470 LOC
│   ├── bugtools-crawler/           ✅ EXISTS 541 LOC, 22 tests
│   ├── bugtools-discovery/         ✅ EXISTS 748 LOC, 18 tests
│   ├── bugtools-runtime/           ✅ EXISTS (recon pipeline orchestrator)
│   ├── bugtools-sql/               ✅ EXISTS 12,982 LOC, 284 tests — the
│   │                               adaptive SQLi research engine
│   ├── bugtools-xss/               ✅ EXISTS 10,811 LOC, 331 tests — the
│   │                               XSS research engine
│   ├── bugtools-fingerprint/       🟡 EXISTS 93 LOC — becomes the Rust
│   │                               consumer of technology intelligence;
│   │                               deep detection lives in bugtools-xss
│   │                               today (technology.rs, 44 tests) and will
│   │                               move behind a shared trait
│   ├── bugtools-waf/               🟡 EXISTS as bugtools-sql/waf/ + layer
│   │                               classification → promote to its own crate
│   ├── bugtools-analysis/          🟡 EXISTS as bugtools-sql/analysis/
│   │                               (diff, timing, environment) → promote
│   │                               and share with the XSS engine
│   ├── bugtools-evidence/          🟡 EXISTS inside both engines → unify
│   ├── bugtools-confidence/        🟡 EXISTS as bugtools-xss/confidence.rs
│   │                               → promote, shared by all engines
│   ├── bugtools-engine/            🔴 NEW — generic ResearchEngine trait,
│   │                               experiment planner, hypothesis lifecycle
│   │                               (the framework SQLi/XSS already follow,
│   │                               made explicit and reusable for SSRF/
│   │                               SSTI/etc. without touching the core)
│   ├── bugtools-storage/           ✅ EXISTS 560 LOC (SQLite)
│   └── bugtools-export/            🔴 NEW — JSONL/Parquet exporters that
│                                   feed the Python lab
│
├── engines/                        GO ACQUISITION (gRPC workers)
│   ├── http-go/                    🟡 60 LOC stub + EXISTS proto contract
│   ├── recon-go/                   🟡 152 LOC
│   ├── crawler-go/                 🔴 EMPTY DIR → implement or remove
│   ├── dns-go/                     🔴 EMPTY DIR → Rust DNS already exists;
│   │                               Go adds throughput when needed
│   └── contracts/v1/*.proto        ✅ EXISTS — Coordinator service,
│                                   RequestJob/RequestObservation envelope
│
├── python/                         PYTHON RESEARCH LAB (all new)
│   ├── bugtools_lab/
│   │   ├── ingestion/              burp, har, openapi, sitemap, graphql
│   │   ├── analysis/               response_similarity, timing, anomaly,
│   │   │                           clustering, fingerprinting
│   │   ├── xss/                    html_context, js_context, dom_analysis,
│   │   │                           browser_verify
│   │   ├── sqli/                   response_analysis, timing, error, dataset
│   │   ├── research/               feature_extraction, hypothesis_analysis,
│   │   │                           evidence_graph, experiment_analysis
│   │   └── models/                 observation, response, evidence,
│   │                               experiment (Pydantic, mirroring Rust
│   │                               domain types via the export schema)
│   └── datasets/
│       ├── http/  xss/  sqli/  fingerprints/  responses/
│       (versioned: dataset_version, source, license, provenance,
│        feature_schema, created_at, validation_status)
│
├── fixtures/                       🔴 NEW — positive/negative/ambiguous/
│   │                                  WAF/dynamic/timing/auth fixtures
│   │                                  (per §24: a detector that cannot
│   │                                  separate positive from negative
│   │                                  fixtures is not production-ready)
├── tests/                          🔴 NEW — integration/ e2e/ regression/
│   └── knowledge/                  (technology/framework/waf profiles)
└── docs/architecture/              ✅ this document
```

---

## 4. Data Flow (the core pipeline, end to end)

```
RAW WORLD
  → GO ACQUISITION WORKERS (scope-constrained jobs via gRPC)
  → NORMALIZED OBSERVATIONS (protobuf → Rust event bus)
  → RUST NORMALIZATION (dynamic-value scrubbing: timestamps, UUIDs,
      CSRF tokens, counters — EXISTS in bugtools-sql/analysis/diff.rs)
  → BASELINE (multi-sample, stable/dynamic field separation — EXISTS)
  → HYPOTHESIS (ranked, supporting AND conflicting evidence — EXISTS)
  → CONTROLLED EXPERIMENT (control/treatment/repeat, each request carries
      its reason: DISCOVERY|BASELINE|CONTROL|TREATMENT|CORROBORATION|
      REPRODUCTION|CONTEXT_VALIDATION)
  → DIFFERENTIAL (status/headers/timing/body-structure/JSON/DOM — EXISTS)
  → EVIDENCE (append-only graph; contradictions retained — EXISTS)
  → CONFIDENCE + UNCERTAINTY (weighted score ≠ probability; corroboration
      requires distinct sources — EXISTS in both engines)
  → REPRODUCTION / REJECTION (repetition verification discards flaky
      results — EXISTS in bugtools-sql/adaptive/repetition.rs)
  → FINDING (builder REJECTS findings without limitations — EXISTS)
  → EXPORT (JSONL/Parquet → Python lab)
  → PYTHON ANALYTICAL RESULT (folds back as analyst input, never
      autonomous findings)
```

Every arrow that says EXISTS was verified against tests today.

---

## 5. Cross-Language Contracts

### Rust ⇄ Go (EXISTS in `contracts/v1`)
- gRPC `Coordinator.ExecuteHttpJob`: Rust sends `RequestJob` (with scope
  constraints), Go streams `RequestObservation` back.
- Envelope carries job_id/observation_id so every observation is traceable.
- **Gap to close:** only http-go has a contract; discovery/crawler need
  equivalent services or the empty dirs get removed.

### Rust → Python (proposed, via bugtools-export)
- Rust exports **versioned JSONL** (Parquet later) of observations,
  baselines, differentials, evidence, and hypotheses.
- Python `models/` are Pydantic mirrors of the export schema — they parse,
  never invent. Schema version is stamped in every export; mismatches fail
  loudly rather than silently misparse.
- Python → Rust: analytical results are structured JSON consumed as
  *evidence input with provenance "python-lab"*; Rust re-validates and owns
  the final confidence arithmetic.

### Non-goal
Python is never an RPC surface for live scanning. It reads exports and
writes results. This keeps it from becoming an uncontrolled
remote-execution path (§4 of the brief).

---

## 6. Domain-Model Relationships

```
Target 1─* Asset 1─* Endpoint 1─* Parameter
                       │
                       └─* Request ─* Response ─* Observation
                                                │
   Baseline *─1 Observation (reference)         │
   Experiment 1─* Request (each with a reason)  │
   Hypothesis *─* Evidence *─1 Observation      │
   Evidence ─* Evidence (supports/contradicts)  │
   Finding 1─* Evidence, 1─1 Assessment         │
   TechnologyFingerprint *─* Evidence           │
   WafObservation ─1 Response                   │
   ScopeRule governs every Request (fail-closed)│
   AuthContext/SessionContext tag every Request │
```

ID policy: every object gets a stable typed ID from `bugtools-ids`
(scan-, trace-, request-, response-, observation-, evidence-,
experiment-, finding-). Today UUIDs are minted ad hoc per module — that is
the consolidation target.

---

## 7. Failure Modes Considered

| Failure | Mitigation |
|---|---|
| Scope violation via Go worker | Jobs embed scope constraints; workers enforce mechanically; Rust re-validates every observation against scope on receipt (fail-closed — pattern EXISTS in policy.rs) |
| Auth-state confusion | AuthContext/SessionContext IDs tag every request; experiments pin their session; the brief's "never mix user sessions" becomes a typed invariant |
| Dynamic content false positives | Normalization layer (EXISTS) + repetition verification (EXISTS) discards flaky differentials |
| WAF misread as app behavior | Layer classification (EXISTS: EDGE_BLOCK ≠ APPLICATION_*; edge classes cannot contribute SQL evidence) |
| Retries distorting timing | Retry policy lives in the HTTP layer with explicit retry-count tagging; timing analysis (EXISTS) excludes retried samples |
| Python result treated as ground truth | Provenance-tagged as analyst input; Rust owns confidence arithmetic |
| Dataset poisoning | Versioned datasets with source/license/provenance/validation_status; unvalidated datasets never load |

---

## 8. Testing Strategy (§24 mapping)

| Level | Today | Target |
|---|---|---|
| Unit | 688 tests across crates | + fixtures trees with positive/negative/ambiguous/WAF/dynamic/timing/auth cases |
| Integration | Live-mock smoke runs (done ad hoc each session) | `tests/integration/` codified: http, fingerprint, attack-surface, evidence |
| Regression | Bugs fixed en route became inline tests | `tests/regression/` for the named weaknesses (long attrs, escaped quotes, regex literals, WAF blocks, flaky baselines) |
| Replay | Not built | Experiment replay from persisted evidence (Phase 16) |
| E2E | CLI verified per change | `tests/end_to_end/` with local mocks, no internet |

---

## 9. Implementation Phases (mapped to the brief's 17)

Phase 0 (this document) → review → then, in order, each ending with
compile/test/lint/coupling review:

1. **bugtools-domain** extraction (models out of core/sql/xss; no behavior
   changes, pure movement + re-exports) — lowest risk, highest leverage
2. **bugtools-errors + bugtools-ids** (typed errors; centralized ID minting)
3. **bugtools-config / policy / budget** promotion (policy.rs and the
   budget types already exist and are tested — promotion is movement)
4. **bugtools-engine** generic trait (make the hypothesis lifecycle SQLi/XSS
   already follow explicit and reusable)
5. **bugtools-export JSONL + python/ minimal lab** (ingestion + models +
   one real analysis: response similarity on exported observations)
6. **Go bridge reality check**: either implement the two empty Go engines
   against the existing proto contract or delete the empty dirs — a stub
   tree that looks alive is worse than an honest absence
7. Analysis/evidence/confidence/waf crate promotions (mechanical movement
   from bugtools-sql/bugtools-xss into shared crates)
8. Datasets + fixtures trees
9. Replay + persistence evolution
10. Performance/security review

**Ordering rationale:** the existing engines are the crown jewels — the
early phases are extraction and promotion that make them shared
infrastructure without rewriting them. New surface area (Python lab, Go
bridge) comes after the contracts are crisp.

---

## 10. Review Checklist (from §33, answered honestly today)

- Can this subsystem produce false positives? → The engines already
  mitigate: repetition verification, contradiction retention, mandatory
  limitations, confidence calibration. Remaining: fixture corpus to prove it
  at scale.
- Can we explain why every request was made? → In the SQLi adaptive engine,
  yes (rationale strings per candidate). Generalizing to every request
  everywhere: Phase 4 (experiment-reason tagging).
- Can the experiment be replayed? → Not yet; persistence evolution (Phase 9).
- Can scope be violated accidentally? → Fail-closed policy EXISTS; the Go
  job-constraint path is specified above but the bridge is a stub today.
- Can it operate without a GUI? → Yes; CLI-only since f57da68c.
- Can another language consume its output safely? → After bugtools-export
  (Phase 5); today JSON output exists but is not schema-versioned.
- Can it be unit tested without the network? → Yes: 688 tests run offline;
  live checks were always separate smoke runs.
