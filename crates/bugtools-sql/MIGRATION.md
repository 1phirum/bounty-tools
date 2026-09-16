# SQL Research Engine — Migration Plan

This document tracks the phased migration of `bugtools-sql` from a single
DBMS-detection engine into the full research workstation described in the
architecture brief. It exists so that **nothing is marked complete until it
actually is**, and so unimplemented capabilities are visible rather than
silently faked in the UI.

## Status legend

- **DONE** — implemented, tested, wired.
- **PARTIAL** — some of the phase exists; gaps listed.
- **TODO** — not implemented. The abstraction may exist; behaviour does not.

---

## Phase 1 — Request model, cookies, raw import, parameter typing

| Feature | Status | Location |
|---|---|---|
| Complete `RequestTemplate` (method/scheme/host/port/path/query/path-params/headers/cookies/body/body_type/auth/source) | **DONE** | `request/model.rs` |
| Stable per-input IDs (`InputSlot`) | **DONE** | `request/model.rs` |
| URL parsing + reconstruction roundtrip | **DONE** | `request/model.rs` |
| JSON body input extraction incl. nested objects and array indices | **DONE** | `request/model.rs` |
| Form-urlencoded input extraction | **DONE** | `request/model.rs` |
| Framing headers excluded from inputs | **DONE** | `request/model.rs` |
| Cookie jar: request `Cookie:` parsing | **DONE** | `request/cookies.rs` |
| Cookie jar: response `Set-Cookie` parsing with attributes (Path/Domain/Secure/HttpOnly/SameSite/Max-Age) | **DONE** | `request/cookies.rs` |
| Cookie deletion semantics (empty value) | **DONE** | `request/cookies.rs` |
| Cookie value masking for display/logs | **DONE** | `request/cookies.rs` |
| Per-target / per-scan cookie profiles | **DONE** | `request/cookies.rs` |
| Cookie expiry pruning | **DONE** | `request/cookies.rs` |
| Raw HTTP import (Burp-style), CRLF-tolerant | **DONE** | `request/parser.rs` |
| Raw HTTP export | **DONE** | `request/parser.rs` |
| Auth extraction (Bearer, cookies) during raw import | **DONE** | `request/parser.rs` |
| Value-type inference from observed values (not names) | **DONE** | `parameter/classifier.rs` |
| Type inference with multi-sample agreement | **DONE** | `parameter/classifier.rs` |
| Multipart body parameter extraction | **TODO** | requires a multipart parser |
| Basic-auth parse during raw import | **PARTIAL** | Bearer only; Basic is TODO |
| CSRF token strategies (`AuthContext.csrf_strategy`) | **TODO** | field not yet present |

## Phase 2 — Endpoint discovery, baseline, response fingerprinting

| Feature | Status | Notes |
|---|---|---|
| Baseline collection + stability (`baseline.rs`) | **DONE** (pre-existing) | median + stability classification |
| Response fingerprinting | **PARTIAL** | `bugtools-fingerprint` crate normalizes timestamps/IDs; not yet wired to `ResponseFingerprint`-based diffing in this crate |
| Crawler (HTML links/forms) | **TODO** | |
| sitemap.xml / robots.txt discovery | **TODO** | |
| JavaScript endpoint extraction | **TODO** | |
| OpenAPI / Swagger ingestion | **TODO** | |
| GraphQL introspection | **TODO** | |
| Endpoint deduplication + grouping | **TODO** | |

## Phase 3 — SQL context, DBMS hypotheses, clause mapping, evidence

| Feature | Status | Notes |
|---|---|---|
| DBMS signature detection (6 families) | **DONE** (pre-existing) | `detection.rs` |
| Clause syntax/dialect map (35 clauses) | **DONE** (pre-existing) | `clause_map.rs` |
| Probe pipeline (baseline/error/syntax/timing/clause) | **DONE** (pre-existing) | `probe.rs` |
| Generators (error/time/boolean/union/syntax/clause) | **DONE** (pre-existing) | `generators/` |
| Input location + value kind + query role classification | **DONE** (pre-existing) | `context.rs` |
| Multi-hypothesis SQL context with probabilities | **PARTIAL** | single `SqlContext` on result; probabilistic engine TODO |
| Evidence model with IDs, supports/contradicts | **TODO** | `evidence_id` is a placeholder field |
| Evidence graph + correlation | **TODO** | |
| Contradiction handling | **TODO** | design exists in brief; code does not |

## Phase 4 — Adaptive scheduler

| Feature | Status | Notes |
|---|---|---|
| Probe planner scaffold | **PARTIAL** | `controls/planner.rs` exists; scoring TODO |
| Information-gain scoring | **TODO** | |
| Budget enforcement (requests/rate/concurrency) | **PARTIAL** | `bugtools-http` enforces rate + budget; not surfaced in SQL scheduler |
| Timing statistics (median/stddev/percentiles) | **TODO** | `baseline.rs` computes median only |
| WAF/rate-limit/auth-failure classification | **PARTIAL** | `waf/` module exists; not integrated into scan decisions |

## Phase 5 — Second-order, API/GraphQL intelligence

All **TODO**.

## Phase 6 — sqlmap adapter, hybrid backend

All **TODO**. No `SqlBackend` trait yet.

## Phase 7 — Professional UI, reporting, persistence

| Feature | Status | Notes |
|---|---|---|
| egui workstation dashboard with real detection panels | **DONE** | `apps/gui/src/workstation.rs` |
| Scan history (in-memory) | **DONE** | session-only; not persisted |
| Persistence of scans/cookies/evidence to SQLite | **TODO** | `bugtools-storage` has projects/findings; not scan data |
| JSON / Markdown reports, evidence bundles | **TODO** | GUI has a basic findings report only |

---

## Honesty constraints (from the brief, §35)

1. No UI control is rendered without a backing implementation.
2. No scan result is fabricated. Panels show explicit empty states.
3. `Confirmed` is only reachable through evidence the engine actually holds.
4. Where an abstraction exists but behaviour does not, it is marked **TODO**
   here and surfaced as "not implemented" in the UI.
