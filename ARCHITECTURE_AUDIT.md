# Architecture Audit — BugTools SQLi / WAF integration

Required by Phase 0 of the 2026-09-16 brief. Audit run against commit
`af516252` before any code was changed.

## Workspace

| Crate | Purpose | State |
|---|---|---|
| `bugtools-core` | domain models, scope rules, HTTP types | working |
| `bugtools-scope` | central scope enforcement, default deny | working |
| `bugtools-http` | bounded, rate-limited, scope-checked HTTP client | working |
| `bugtools-dns` | native resolver (A/AAAA/CNAME/MX/NS/TXT/SOA) | working |
| `bugtools-discovery` | CT + DNS brute-force discovery sources | working |
| `bugtools-crawler` | BFS frontier, normalization, HTML extraction | working |
| `bugtools-output` | `PipelineEvent` stream shared by CLI + GUI | working |
| `bugtools-runtime` | pipeline orchestrator | working |
| `bugtools-sql` | SQL research engine (see below) | working |
| `bugtools-storage` | SQLite persistence | working |
| `bugtools-fingerprint` | response normalization | working |
| `apps/bugtools-cli` | `bugtools` binary | working |
| `apps/gui` | egui workstation | REMOVED 2026-09-17: the platform is now CLI-only per the current architecture brief |

## bugtools-sql module map

| Existing module | Purpose | Target architecture | Required work |
|---|---|---|---|
| `detection.rs` | 6→8 DBMS signature detection | `dbms/fingerprint.rs` | keep; DB2/H2 added via `dbms_ext.rs` |
| `clause_map.rs` | 35-clause dialect table | `payload/registry/clauses` | keep as reference data |
| `probe.rs` | baseline→error→syntax→timing probes | `adaptive/` + `differential/` | keep; planning layer needed |
| `types.rs` | `ProbeResult`, `SqlAnalysisResult` | `models/` | keep |
| `context.rs` | `InputLocation`, `ValueKind`, `QueryRole` | `context/` | keep; hypothesis layer added |
| `baseline.rs` | median + stability | `baseline/profile.rs` | keep; needs variance/MAD |
| `differential/` | semantic JSON/HTML diff | `differential/` | keep; needs status/header/cookie/waf deltas |
| `waf/` | Cloudflare-only origin classifier | `bugtools-waf` | **extend**: vendor modules, layer enum |
| `evidence/` | evidence graph + confidence | `evidence/` | keep |
| `scheduler/` | probe scoring + request budget | `adaptive/` | keep |
| `controls/` | control-role experiment model | `causal/` | keep; needs executor |
| `generators/` | payload generation | `payload/` | **REPLACE STUBS** |

## Critical findings

### 1. Empty generators (highest priority)

`generators/boolean_based.rs` and `generators/union_based.rs` return
`vec![]` — they are placeholders that produce no payloads. This violates the
brief's rule against fake implementations. These must produce real,
context-aware candidates.

### 2. No boundary engine

There is no typed `Boundary` (prefix/suffix/quote-mode/termination). Payloads
currently embed their boundaries as literals. The brief requires boundaries
be a separate composition concern.

### 3. No safety gate

No `SafetyPolicy` inspects candidates before execution. Destructive
statement detection (DROP/DELETE/UPDATE/INSERT/stacked) does not exist.

### 4. WAF coverage is Cloudflare-only

`waf/classifier.rs` matches `cf-ray`/`Server: cloudflare` and nothing else.
No AWS/Akamai/Fastly/generic vendors, and no `LayerClass` enum separating
EDGE_BLOCK from APPLICATION_RESPONSE (the brief's §6 requirement).

### 5. Duplicate-layer risk (avoided)

`bugtools-http` and `bugtools-sql/waf` both model responses differently but
for different purposes (transport vs. origin classification). No
duplication requiring refactor; the WAF code should move to its own crate
in a future pass.

## Refactor decisions taken

- **Extend, don't rewrite.** `bugtools-sql` keeps all working modules.
- **Add** `payload.rs` (boundary + generation) and `safety.rs` rather than
  restructuring the crate tree wholesale, because a wholesale move would
  break the CLI, GUI, and 135 passing tests for no functional gain.
- **WAF vendors** land in `bugtools-sql/src/waf/` alongside the existing
  classifier so the layer enum and origin model stay in one place.

## Not implemented after this pass (tracked in MIGRATION.md)

Dedicated `bugtools-waf` and `bugtools-sqli` crates, UNION column-count
inference, stacked-query execution, causal executor, OOB listener, second
order executor, GraphQL/WebSocket locations, and the attack-surface
view. No placeholder UI or command claims these work.
