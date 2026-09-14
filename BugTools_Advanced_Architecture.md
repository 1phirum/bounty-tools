# BugTools — Advanced Bug-Bounty Research Workstation

> **Project root:** `C:\bug-tools`
>
> **Stack:** Rust + Go + Tauri + React + TypeScript + SQLite
>
> **Goal:** Build a modular, auditable desktop security-research workstation for **authorized bug-bounty programs and owned systems**.
>
> **Design principle:** Build the platform first, then add scanners as independent engines. Do not build one giant scanner or one giant payload list.

---

## 1. Project Vision

BugTools should eventually provide a single desktop interface for:

- Scope management
- Project management
- Reconnaissance
- DNS enumeration
- HTTP probing
- URL and endpoint discovery
- JavaScript analysis
- Technology fingerprinting
- Parameter inventory
- SQL-injection research
- Request/response comparison
- Findings and evidence management
- Scan history
- Reports and exports
- Rate limiting and request budgets
- Authentication profiles
- Worker/job management

The application should be designed around this pipeline:

```text
                    ┌──────────────────────┐
                    │      React UI        │
                    │ TypeScript + Vite    │
                    └──────────┬───────────┘
                               │
                         Tauri IPC
                               │
                    ┌──────────▼───────────┐
                    │    Rust Controller   │
                    │ Jobs / Scope / State │
                    └──────────┬───────────┘
                               │
             ┌─────────────────┼─────────────────┐
             │                 │                 │
      ┌──────▼──────┐   ┌──────▼──────┐   ┌──────▼──────┐
      │ Rust Engine │   │  Go Workers │   │   Storage   │
      │ Core/SQL    │   │ Recon/Crawl │   │   SQLite    │
      └──────┬──────┘   └──────┬──────┘   └─────────────┘
             │                 │
             └─────────────────┼─────────────────┘
                               ▼
                        Evidence / Findings
```

---

# 2. Architecture Rules

These rules should guide the entire project.

## Rule 1 — UI never performs scanning directly

Bad:

```text
React → HTTP request → target
```

Good:

```text
React
  ↓
Tauri command
  ↓
Rust controller
  ↓
Scope validation
  ↓
Rate limiter
  ↓
Worker
  ↓
Target
```

---

## Rule 2 — Scope enforcement happens before network execution

Every network operation must pass through the scope engine.

```text
Request
   ↓
Scope Validator
   ↓
┌───────────────┐
│ Is it allowed?│
└───────┬───────┘
        │
   ┌────┴────┐
   │         │
  YES        NO
   │         │
   ▼         ▼
Execute    Reject
```

Never rely only on the UI to enforce scope.

---

## Rule 3 — Scanner modules must be replaceable

A module should not know how the UI works.

```text
SQL Engine
   ↓
Input
   ↓
Analysis
   ↓
Structured Result
```

The UI only displays the result.

---

## Rule 4 — Rules should be data-driven

Do not hard-code every SQL rule inside Rust.

Use:

```text
rules/
└── sql/
    ├── generic/
    ├── mysql/
    ├── postgresql/
    ├── mssql/
    ├── oracle/
    └── sqlite/
```

This allows rules to evolve independently from the core engine.

---

# 3. Repository Structure

Recommended final structure:

```text
C:\bug-tools\
│
├── apps/
│   └── desktop/
│       ├── src/
│       │   ├── app/
│       │   ├── assets/
│       │   ├── components/
│       │   ├── layouts/
│       │   ├── pages/
│       │   │   ├── Dashboard/
│       │   │   ├── Projects/
│       │   │   ├── Scope/
│       │   │   ├── Recon/
│       │   │   ├── HTTP/
│       │   │   ├── URLs/
│       │   │   ├── JavaScript/
│       │   │   ├── SQL/
│       │   │   ├── Findings/
│       │   │   ├── Reports/
│       │   │   └── Settings/
│       │   │
│       │   ├── features/
│       │   │   ├── projects/
│       │   │   ├── targets/
│       │   │   ├── recon/
│       │   │   ├── crawler/
│       │   │   ├── sql/
│       │   │   └── findings/
│       │   │
│       │   ├── stores/
│       │   ├── hooks/
│       │   ├── services/
│       │   ├── api/
│       │   ├── types/
│       │   └── utils/
│       │
│       ├── package.json
│       ├── tsconfig.json
│       └── vite.config.ts
│
├── src-tauri/
│   ├── src/
│   │   ├── main.rs
│   │   ├── commands/
│   │   ├── events/
│   │   ├── state/
│   │   ├── process/
│   │   ├── scheduler/
│   │   ├── security/
│   │   ├── database/
│   │   └── config/
│   │
│   ├── capabilities/
│   └── tauri.conf.json
│
├── crates/
│   ├── bugtools-core/
│   ├── bugtools-http/
│   ├── bugtools-scope/
│   ├── bugtools-parser/
│   ├── bugtools-storage/
│   ├── bugtools-scheduler/
│   ├── bugtools-events/
│   ├── bugtools-fingerprint/
│   └── bugtools-sql/
│
├── engines/
│   ├── recon-go/
│   ├── dns-go/
│   ├── crawler-go/
│   └── http-go/
│
├── modules/
│   ├── subdomain/
│   ├── dns/
│   ├── http-probe/
│   ├── crawler/
│   ├── javascript/
│   ├── parameters/
│   ├── technology/
│   └── sql-injection/
│
├── rules/
│   ├── sql/
│   │   ├── generic/
│   │   ├── mysql/
│   │   ├── postgresql/
│   │   ├── mssql/
│   │   ├── oracle/
│   │   └── sqlite/
│   │
│   └── technologies/
│
├── migrations/
├── wordlists/
├── configs/
├── tests/
├── docs/
├── examples/
├── scripts/
│
└── workspace/
    ├── projects/
    ├── exports/
    ├── logs/
    └── cache/
```

---

# 4. Technology Responsibilities

| Technology | Main responsibility |
|---|---|
| React | UI |
| TypeScript | Frontend types/business presentation |
| Tauri | Desktop application bridge |
| Rust | Controller, security boundaries, SQL engine, parsing |
| Go | High-concurrency network workers |
| SQLite | Local project/result database |
| TOML | Configuration/rules |
| JSON | Worker/event interchange |
| Markdown | Reports |

### Why Rust?

Use Rust for components where correctness, control, parsing, and predictable resource management matter.

### Why Go?

Use Go for worker-style tasks that benefit from simple concurrency:

```text
DNS
HTTP probing
Crawler
Enumeration
Worker pools
```

Do not force every component to use both languages.

---

# 5. Core Domain Model

Everything should revolve around a project.

```text
Project
│
├── Scope
│
├── Targets
│
├── Endpoints
│
├── Parameters
│
├── URLs
│
├── Technologies
│
├── Scan Jobs
│
├── Requests
│
├── Responses
│
└── Findings
```

Example:

```text
Project: Example Program
│
├── Scope
│   ├── example.com
│   ├── *.example.com
│   └── exclusions
│
├── Recon
│   ├── api.example.com
│   ├── app.example.com
│   └── dev.example.com
│
├── URLs
│   ├── /login
│   ├── /api/users
│   └── /search?q=
│
└── Findings
    ├── Candidate #1
    └── Candidate #2
```

---

# 6. Scope Engine

The scope engine is a critical security component.

## Scope object

```text
Scope
├── include_domains
├── exclude_domains
├── include_paths
├── exclude_paths
├── include_ports
├── exclude_ports
└── protocols
```

Example configuration:

```toml
[scope]

include_domains = [
    "example.com",
    "*.example.com"
]

exclude_domains = [
    "status.example.com"
]

protocols = [
    "https"
]
```

## Scope decision

```text
Target
  ↓
Normalize
  ↓
Canonicalize
  ↓
Domain match
  ↓
Path match
  ↓
Port match
  ↓
Exclusion match
  ↓
ALLOW / DENY
```

Every denied request should generate an audit event.

---

# 7. Job System

Every scanner operation becomes a job.

```text
Job
├── id
├── project_id
├── module
├── target
├── configuration
├── status
├── progress
├── created_at
├── started_at
└── finished_at
```

Statuses:

```text
QUEUED
RUNNING
PAUSED
CANCELLED
FAILED
COMPLETED
```

---

# 8. Scheduler

The scheduler controls jobs.

```text
                 Scheduler
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
      Job A        Job B        Job C
        │            │            │
        ▼            ▼            ▼
     Worker       Worker       Worker
```

Responsibilities:

- Queue jobs
- Limit concurrency
- Cancel jobs
- Pause jobs
- Resume jobs
- Track progress
- Apply request budgets
- Prevent duplicate work

---

# 9. Event System

Use events to update the UI without polling constantly.

Recommended events:

```text
project.created
project.updated

scan.created
scan.started
scan.progress
scan.paused
scan.cancelled
scan.failed
scan.completed

target.discovered
url.discovered
endpoint.discovered
parameter.discovered

request.started
request.completed

analysis.started
analysis.completed

finding.candidate
finding.updated
```

Example:

```text
Go Worker
    │
    ▼
Rust Controller
    │
    ▼
Tauri Event
    │
    ▼
React Store
    │
    ▼
Dashboard
```

---

# 10. HTTP Abstraction

All modules should use one HTTP abstraction.

```text
HttpClient
│
├── Request
│   ├── method
│   ├── URL
│   ├── headers
│   ├── cookies
│   ├── query
│   └── body
│
└── Response
    ├── status
    ├── headers
    ├── body
    ├── size
    └── duration
```

Then SQL, crawler, HTTP probing, etc. can share the same infrastructure.

---

# 11. Response Fingerprinting

Do not compare responses only with status codes.

Create a response fingerprint:

```text
ResponseFingerprint
├── status
├── content_type
├── content_length
├── body_hash
├── normalized_body_hash
├── redirect_location
├── response_time
└── structural_signature
```

This becomes the foundation of many analysis modules.

---

# 12. Normalization Engine

Dynamic values can make two equivalent responses look different.

Normalization can account for things such as:

```text
timestamps
request IDs
CSRF values
random identifiers
tracking values
dynamic counters
```

Conceptually:

```text
Raw Response
     ↓
Normalizer
     ↓
Normalized Response
     ↓
Fingerprint
```

Keep normalization conservative and configurable. Over-normalization can hide meaningful behavior.

---

# 13. SQL Research Engine

The SQL component should be a **framework**, not a huge static payload dictionary.

Architecture:

```text
                 SQL Engine
                     │
        ┌────────────┼─────────────┐
        ▼            ▼             ▼
 Context       DBMS Detection   Baseline
 Analyzer          │             Engine
        │          │               │
        └──────────┼───────────────┘
                   ▼
            Technique Selector
                   │
        ┌──────────┼──────────┐
        ▼          ▼          ▼
      Error     Boolean     Timing
     Analysis   Analysis    Analysis
        │          │          │
        └──────────┼──────────┘
                   ▼
             Diff Engine
                   │
                   ▼
           Confidence Engine
                   │
                   ▼
            Evidence Store
```

---

# 14. SQL Context Model

The engine needs to understand that parameters may occur in different contexts.

```rust
enum SqlContext {
    Unknown,
    Numeric,
    String,
    Boolean,
    Like,
    OrderBy,
    Limit,
    Offset,
    Identifier,
}
```

The purpose is not to magically reconstruct the server's SQL query. Instead, the scanner maintains a hypothesis about the parameter context and selects appropriate **non-destructive detection tests**.

---

# 15. SQL Clause Model

Create an internal SQL feature taxonomy.

```text
SQL Features
│
├── SELECT
│   ├── projection
│   ├── FROM
│   ├── WHERE
│   ├── GROUP BY
│   ├── HAVING
│   ├── ORDER BY
│   ├── LIMIT
│   └── OFFSET
│
├── INSERT
│
├── UPDATE
│
├── DELETE
│
├── JOIN
│
├── UNION
│
├── SUBQUERY
│
├── EXPRESSION
│
├── FUNCTION
│
└── COMMENT
```

Treat this as a **research taxonomy**, not as a command to execute arbitrary destructive SQL.

---

# 16. SQL Dialect Abstraction

Do not scatter DBMS-specific logic throughout the code.

Use:

```rust
trait DatabaseDialect {
    fn name(&self) -> &str;

    fn supports(&self, feature: SqlFeature) -> bool;

    fn fingerprint_rules(&self) -> &[FingerprintRule];

    fn context_rules(&self) -> &[ContextRule];

    fn comparison_rules(&self) -> &[ComparisonRule];
}
```

Implement:

```text
DatabaseDialect
│
├── Generic
├── MySQL
├── PostgreSQL
├── MSSQL
├── Oracle
└── SQLite
```

Later:

```text
├── MariaDB
├── CockroachDB
└── Other dialects
```

---

# 17. SQL Rule Format

Keep detection knowledge outside the binary.

Example conceptual rule:

```toml
id = "generic-error-family-001"
name = "Database error fingerprint"
category = "error-analysis"

[conditions]
requires_response_body = true

[confidence]
base = 20
```

A DBMS-specific rule:

```toml
id = "postgres-error-family-001"
dbms = "postgresql"
category = "fingerprint"
```

The engine loads rules at startup.

---

# 18. SQL Technique Registry

Each technique should declare metadata.

```text
Technique
├── id
├── name
├── category
├── contexts
├── supported_dbms
├── safety_level
├── prerequisites
├── analyzer
└── confidence_model
```

Example categories:

```text
error-analysis
differential-analysis
timing-analysis
dialect-fingerprinting
context-analysis
```

The registry decides which analyzer is eligible.

---

# 19. Baseline Engine

Before analysis, capture a baseline.

```text
Parameter
    ↓
Baseline Request
    ↓
Baseline Response
    ↓
Fingerprint
```

Repeat baseline measurements when necessary to understand normal variance.

This is especially important for timing-based analysis because network latency naturally varies.

---

# 20. Differential Analysis

Conceptually:

```text
Baseline
    │
    ▼
Response A
    │
    ├── status
    ├── body
    ├── headers
    └── timing
           │
           ▼
        Compare
           ▲
           │
    Test Response
    │
    ▼
Response B
```

The engine should ask:

```text
Is the difference:
    • reproducible?
    • parameter-dependent?
    • statistically meaningful?
    • consistent with a known DBMS signal?
```

A single anomalous response should not automatically become a finding.

---

# 21. Confidence Engine

Use evidence rather than binary "vulnerable/not vulnerable".

Example model:

```text
Signal
────────────────────────────
Known DB error pattern     +30
Consistent differential    +25
Repeated behavior          +20
DBMS fingerprint           +10
Timing correlation         +10
Context confidence          +5
────────────────────────────
Maximum                    100
```

Classification:

```text
0–29    Informational
30–49   Low confidence
50–69   Medium confidence
70–89   High confidence
90–100  Very high confidence
```

Make these weights configurable.

The scanner should still require manual verification before treating a candidate as a reportable vulnerability.

---

# 22. SQL Result Model

```text
SqlAnalysisResult
├── target
├── endpoint
├── parameter
├── context
├── dbms_hypothesis
├── techniques_tested
├── baseline_fingerprint
├── test_fingerprints
├── signals
├── confidence
└── evidence_id
```

---

# 23. Evidence System

Never store only:

```text
SQLi detected
```

Store evidence.

```text
Evidence
├── baseline_request
├── baseline_response
├── test_request
├── test_response
├── response_diff
├── timing_data
├── fingerprints
├── analysis_notes
└── timestamps
```

Sensitive authentication data should be redacted from logs and exports.

---

# 24. Finding Model

```text
Finding
│
├── id
├── project_id
├── title
├── severity
├── confidence
├── status
├── target
├── endpoint
├── parameter
├── module
├── technique
├── dbms_hypothesis
├── evidence
├── notes
├── created_at
└── updated_at
```

Statuses:

```text
CANDIDATE
NEEDS_REVIEW
VERIFIED
REJECTED
DUPLICATE
REPORTED
RESOLVED
```

---

# 25. Database Schema

Start with SQLite.

Core tables:

```text
projects
scope_rules
targets
domains
hosts
ports
urls
endpoints
parameters
technologies

scan_jobs
scan_profiles
requests
responses
response_fingerprints

sql_analyses
sql_signals
sql_techniques

findings
evidence
notes
events
```

Relationships:

```text
Project
 │
 ├── Targets
 │     └── Hosts
 │          └── Endpoints
 │                └── Parameters
 │
 ├── Scan Jobs
 │     └── Requests
 │           └── Responses
 │
 └── Findings
       └── Evidence
```

---

# 26. Authentication Profiles

Use profiles such as:

```text
Anonymous
Research Account A
Research Account B
Custom Profile
```

Store secrets through the OS secure credential mechanism where practical. Do not put raw tokens/passwords into SQLite, source code, screenshots, or normal scan logs.

---

# 27. Recon Pipeline

The complete pipeline can eventually become:

```text
                     Project
                        │
                        ▼
                     Scope
                        │
                        ▼
                Subdomain Discovery
                        │
                        ▼
                    DNS Resolve
                        │
                        ▼
                  HTTP Probing
                        │
                        ▼
               Technology Detection
                        │
                        ▼
                  URL Discovery
                        │
                        ▼
                     Crawler
                        │
                        ▼
                Endpoint Inventory
                        │
                        ▼
               Parameter Inventory
                        │
            ┌───────────┴───────────┐
            ▼                       ▼
       HTTP Analysis            SQL Analysis
            │                       │
            └───────────┬───────────┘
                        ▼
                     Findings
```

---

# 28. Go Worker Architecture

Example:

```text
engines/recon-go/
│
├── cmd/
│   └── recon/
│
├── internal/
│   ├── dns/
│   ├── resolver/
│   ├── http/
│   ├── crawler/
│   ├── worker/
│   ├── parser/
│   ├── rate/
│   └── output/
│
├── pkg/
└── go.mod
```

Go worker responsibilities:

```text
DNS
  ↓
Concurrent resolution

HTTP
  ↓
Concurrent probing

Crawler
  ↓
Controlled worker pool

Output
  ↓
Structured events/results
```

---

# 29. Worker Communication

Keep the Rust/Go boundary simple.

Concept:

```text
Rust
  │
  │ structured job
  ▼
Go Worker
  │
  │ structured events
  ▼
Rust
```

A job can conceptually contain:

```json
{
  "type": "job",
  "id": "job-123",
  "module": "dns",
  "target": "example.com"
}
```

A result:

```json
{
  "type": "result",
  "job_id": "job-123",
  "status": "completed"
}
```

Define a versioned protocol:

```text
protocol_version = 1
```

This prevents future Rust/Go upgrades from silently breaking communication.

---

# 30. Rate Limiting

Make rate control centralized.

```text
                 Request
                    │
                    ▼
              Scope Check
                    │
                    ▼
             Request Budget
                    │
                    ▼
              Rate Limiter
                    │
                    ▼
               HTTP Engine
```

Configuration:

```toml
[limits]

requests_per_second = 5
max_concurrency = 4
timeout_seconds = 15
max_requests_per_job = 1000
```

Always respect the target program's published rules. Never let the tool's default settings encourage aggressive traffic.

---

# 31. Request Budget

Each scan should have a budget.

```text
Scan
│
├── Maximum requests
├── Current requests
├── Remaining requests
├── Maximum concurrency
└── Rate limit
```

UI:

```text
Requests

██████████████░░░░░░  720 / 1000

Rate: 4.2 req/s
Workers: 4
```

---

# 32. Duplicate Detection

Recon produces enormous amounts of duplicate data.

Normalize before storing.

```text
Raw URL
   ↓
URL Canonicalizer
   ↓
Normalized URL
   ↓
Hash
   ↓
Deduplication
   ↓
SQLite
```

Do the same for:

- endpoints
- parameters
- hosts
- technologies
- findings

---

# 33. React Application Layout

Recommended UI:

```text
┌──────────────────────────────────────────────────────────────┐
│ BugTools                                  Project ▼   ⚙      │
├──────────────┬───────────────────────────────────────────────┤
│              │                                               │
│ Dashboard    │                 Dashboard                     │
│              │                                               │
│ Projects     │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ │
│ Scope        │  │Domains │ │ Hosts  │ │ URLs   │ │Findings│ │
│              │  │  1,284 │ │  347   │ │ 8,921  │ │   12   │ │
│ Recon        │  └────────┘ └────────┘ └────────┘ └────────┘ │
│              │                                               │
│ HTTP         │  Active Jobs                                  │
│ URLs         │  ┌─────────────────────────────────────────┐  │
│              │  │ SQL Analysis       67%     Running      │  │
│ JavaScript   │  │ HTTP Discovery     91%     Running      │  │
│              │  └─────────────────────────────────────────┘  │
│ SQL Analysis │                                               │
│              │  Recent Findings                             │
│ Findings     │                                               │
│              │  ...                                          │
│ Reports      │                                               │
│              │                                               │
│ Logs         │                                               │
│ Settings     │                                               │
└──────────────┴───────────────────────────────────────────────┘
```

---

# 34. SQL UI

```text
SQL ANALYSIS
─────────────────────────────────────────────

Project
[ Example Program ▼ ]

Target
[ https://example.com ]

Authentication
[ Research Account A ▼ ]

Scope
[ ● ENFORCED ]

─────────────────────────────────────────────

Parameters

┌──────────┬───────────┬────────────┐
│ Parameter│ Context   │ Confidence │
├──────────┼───────────┼────────────┤
│ id       │ Numeric   │ Medium     │
│ search   │ String    │ Low        │
│ sort     │ Order By  │ Unknown    │
└──────────┴───────────┴────────────┘

─────────────────────────────────────────────

Analysis

☑ Baseline analysis
☑ Context analysis
☑ Error analysis
☑ Differential analysis
☑ DBMS fingerprinting
☑ Timing analysis

[ Start Analysis ]

─────────────────────────────────────────────

RESULT

Parameter: id
Context: Numeric
DBMS hypothesis: PostgreSQL
Confidence: High

Signals:
• Consistent differential response
• Database-specific error signature

[ Open Evidence ]
```

---

# 35. Scan Profiles

Instead of configuring every scan manually:

```text
scan-profiles/
│
├── passive.toml
├── recon.toml
├── http.toml
├── sql-review.toml
└── custom.toml
```

Example:

```toml
[name]
value = "Conservative SQL Review"

[limits]
requests_per_second = 2
max_concurrency = 2

[analysis]
baseline_repetitions = 3
enable_error_analysis = true
enable_differential_analysis = true
enable_timing_analysis = false
```

Profiles make your workflow repeatable.

---

# 36. Logging

Use structured logs.

```text
timestamp
level
component
job_id
target
event
message
```

Example:

```text
23:41:02 INFO  scheduler job_started
23:41:03 INFO  http      request_completed
23:41:04 INFO  sql       baseline_created
23:41:06 INFO  sql       analysis_completed
23:41:06 WARN  finding  candidate_created
```

Never log:

```text
Authorization: Bearer <secret>
Cookie: session=<secret>
Password: <secret>
```

Redact them.

---

# 37. Testing Strategy

Do not test the scanner only against live programs.

Create local fixtures.

```text
tests/
│
├── unit/
│   ├── scope/
│   ├── parser/
│   ├── fingerprint/
│   └── sql/
│
├── integration/
│   ├── http/
│   ├── workers/
│   └── database/
│
└── fixtures/
    ├── http/
    └── sql/
```

For SQL specifically:

```text
SQL Test Fixture
    ↓
Known behavior
    ↓
Engine
    ↓
Expected analysis result
```

Use intentionally vulnerable local applications/containers for testing rather than third-party production systems.

---

# 38. Development Roadmap

## Phase 0 — Planning

Create:

```text
docs/
├── architecture.md
├── protocol.md
├── database.md
├── scope.md
├── sql-engine.md
└── development.md
```

Deliverable:

```text
Architecture specification
```

---

## Phase 1 — Tauri Foundation

Build:

```text
React
+
TypeScript
+
Tauri
+
Rust
```

Implement:

- Sidebar
- Routing
- Settings
- Project page
- Tauri command
- Event listener

Do not build scanners yet.

---

## Phase 2 — SQLite

Implement:

```text
Project CRUD
Target CRUD
Scope CRUD
Scan Job CRUD
Finding CRUD
```

Then test:

```text
Create Project
      ↓
Add Target
      ↓
Save to SQLite
      ↓
Reload application
      ↓
Data remains
```

---

## Phase 3 — Scope Engine

Build:

```text
Domain matcher
Path matcher
Exclusion matcher
Protocol matcher
Port matcher
```

Test heavily before adding active scanners.

---

## Phase 4 — Job System

Build:

```text
Job queue
Worker manager
Cancellation
Progress
Events
Logs
```

At this point the application should be able to run a fake job:

```text
Test Job
  0%
  25%
  50%
  75%
  100%
```

before you connect real network engines.

---

## Phase 5 — HTTP Core

Implement:

```text
Request model
Response model
HTTP client
Timeout
Redirect handling
Headers
Cookies
Rate limiter
Request budget
Fingerprint
```

This becomes shared infrastructure.

---

## Phase 6 — Go Recon Worker

Start with:

```text
DNS
HTTP probing
Basic crawling
```

Connect it through the worker protocol.

---

## Phase 7 — Discovery

Add:

```text
URL normalization
Endpoint extraction
Parameter extraction
JavaScript inventory
Technology detection
```

---

# 39. Phase 8 — SQL Engine

Build in this order:

```text
1. SQL domain models
2. Context model
3. DBMS abstraction
4. Rule loader
5. Baseline engine
6. Response fingerprinting
7. Differential analyzer
8. Error analyzer
9. DBMS fingerprinting
10. Timing analyzer
11. Confidence engine
12. Evidence engine
13. Finding integration
14. UI
```

Do not begin with a massive payload database.

---

# 40. SQL Engine Internal Modules

Recommended:

```text
crates/bugtools-sql/
│
├── src/
│   ├── lib.rs
│   │
│   ├── context/
│   │   ├── mod.rs
│   │   ├── classifier.rs
│   │   └── models.rs
│   │
│   ├── dialect/
│   │   ├── mod.rs
│   │   ├── generic.rs
│   │   ├── mysql.rs
│   │   ├── postgres.rs
│   │   ├── mssql.rs
│   │   ├── oracle.rs
│   │   └── sqlite.rs
│   │
│   ├── baseline/
│   │   ├── mod.rs
│   │   └── analyzer.rs
│   │
│   ├── fingerprint/
│   │   ├── mod.rs
│   │   └── database.rs
│   │
│   ├── techniques/
│   │   ├── mod.rs
│   │   ├── error.rs
│   │   ├── differential.rs
│   │   └── timing.rs
│   │
│   ├── comparison/
│   │   ├── mod.rs
│   │   ├── body.rs
│   │   ├── headers.rs
│   │   └── timing.rs
│   │
│   ├── confidence/
│   │   ├── mod.rs
│   │   └── scorer.rs
│   │
│   └── evidence/
│       ├── mod.rs
│       └── collector.rs
```

---

# 41. Phase 9 — Findings

Build:

```text
Candidate
   ↓
Review
   ↓
Verified
   ↓
Report
```

The tool should help the researcher make the final determination rather than automatically declaring every anomaly a vulnerability.

---

# 42. Phase 10 — Reports

Export:

```text
Markdown
JSON
CSV
```

Possible report:

```text
# Finding

## Target

example.com

## Endpoint

/api/search

## Parameter

query

## Analysis

...

## Evidence

...

## Confidence

High

## Verification Status

Needs Review
```

---

# 43. Phase 11 — Performance

Only optimize after correctness.

Potential optimizations:

```text
Connection pooling
Caching
Concurrent workers
Batch database writes
URL deduplication
Response hashing
Incremental scans
Persistent job state
```

Measure:

```text
requests/sec
CPU
RAM
SQLite write rate
queue latency
worker utilization
```

---

# 44. Phase 12 — Packaging

Final application:

```text
BugTools.exe
```

With:

```text
Rust/Tauri application
Go worker binaries
SQLite database
rules/
configs/
```

Use a versioned application data directory rather than storing mutable data beside the executable.

---

# 45. Suggested Milestone Tree

```text
M0  Architecture
 │
 ├── repository
 ├── documentation
 └── data models
 │
 ▼
M1  Tauri + React
 │
 ▼
M2  SQLite
 │
 ▼
M3  Scope Engine
 │
 ▼
M4  Job/Event System
 │
 ▼
M5  HTTP Core
 │
 ▼
M6  Go Workers
 │
 ▼
M7  Recon
 │
 ▼
M8  URL/Endpoint Discovery
 │
 ▼
M9  SQL Engine
 │
 ▼
M10 Findings
 │
 ▼
M11 Reports
 │
 ▼
M12 Performance
 │
 ▼
M13 Packaging
```

---

# 46. What NOT to Build First

Avoid these early:

```text
❌ Huge payload database
❌ 50 scanners
❌ Fancy dashboard animations
❌ Distributed scanning
❌ Cloud backend
❌ AI vulnerability detector
❌ Automatic exploitation
❌ Massive wordlists
```

First make this work:

```text
Project
   ↓
Scope
   ↓
Job
   ↓
HTTP
   ↓
Analysis
   ↓
Evidence
   ↓
Finding
```

If this foundation is good, additional modules become much easier.

---

# 47. Recommended First Version

Your V1 should contain only:

```text
┌─────────────────────────────────┐
│            BugTools             │
├─────────────────────────────────┤
│                                 │
│ Projects                        │
│ Scope                           │
│ HTTP                            │
│ Recon                           │
│ SQL Analysis                    │
│ Findings                        │
│ Logs                            │
│ Settings                        │
│                                 │
└─────────────────────────────────┘
```

Backend:

```text
Tauri
  ↓
Rust
  ├── Scope
  ├── Job Manager
  ├── HTTP
  ├── SQL
  ├── SQLite
  └── Events

Go
  ├── DNS
  ├── Recon
  └── Crawler
```

---

# 48. V1 Success Criteria

Do not move to advanced scanning until all of these work:

```text
[ ] Create project
[ ] Define scope
[ ] Add target
[ ] Validate target
[ ] Start job
[ ] Display job progress
[ ] Cancel job
[ ] Enforce request budget
[ ] Enforce rate limit
[ ] Store request
[ ] Store response
[ ] Generate fingerprint
[ ] Display evidence
[ ] Create finding
[ ] Persist everything in SQLite
[ ] Restart app without losing state
```

---

# 49. Long-Term Architecture

Eventually the application should support:

```text
                        BugTools
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
      Recon              Analysis           Evidence
        │                  │                  │
   ┌────┼────┐       ┌─────┼─────┐       ┌───┴────┐
   │    │    │       │     │     │       │        │
  DNS  HTTP Crawl    SQL  HTTP  Auth   Requests Findings
                     │
             ┌───────┼────────┐
             │       │        │
           Context Dialect  Diff
             │       │        │
             └───────┼────────┘
                     │
                Confidence
                     │
                     ▼
                  Finding
```

---

# 50. Final Design Philosophy

The strongest version of this project is **not**:

```text
"One program containing every security payload."
```

It is:

```text
"An extensible research platform that safely
collects evidence, analyzes behavior, and lets
the researcher decide what is significant."
```

The most important engineering abstractions are:

```text
Scope
  ↓
Job
  ↓
HTTP
  ↓
Baseline
  ↓
Analysis
  ↓
Evidence
  ↓
Confidence
  ↓
Finding
```

And the SQL subsystem should follow:

```text
Request
  ↓
Parameter
  ↓
Context Hypothesis
  ↓
Baseline
  ↓
Dialect Hypothesis
  ↓
Applicable Analysis
  ↓
Response Comparison
  ↓
Repeated Signal
  ↓
Confidence
  ↓
Evidence
  ↓
Manual Verification
```

This gives you a foundation where adding another SQL dialect, another analysis technique, or another recon engine does not require rewriting the entire application.

---

# 51. Immediate Next Step

From:

```powershell
C:\bug-tools>
```

build the project in this order:

```text
STEP 1
Tauri + React + TypeScript
        ↓
STEP 2
Rust command/event layer
        ↓
STEP 3
SQLite project database
        ↓
STEP 4
Scope engine
        ↓
STEP 5
Job manager
        ↓
STEP 6
HTTP abstraction
        ↓
STEP 7
Response fingerprinting
        ↓
STEP 8
Go worker protocol
        ↓
STEP 9
DNS/HTTP recon worker
        ↓
STEP 10
SQL engine foundation
```

**Do not jump directly to Step 10.**

The SQL scanner will become much more powerful when it can reuse the same scope, HTTP, baseline, fingerprinting, job, evidence, and storage infrastructure used by the rest of BugTools.

---

## Safety Boundary

BugTools should be developed and used only against:

- systems you own;
- intentionally vulnerable local labs;
- targets explicitly authorized by a bug-bounty/security program.

The platform should default to conservative request rates, strict scope enforcement, request budgets, audit logging, and non-destructive analysis.
