# BugTools Architecture Specification

BugTools is an advanced, auditable security-research desktop workstation built for authorized bug-bounty testing and owned systems.

## Core Tenets
1. **Rule 1 — UI never performs scanning directly**: React dispatches typed commands to the Rust controller; Rust enforces scope and schedules jobs.
2. **Rule 2 — Scope enforcement happens before network execution**: All requests are checked by `bugtools-scope` prior to network transmission.
3. **Rule 3 — Scanner modules must be replaceable**: Engines operate as decoupled, modular units emitting structured evidence.
4. **Rule 4 — Rules are data-driven**: Detection patterns and signatures reside in declarative TOML rules (`rules/sql/`, `rules/technologies/`).

## Monorepo Layout
- `apps/desktop/`: React 18 + TypeScript + Vite + Tailwind CSS v4 + React Router + Lucide Icons.
- `src-tauri/`: Tauri v2 application bridge, state management, and command routing.
- `crates/`:
  - `bugtools-core`: Domain models (Project, Scope, Target, Job, Finding, Evidence, HTTP).
  - `bugtools-scope`: Pre-network scope validation engine (wildcards, paths, ports, protocols).
  - `bugtools-storage`: SQLite storage layer with WAL mode and bundled SQLite.
  - `bugtools-http`: Rate-limited, budget-aware HTTP abstraction client.
  - `bugtools-fingerprint`: Response normalization, hashing, and structural signature extraction.
  - `bugtools-scheduler`: Job queue and concurrency scheduler.
  - `bugtools-sql`: Non-destructive SQL research taxonomy, dialect abstractions, and hypothesis analyzer.
  - `bugtools-parser`: URL and endpoint extraction engine.
- `engines/`: Concurrency workers written in Go (`recon-go`, `dns-go`, `crawler-go`, `http-go`).
- `rules/`: TOML signature rules for database error fingerprints and technology detection.
- `configs/scan-profiles/`: Repeatable scan profiles (`passive.toml`, `conservative-sql.toml`).
