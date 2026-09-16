# BugTools — CLI-Only Architecture

BugTools is a native Rust, **CLI-only** security research platform. There is
no GUI: the previous egui application was removed on 2026-09-17 and the CLI
carries all functionality.

## Principles

1. **CLI is the only interface.** All commands live in `apps/bugtools-cli`.
2. **One responsibility per file.** `main.rs` only parses and dispatches;
   argument definitions live in `cli.rs`; each command's execution lives in
   its own file under `commands/`; shared input parsing lives in `parsing/`;
   terminal rendering lives in `output/`.
3. **CLI orchestrates libraries; it contains no vulnerability logic.** The
   engines in `crates/` do the research. Command handlers translate parsed
   arguments into engine calls and render results.
4. **No god files.** No file in the CLI exceeds ~300 lines; `main.rs` is
   ~120.
5. **Evidence-first.** Results carry their evidence, confidence, and
   limitations. Reflection is not injection; a WAF block is not a finding;
   only observed execution confirms.

## CLI structure

```
apps/bugtools-cli/src/
├── main.rs          parse, initialize tracing, dispatch  (~120 lines)
├── cli.rs           clap definitions only — no execution
├── commands/
│   ├── target.rs    normalize a target (offline)
│   ├── discover.rs  CT + DNS brute-force subdomain discovery
│   ├── resolve.rs   DNS record resolution
│   ├── pipeline.rs  full recon pipeline
│   ├── sql.rs       detect / clauses / analyze
│   ├── sqli.rs      adaptive assessment from a candidates file
│   ├── tech.rs      technology fingerprint + XSS analysis
│   └── payload.rs   inspect adaptive generation (sends nothing)
├── parsing/mod.rs   cookies, headers, record types, DBMS names, hypotheses
└── output/
    ├── mod.rs
    └── sink.rs      PipelineEvent → terminal / JSONL
```

## Engine crates

The research engines are library crates with their own internal structure —
see each crate's module docs:

- `bugtools-sql` — adaptive SQLi research (baseline, hypotheses, repetition
  verification, payload composition, policy)
- `bugtools-xss` — reflection/source/sink/taint analysis with the
  exploitability state machine
- `bugtools-dns`, `bugtools-discovery`, `bugtools-crawler`,
  `bugtools-runtime` — the recon pipeline
- `bugtools-http`, `bugtools-scope`, `bugtools-storage`, `bugtools-output`,
  `bugtools-fingerprint`, `bugtools-events`, `bugtools-scheduler`,
  `bugtools-parser`, `bugtools-core` — shared infrastructure

## Safety invariants (enforced in code, not convention)

- Every network-touching command requires `--i-authorize`.
- A program policy TOML (`--program FILE`) refuses out-of-scope hosts before
  any request and fails closed when `scanners_allowed = false`.
- SQLi findings require repetition-verified evidence; the assessment builder
  rejects a finding without limitations.
- XSS `confirmed` derives only from the exploitability machine reaching
  `ExecutionConfirmed`.

## Adding a command

1. Add the variant to `Commands` in `cli.rs` (definitions only).
2. Create `commands/<name>.rs` with a `run(...)` handler.
3. Register the module in `commands/mod.rs`.
4. Add the match arm in `main.rs` — one line of dispatch.
