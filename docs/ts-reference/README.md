# @bugtools/backend

Advanced backend core for the BugTools desktop security workstation.
Zero runtime dependencies, pure TypeScript, Node 24+, designed to map
1:1 onto a Rust/Tauri implementation if you migrate.

## Architecture

```
src/
  core/
    errors.ts        Typed error taxonomy (E_SCOPE_VIOLATION, ...)
    config.ts        Strict, validated runtime configuration
    ids.ts           Monotonic, collision-free traffic IDs
    scope.ts         Scope manager — safety boundary for ALL engines
  traffic/
    http-message.ts  Immutable HTTP request/response model
    traffic-store.ts Bounded ring buffer + dedup + pagination
    dedup.ts         Fingerprinting and near-duplicate clustering
  engines/
    rate-limiter.ts  Token bucket (burst + sustained refill)
    proxy-engine.ts  Intercepting proxy core with scope enforcement
    repeater.ts      Single-request replay with analyst edits
    fuzzer.ts        Cartesian payload expansion + bounded concurrency
  index.ts           createBackend() facade wiring everything
test/
  bugtools.test.ts   Node test-runner suite covering all modules
```

## Key design decisions

1. **Safety first**: every outbound request — proxy, repeater, or
   fuzzer — passes through `ScopeManager.assertAllowed()` *before*
   any network I/O. Out-of-scope targets are impossible to hit by
   accident.

2. **Immutability**: captured traffic is frozen. Edits (repeater,
   fuzzing) produce new request objects, so the audit trail is intact.

3. **Deterministic dedup**: SHA-256 fingerprints over
   method+host+path+sorted query keys, with volatile params
   (csrf, nonce, timestamps) excluded by default. The fuzzer reports
   which iterations collapsed into existing entries.

4. **Rate limiting is non-negotiable**: the token bucket gates every
   engine. Bursts are allowed, sustained load is capped, and the UI
   can surface `msUntilNextToken()` for live status.

5. **Typed errors**: no stringly-typed failures. The frontend maps
   `BugToolsError.code` to precise status chips.

## Running

```bash
npm test          # full suite
npm start         # smoke bootstrap (prints config summary)
```

## Tauri/Rust mapping

| TypeScript module      | Rust crate equivalent                       |
|------------------------|---------------------------------------------|
| `core/errors.ts`       | `thiserror` enum `BugToolsError`            |
| `core/config.ts`       | `serde` struct with `#[serde(deny_unknown_fields)]` |
| `core/scope.ts`        | `ScopeManager` struct with `HashSet<ScopeRule>` |
| `traffic/traffic-store.ts` | `RingBuffer<TrafficEntry>` behind `RwLock` |
| `engines/proxy-engine.ts`  | `hyper` server + `reqwest` client       |
| `engines/rate-limiter.ts`  | `governor` crate or hand-rolled bucket  |
| `engines/fuzzer.ts`    | `tokio::spawn` workers with `Semaphore`     |

## Security notes

- The proxy binds to loopback by default. Never expose it without
  adding authentication.
- Scope enforcement is the product's primary safety boundary — treat
  any bypass as a critical bug.
- No telemetry, no external calls except to analyst-specified targets.
