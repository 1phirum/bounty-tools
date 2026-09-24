# BugTools — Native Rust Security Research Platform

BugTools is a command-line security research platform written in Rust. It
performs subdomain discovery, DNS resolution, HTTP probing/crawling,
technology fingerprinting, endpoint discovery, and differential SQL-injection
and XSS research — all behind a rigid, default-deny scope engine so that no
request is ever sent to a host you have not explicitly authorized.

> **Authorized testing only.** BugTools is for security research on systems
> you own or are explicitly authorized to test (e.g. a bug-bounty program's
> in-scope assets). Live commands send nothing until you pass `--i-authorize`,
> and an optional `--program` policy file enforces a program's scope and
> rate limits on every request.

## Install

### Prebuilt binaries (recommended)

Download the latest release for your platform, or use the one-line installer.

**Windows** (PowerShell):
```powershell
irm https://raw.githubusercontent.com/1phirum/bounty-tools/master/scripts/install.ps1 | iex
```

**Linux / macOS**:
```bash
curl -fsSL https://raw.githubusercontent.com/1phirum/bounty-tools/master/scripts/install.sh | bash
```

Both installers place `bugtools` on your `PATH`. Then run `bugtools --help`.
Prebuilt archives for Linux, Windows and macOS are also attached to each
[GitHub Release](https://github.com/1phirum/bounty-tools/releases).

### Build from source

Requires the latest stable [Rust](https://rustup.rs/) toolchain.

```bash
# Build the optimized binary at target/release/bugtools
cargo build --release -p bugtools-cli
```

```bash
# Or install it globally onto your PATH
cargo install --path apps/bugtools-cli
```

## Usage

`bugtools <command>`. Every command has `--help`; most have a short alias.

| Command | Alias | What it does |
| --- | --- | --- |
| `target` | `t` | Normalize and validate a target/scope specification. |
| `discover` | `d` | Subdomain discovery (certificate-transparency logs + DNS). |
| `resolve` | `r` | Resolve hosts to A/AAAA/CNAME records. |
| `pipeline` | `p` | Full recon pipeline: discover → resolve → probe → crawl. |
| `endpoints` | `e` | Discover endpoints/routes from HTML & JS (offline or live). |
| `tech` | `x` | Technology / stack fingerprinting from responses. |
| `sql` | `s` | Differential SQL-injection research (detect, analyze). |
| `sqli` | `q` | End-to-end SQLi probing against an authorized target. |
| `xss` | `w` | XSS reflection, context and DOM taint-flow analysis. |
| `payload` | — | Generate research payloads for the engines above. |

Offline endpoint discovery reads from a file or stdin and never touches the
network:

```bash
bugtools endpoints ./page.html --json
cat page.html | bugtools endpoints - --kind api --no-assets
```

Live commands are gated. Nothing leaves your machine until you pass
`--i-authorize`, and a `--program` policy file (TOML) pins the allowed scope
and rate limits for a specific engagement:

```bash
# Crawl a single authorized host for endpoints, following same-host scripts
bugtools endpoints https://example.com --i-authorize --depth 2

# Run the full pipeline under a program's scope + rate policy
bugtools pipeline example.com --i-authorize --program ./program.toml
```

If a request would fall outside the configured scope, the default-deny
[scope engine](crates/bugtools-scope) refuses to send it.

## Workspace layout

A single binary crate (`apps/bugtools-cli`) drives a set of focused library
crates under `crates/`:

| Crate | Role |
| --- | --- |
| `bugtools-core` | Shared domain types (targets, HTTP request/response, scope rules). |
| `bugtools-scope` | Rigid, default-deny scope enforcement for every outbound request. |
| `bugtools-http` | Async `SafeHttpClient`: scope-checked, rate-limited, budget-capped; browser request profiles. |
| `bugtools-discovery` | Subdomain discovery (CT logs + DNS brute force). |
| `bugtools-dns` | DNS resolution engine. |
| `bugtools-crawler` | Crawl frontier and link extraction. |
| `bugtools-endpoints` | Static endpoint/route extraction (HTML, JS, path heuristics) with confidence scoring. |
| `bugtools-fingerprint` | Technology fingerprinting from responses. |
| `bugtools-sql` | Differential SQL-injection research engine (DBMS detection, clause mapping, adaptive payloads). |
| `bugtools-xss` | XSS analysis: reflection, injection context, AST-based DOM taint flow. |
| `bugtools-runtime` | Orchestrates the recon pipeline across the crates above. |
| `bugtools-output` | Typed event/summary stream shared by the CLI (and future front-ends). |
| `bugtools-parser` | Shared parsing utilities. |
| `bugtools-events` | Internal event bus. |
| `bugtools-scheduler` | Task scheduling for concurrent work. |
| `bugtools-storage` | Local persistence of results. |

## Development

```bash
cargo build --workspace     # build everything
cargo test --workspace      # run the test suite
cargo fmt --all             # format
cargo clippy --workspace --all-targets
```

CI (`.github/workflows/ci.yml`) builds and tests the workspace on every push
and pull request. Tagging a release (`git tag v0.1.0 && git push origin v0.1.0`)
triggers `.github/workflows/release.yml`, which cross-compiles the `bugtools`
binary for Linux, Windows and macOS and attaches the archives to a GitHub
Release — the same archives the install scripts download.

## Roadmap

The CLI and its Rust engines are the working product today. A broader
multi-language design — a Rust core "brain" with Go acquisition workers and a
Python research lab — is proposed but **not yet implemented**; the Go engine is
an early stub and the Python lab does not exist yet. See
[docs/architecture/three-language-architecture.md](docs/architecture/three-language-architecture.md)
for that design and its current status.

## License

MIT. See [Cargo.toml](Cargo.toml).


