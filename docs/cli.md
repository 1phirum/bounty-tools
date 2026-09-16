# BugTools CLI

The `bugtools` binary shares its entire engine layer with the GUI. Every
command runs natively — no external reconnaissance tool is invoked.

## Build

```sh
cargo build -p bugtools-cli --release
# binary at target/release/bugtools
```

## Commands

### `bugtools target <input>`

Normalize a domain or URL and show what the engine would use as its apex
domain and seed hosts. Performs no network activity.

```sh
bugtools target https://api.example.com/v2/items?id=1
# domain: example.com
# seeds:  api.example.com
```

### `bugtools discover <input> [--json]`

Run the native discovery engine: certificate transparency plus DNS
brute-force, deduplicated by normalized hostname.

```sh
bugtools discover example.com
bugtools discover example.com --json
```

### `bugtools resolve <hostname> [--types a,cname]`

Resolve DNS records. Supported types: `a`, `aaaa`, `cname`, `mx`, `ns`,
`txt`, `soa`.

```sh
bugtools resolve example.com --types a,ns,mx
```

### `bugtools pipeline <input> [--out report.json] [--depth N] [--max-urls N] [--rps N]`

The full pipeline: scope → discovery → DNS → HTTP probe → crawl →
normalization → summary.

```sh
bugtools pipeline example.com --out result.json --depth 2 --max-urls 200 --rps 5
```

Every stage streams `PipelineEvent`s to the terminal. Warnings (for example
a discovery source being unavailable) are reported rather than hidden.

## Scope and safety

- The pipeline authorizes only the target domain and its subdomain wildcard.
- Requests are scope-checked before execution; an out-of-scope URL is refused.
- Concurrency, request rate, crawl depth and URL count are bounded by flags
  and conservative defaults.

## Status

Implemented: `target`, `discover`, `resolve`, `pipeline`.

Not yet implemented (see `crates/bugtools-sql/MIGRATION.md` and the workspace
architecture doc): `probe`, `crawl` as a standalone command, `analyze`,
`export`, `config`, and technology fingerprinting configuration. These are
planned stages; no placeholder command returns fabricated output.
