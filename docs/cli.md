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

### `bugtools sql <subcommand>`

The SQL research engine, exposed on the CLI.

**`bugtools sql detect <text>`** — identify a DBMS from pasted error text.
Offline: sends no requests. Use `-` to read the text from stdin.

```sh
bugtools sql detect "psycopg2.errors.SyntaxError: syntax error at or near \"'\""
bugtools sql detect - < captured_error.txt
```

Reports the DBMS, a confidence score, the matched signals with their
weights and categories, and — when nothing matched — says plainly that
absence of a signature does not identify a DBMS.

**`bugtools sql clauses [--dbms <family>]`** — print the clause/dialect
reference. With `--dbms` it shows only clauses relevant to that family, each
variant annotated with the dialects that accept it.

```sh
bugtools sql clauses --dbms postgresql
bugtools sql clauses
```

**`bugtools sql analyze <url> [--param <name>] --i-authorize`** — run
scope-checked DBMS detection against a live parameterized endpoint. Probes
the baseline, error, syntax, clause and timing sets, then reports the DBMS
hypothesis, confidence, techniques run, unique matched signals and clause
coverage.

```sh
bugtools sql analyze "https://target/item?id=1" --i-authorize
bugtools sql analyze "https://target/item?id=1" --param id --i-authorize
```

`--i-authorize` is required and is your explicit confirmation that you are
authorized to test the target. Only the host in the URL is added to scope;
every other host stays blocked by default deny.

### `bugtools payload` — inspect adaptive generation (sends nothing)

Generate and print the candidates the engine would use, with the rationale
for each. This is the transparency surface: you can see *why* a payload was
composed.

```sh
bugtools payload --clause order_by --quote numeric --dbms postgresql --tier explore --technique boolean
bugtools payload --clause where --quote single --tier recon
bugtools payload --clause where --quote single --waf --technique error --json
```

Flags: `--clause` (where/having/order_by/group_by/join/like/limit/insert/
update/delete/select_expr/function_arg/generic), `--quote` (none/single/
double/backtick/bracket), `--dbms`, `--representation` (query/form/json/
header/cookie/path), `--tier` (recon/confirm/explore), `--technique`
(boolean/error/timing/union/clause), `--waf`, `--json`.

Note that generation is clause-aware: for `--clause order_by` the engine
emits `,(SELECT 1)` rather than `AND 1=1`, because ORDER BY cannot take a
boolean predicate.

## Cookies, headers and authentication

`bugtools sqli` and `bugtools sql analyze` accept session material so you can
test authenticated surfaces exactly as you are logged in:

```sh
# from a file — pass the path straight to --cookie
bugtools sqli --input endpoints.json --i-authorize --cookie cookies.txt

# inline cookies (repeatable, or one string with ; separators)
bugtools sqli --input endpoints.json --i-authorize \
  --cookie "session=abc123" --cookie "tenant_id=42"

# --cookie-file is equivalent and still supported
bugtools sqli --input endpoints.json --i-authorize --cookie-file session.txt

# custom headers and a bearer token
bugtools sqli --input endpoints.json --i-authorize \
  --header "X-Account-ID: 99" --bearer "eyJhbGci..."

# depth and request budget
bugtools sqli --input endpoints.json --i-authorize --depth confirm --max-requests 200
```

Cookie values are never printed — only the cookie *names* are listed, so a
terminal transcript is safe to share.

## Scope and safety

- The pipeline authorizes only the target domain and its subdomain wildcard.
- Requests are scope-checked before execution; an out-of-scope URL is refused.
- Concurrency, request rate, crawl depth and URL count are bounded by flags
  and conservative defaults.

## Status

Implemented: `target`, `discover`, `resolve`, `pipeline`, and the full
`sql` tree (`detect`, `clauses`, `analyze`).

Not yet implemented (see `crates/bugtools-sql/MIGRATION.md` and the workspace
architecture doc): `probe`, `crawl` as a standalone command, `analyze`,
`export`, `config`, and technology fingerprinting configuration. These are
planned stages; no placeholder command returns fabricated output.
