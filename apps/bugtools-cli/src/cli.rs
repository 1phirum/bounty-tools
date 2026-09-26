//! CLI argument definitions.
//!
//! Definitions only — no execution logic. The dispatcher in `main.rs` routes
//! a parsed [`Cli`] to the matching command handler in `commands/`.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "bugtools",
    about = "BugTools — Native Rust Security Research Platform",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Normalize and describe a target without scanning it.
    #[command(visible_alias = "t", long_about = "Normalize a domain or URL and show the apex domain and seed hosts. Performs no network activity.\n\nEXAMPLES:\n  bugtools t example.com\n  bugtools target https://api.example.com/v2/items?id=1")]
    Target {
        /// Domain or URL, e.g. example.com
        input: String,
    },
    /// Discover subdomains for a target (CT logs + DNS brute-force).
    #[command(visible_alias = "d", long_about = "Run the native discovery engine: certificate transparency plus DNS brute-force, deduplicated by normalized hostname.\n\nEXAMPLES:\n  bugtools d example.com\n  bugtools discover example.com --json")]
    Discover {
        /// Domain or URL, e.g. example.com
        input: String,
        /// Emit JSON instead of human-readable lines.
        #[arg(short = 'j', long)]
        json: bool,
    },
    /// Resolve DNS records for a hostname.
    #[command(visible_alias = "r", long_about = "Resolve A/AAAA/CNAME/MX/NS/TXT/SOA records using the native DNS engine.\n\nEXAMPLES:\n  bugtools r example.com\n  bugtools resolve example.com --types a,ns,mx")]
    Resolve {
        hostname: String,
        /// Record types to query (a, aaaa, cname, mx, ns, txt, soa).
        #[arg(long, value_delimiter = ',', default_value = "a,cname")]
        types: Vec<String>,
    },
    /// DNS/TLS/HTTP reconnaissance via the embedded engine.
    #[command(visible_alias = "rec", long_about = "Reconnaissance for one target, run by the engine baked into this binary: DNS enumeration (A/AAAA + reverse PTR, CNAME, MX, NS, TXT, SRV), TLS certificate inspection (issuer, validity, version/cipher, and in-scope SAN hostnames surfaced as discovered subdomains), and HTTP(S) probing (status, Server, final URL, title). Read-only.\n\nEXAMPLES:\n  bugtools recon example.com\n  bugtools rec example.com\n  bugtools recon example.com --json\n  bugtools recon example.com:8443 --no-http\n  bugtools recon example.com -q > recon.txt\n  bugtools recon example.com --engine ./engines/dns-go/dns.exe")]
    Recon {
        /// Domain, host:port, or URL to reconnoitre.
        target: String,
        /// Emit JSON instead of grouped, human-readable lines.
        #[arg(short = 'j', long)]
        json: bool,
        /// Suppress the live progress indicator (results still print).
        #[arg(short = 'q', long)]
        quiet: bool,
        /// Use this engine binary instead of the embedded one.
        #[arg(long, value_name = "PATH")]
        engine: Option<String>,
        /// Skip TLS certificate inspection.
        #[arg(long)]
        no_tls: bool,
        /// Skip HTTP(S) probing.
        #[arg(long)]
        no_http: bool,
        /// Per-connection dial/handshake timeout, in seconds.
        #[arg(long, default_value_t = 5)]
        timeout: u64,
        /// Overall time budget for the whole run, in seconds.
        #[arg(long, default_value_t = 20)]
        overall_timeout: u64,
    },
    /// Run the full pipeline: discovery -> DNS -> HTTP -> crawl -> JSON.
    #[command(visible_alias = "p", long_about = "Full recon pipeline for a target: scope -> discovery -> DNS -> HTTP probe -> crawl -> summary.\n\nEXAMPLES:\n  bugtools p example.com\n  bugtools pipeline example.com --out result.json --depth 2 --max-urls 200")]
    Pipeline {
        /// Domain or URL, e.g. example.com
        input: String,
        /// Write the result summary as JSON to this path.
        #[arg(long)]
        out: Option<String>,
        /// Maximum crawl depth.
        #[arg(long, default_value_t = 2)]
        depth: u32,
        /// Maximum URLs to fetch while crawling.
        #[arg(long, default_value_t = 200)]
        max_urls: usize,
        /// Requests per second for HTTP probing.
        #[arg(long, default_value_t = 5.0)]
        rps: f64,
    },
    /// SQL research engine: DBMS detection and clause mapping.
    #[command(visible_alias = "s", long_about = "SQL research engine. Offline detection from pasted error text, the clause/dialect reference, and live scope-checked DBMS probing.\n\nEXAMPLES:\n  bugtools s detect \"psycopg2.errors.SyntaxError: syntax error at or near\"\n  bugtools sql clauses --dbms postgresql\n  bugtools s analyze \"https://target/item?id=1\" --i-authorize\n  bugtools s analyze \"https://target/item?id=1\" -c session.txt --i-authorize")]
    Sql {
        #[command(subcommand)]
        command: SqlCommands,
    },
    /// NoSQL research engine: MongoDB error fingerprinting + live operator injection.
    #[command(visible_alias = "n", long_about = "NoSQL research engine (MongoDB-focused). Offline datastore fingerprinting from pasted error text, and live scope-checked operator-injection detection with a NOT_INTERPRETED negative finding. Every payload is read-only (writes/admin/server-exec operators are refused) and delay/size-capped.\n\nEXAMPLES:\n  bugtools n detect \"MongoError: E11000 duplicate key\"\n  bugtools nosql detect - < error.txt\n  bugtools n analyze \"https://target/login?user=alice\" -p user --i-authorize\n  bugtools nosql analyze \"https://target/api?user=x\" -p user -c session.txt --i-authorize --json")]
    Nosql {
        #[command(subcommand)]
        command: NosqlCommands,
    },
    /// Fingerprint a target's technology stack from a live response.
    #[command(visible_alias = "x", long_about = "Technology intelligence: fingerprint the stack from headers, cookies, HTML and script paths, then derive the XSS strategy. Versions are reported only when the exact string is observed.\n\nEXAMPLES:\n  bugtools x https://example.com --i-authorize\n  bugtools tech https://example.com --i-authorize --json\n  bugtools x https://app.example.com -c session.txt -H \"X-Account-ID: 99\" --i-authorize")]
    Tech {
        /// URL to fingerprint.
        url: String,
        /// Authorize this host for the request.
        #[arg(short = 'y', long)]
        i_authorize: bool,
        /// Cookies (inline list or file path).
        #[arg(short = 'c', long = "cookie", value_delimiter = ';')]
        cookies: Vec<String>,
        /// Extra headers as `Name: value`.
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        /// Bearer token.
        #[arg(short = 'b', long)]
        bearer: Option<String>,
        /// Emit JSON.
        #[arg(short = 'j', long)]
        json: bool,
        /// Path to a program policy TOML file. Enforces its scope and limits.
        #[arg(long, value_name = "FILE")]
        program: Option<String>,
        /// Your researcher handle; sent as an identity header when the
        /// program requires one.
        #[arg(long)]
        handle: Option<String>,
    },
    /// Analyze a URL for XSS: reflection, context and DOM taint flow.
    #[command(visible_alias = "w", long_about = "XSS analysis. Submits one benign marker per parameter (in the query, or the form body for a POST), resolves where the response reflects it, and traces the page's inline scripts for a source-to-sink taint flow. The marker carries no markup: this observes, it does not attack.\n\nWith no --param, every parameter already in the request is probed in turn.\n\nEXAMPLES:\n  bugtools w https://target/search?q=1 --i-authorize\n  bugtools xss https://target/item?id=1 -p id --i-authorize\n  bugtools w https://target/comment -X POST -d \"body=hi\" --i-authorize\n  bugtools w https://target/p?a=1 -p a -c session.txt -H \"X-Account-ID: 9\" --i-authorize --json")]
    Xss {
        /// URL to analyze. Query parameters are probed unless --param selects.
        url: String,
        /// Authorize this host for the request.
        #[arg(short = 'y', long)]
        i_authorize: bool,
        /// Parameter(s) to probe. Repeatable; defaults to every parameter the
        /// request already carries.
        #[arg(short = 'p', long = "param")]
        param: Vec<String>,
        /// Request method: GET or POST.
        #[arg(short = 'X', long, default_value = "GET")]
        method: String,
        /// Form body for a POST, as `a=1&b=2`.
        #[arg(short = 'd', long = "data")]
        data: Option<String>,
        /// Cookies (inline list or file path).
        #[arg(short = 'c', long = "cookie", value_delimiter = ';')]
        cookies: Vec<String>,
        /// Extra headers as `Name: value`.
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        /// Bearer token.
        #[arg(short = 'b', long)]
        bearer: Option<String>,
        /// Emit JSON.
        #[arg(short = 'j', long)]
        json: bool,
        /// Path to a program policy TOML file. Enforces its scope and limits.
        #[arg(long, value_name = "FILE")]
        program: Option<String>,
        /// Your researcher handle; sent as an identity header when the
        /// program requires one.
        #[arg(long)]
        handle: Option<String>,
    },
    /// Inspect adaptive payload generation (sends nothing).
    #[command(visible_alias = "gen", long_about = "Show the candidates the SQLi engine would use, with the rationale for each. Sends no traffic.\n\nEXAMPLES:\n  bugtools gen --clause where --quote single\n  bugtools payload --clause order_by --quote numeric --dbms postgresql --tier explore\n  bugtools gen --clause where --quote single --waf --json")]
    Payload {
        /// SQL clause/context: where, having, order_by, group_by, join, like,
        /// limit, insert, update, delete, select_expr, function_arg, generic.
        #[arg(long, default_value = "where")]
        clause: String,
        /// Quote mode: none, single, double, backtick, bracket.
        #[arg(long, default_value = "single")]
        quote: String,
        /// DBMS hypothesis: mysql, mariadb, postgresql, mssql, oracle,
        /// sqlite, db2, h2. Omit for unknown.
        #[arg(long)]
        dbms: Option<String>,
        /// Representation context: query, form, json, header, cookie, path.
        #[arg(long, default_value = "query")]
        representation: String,
        /// Escalation tier: recon, confirm, explore.
        #[arg(long, default_value = "recon")]
        tier: String,
        /// Technique: boolean, error, timing, union, clause.
        #[arg(long, default_value = "boolean")]
        technique: String,
        /// Simulate prior edge interference (widens representation breadth).
        #[arg(long)]
        waf: bool,
        /// Apply a named tamper chain to the composed candidates,
        /// e.g. `space2comment,randomcase,versionedmorekeywords`. Names match
        /// sqlmap's tamper scripts where the semantics match ours; each step is
        /// recorded so the result is replayable.
        #[arg(long, value_name = "NAMES")]
        tamper: Option<String>,
        /// List the available tampers and exit.
        #[arg(long)]
        list_tampers: bool,
        /// Print the shared payload catalogue — every payload the live engine
        /// can run, per technique, per depth tier, and per engine when --dbms
        /// is given. Sends nothing.
        #[arg(long)]
        catalogue: bool,
        /// Emit JSON instead of a human-readable table.
        #[arg(short = 'j', long)]
        json: bool,
    },
    /// Assess SQLi candidates from an endpoints/parameters JSON file.
    #[command(visible_alias = "q", long_about = "Assess SQLi candidates listed in a JSON file. Requires --i-authorize.\n\nEXAMPLES:\n  bugtools q --input endpoints.json --i-authorize\n  bugtools sqli --input endpoints.json -c cookies.txt --i-authorize --depth confirm\n  bugtools q --input endpoints.json -b \"eyJ...\" --i-authorize --json --format json")]
    Sqli {
        /// JSON file describing candidates: a list of objects with url,
        /// method, parameter and location fields.
        #[arg(short = 'i', long)]
        input: String,
        /// Authorize the hosts in the input file for probing.
        #[arg(short = 'y', long)]
        i_authorize: bool,
        /// Cookies to send. Accepts either an inline `name=value` list (use
        /// `;` to separate several) or a path to a cookie file — the file is
        /// read automatically when the argument names an existing file.
        #[arg(short = 'c', long = "cookie", value_delimiter = ';')]
        cookies: Vec<String>,
        /// Explicit cookie-file flag, equivalent to passing a path to
        /// `--cookie`. Kept for clarity.
        #[arg(long)]
        cookie_file: Option<String>,
        /// Extra headers as `Name: value` (repeatable).
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        /// Bearer token, sent as `Authorization: Bearer <token>`.
        #[arg(short = 'b', long)]
        bearer: Option<String>,
        /// Maximum concurrent probes.
        #[arg(long, default_value_t = 4)]
        concurrency: usize,
        /// Requests per second.
        #[arg(long, default_value_t = 5.0)]
        rate_limit: f64,
        /// Per-request timeout in seconds.
        #[arg(long, default_value_t = 15)]
        timeout: u64,
        /// Write the assessments as JSON to this path.
        #[arg(short = 'o', long)]
        output: Option<String>,
        /// Output format for stdout: text or json.
        #[arg(short = 'f', long, default_value = "text")]
        format: String,
        /// Test depth: recon, confirm, or explore.
        #[arg(short = 'd', long, default_value = "recon")]
        depth: String,
        /// Maximum requests to spend across the whole run.
        #[arg(long, default_value_t = 500)]
        max_requests: u64,
        /// Path to a program policy TOML file. Enforces its scope and limits.
        #[arg(long, value_name = "FILE")]
        program: Option<String>,
        /// Your researcher handle; sent as an identity header when the
        /// program requires one, and available as X-Bug-Bounty otherwise.
        #[arg(long)]
        handle: Option<String>,
        /// Known backend engine, so the engine-specific primitive catalogue is
        /// used instead of being guessed from the sweep: mysql, mariadb,
        /// postgresql, mssql, oracle, sqlite, db2, h2, sybase, firebird,
        /// informix, hsqldb, maxdb, hana, clickhouse, cubrid, virtuoso,
        /// monetdb, vertica, cache, presto, spanner, access.
        #[arg(long)]
        dbms: Option<String>,
        /// Apply a named tamper chain to every payload in the sweep,
        /// e.g. `space2comment,versionedmorekeywords`.
        #[arg(long, value_name = "NAMES")]
        tamper: Option<String>,
        /// Restrict the sweep to these techniques: error, timing, union,
        /// boolean, clause, syntax. Naming techniques overrides the depth
        /// tier gate, because naming one is a direct instruction.
        #[arg(long, value_delimiter = ',', value_name = "LIST")]
        techniques: Vec<String>,
        /// Disable the read-only proof extraction (version / current user /
        /// current db / is-dba) that otherwise runs automatically once a
        /// positive result is reached. Extraction is read-only SELECT only and
        /// shares the request budget.
        #[arg(long)]
        no_prove: bool,
        /// After the proof set, dump a table's rows read-only (sqlmap's
        /// `--dump`). Opt-in and row-capped; prints a rules-of-engagement / PII
        /// warning first. Requires --dump-table.
        #[arg(long)]
        dump: bool,
        /// Table to dump when --dump is set. Extraction stays read-only SELECT.
        #[arg(long, value_name = "TABLE")]
        dump_table: Option<String>,
        /// Row cap for --dump — kept small on purpose (most programs want
        /// proof-of-access, not mass exfiltration).
        #[arg(long, default_value_t = 5)]
        max_rows: usize,
        /// Enable out-of-band confirmation: induce the target DB to make an
        /// outbound DNS/HTTP lookup to an operator-controlled collector, then
        /// correlate a planted token. This is the only proof channel for a
        /// fully blind injection. Opt-in and requires --i-authorize; it causes
        /// the target database to emit outbound traffic to your collector.
        #[arg(long)]
        oob: bool,
        /// OOB collector backend: `interactsh` (default; a self-hosted or
        /// public interactsh server) or `byoc` (bring-your-own-collector — a
        /// domain you own plus a poll URL/file, e.g. Burp Collaborator or a
        /// custom DNS logger).
        #[arg(long, value_name = "KIND", default_value = "interactsh")]
        oob_provider: String,
        /// BYOC: the callback domain you control (tokens attach as labels of
        /// this domain). Required when --oob-provider byoc.
        #[arg(long, value_name = "DOMAIN")]
        oob_domain: Option<String>,
        /// BYOC: where to read logged interactions — an HTTP(S) URL returning a
        /// JSON array of interactions, or a local file the collector appends to.
        #[arg(long, value_name = "URL|FILE")]
        oob_poll: Option<String>,
        /// interactsh: server host to register with and poll (self-hosted or
        /// public). Defaults to the built-in public server.
        #[arg(long, value_name = "HOST")]
        oob_interactsh_server: Option<String>,
        /// interactsh: optional authorization token for a protected server.
        #[arg(long, value_name = "TOKEN")]
        oob_token: Option<String>,
        /// Seconds to wait after sending OOB payloads before polling the
        /// collector, giving the target DB time to perform the lookup.
        #[arg(long, default_value_t = 20, value_name = "SECS")]
        oob_wait: u64,
    },
    #[command(visible_alias = "e", long_about = "Endpoint discovery. Runs the composable extractor engine (HTML DOM, JavaScript request calls, and a path heuristic) over content and reports classified, route-templated endpoints with a confidence that reflects how many independent sources corroborate each one.\n\nOFFLINE (default): read a saved response/bundle from a file or stdin.\nLIVE (--i-authorize): fetch the URL through the scope-checked, rate-limited safe client, then dynamically follow the page's same-host scripts up to --depth and extract from those too.\n\nThe --profile flag sets a realistic browser header set (User-Agent, Accept, Sec-CH-UA) as defaults so an authorized scan presents as an ordinary client and is not trivially rejected. It sends a static, honest profile only: it does NOT spoof origin IPs, rotate headers, or attempt to defeat WAF/bot-management challenges.\n\nEXAMPLES:\n  bugtools e app.html --base https://target/\n  bugtools e - < bundle.js\n  bugtools e https://target/ --i-authorize\n  bugtools e https://target/ --i-authorize --depth 2 --profile chrome --json\n  bugtools e https://target/ --i-authorize --kind api --no-assets")]
    Endpoints {
        /// A file path, "-" for stdin, or (with --i-authorize) a URL to fetch.
        input: String,
        /// Authorize a live fetch of the URL and its same-host scripts.
        /// Without it, `input` is read as a file or from stdin.
        #[arg(short = 'y', long)]
        i_authorize: bool,
        /// Base URL to resolve relative references against (offline mode).
        /// In live mode the fetched URL is the base.
        #[arg(long)]
        base: Option<String>,
        /// Browser header profile for live requests: chrome, safari, api, none.
        #[arg(long, default_value = "chrome")]
        profile: String,
        /// Dynamic depth: also fetch same-host scripts found, this many levels.
        #[arg(long, default_value_t = 1)]
        depth: u32,
        /// Keep references that point at a host other than the base's.
        #[arg(long)]
        include_external: bool,
        /// Drop static-asset endpoints from the output.
        #[arg(long)]
        no_assets: bool,
        /// Show only endpoints of this kind: page, api, asset, form, websocket.
        #[arg(long)]
        kind: Option<String>,
        /// Cookies (inline list or file path).
        #[arg(short = 'c', long = "cookie", value_delimiter = ';')]
        cookies: Vec<String>,
        /// Extra headers as `Name: value`. Override profile defaults.
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        /// Bearer token.
        #[arg(short = 'b', long)]
        bearer: Option<String>,
        /// Requests per second for live fetching.
        #[arg(long, default_value_t = 5.0)]
        rate_limit: f64,
        /// Maximum requests to spend across a live run.
        #[arg(long, default_value_t = 50)]
        max_requests: u64,
        /// Path to a program policy TOML file. Enforces its scope and limits.
        #[arg(long, value_name = "FILE")]
        program: Option<String>,
        /// Your researcher handle; sent as an identity header when supplied.
        #[arg(long)]
        handle: Option<String>,
        /// Emit JSON instead of a human-readable table.
        #[arg(short = 'j', long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub enum SqlCommands {
    /// Identify a DBMS from pasted error text (offline, no network).
    #[command(visible_alias = "id", long_about = "Identify a DBMS from error text. Sends nothing. Use \"-\" to read from stdin.\n\nEXAMPLES:\n  bugtools s detect \"ORA-01756: quoted string not properly terminated\"\n  bugtools s detect - < error.txt")]
    Detect {
        /// Error text. Use "-" to read from stdin.
        text: String,
    },
    /// Print the clause/dialect reference, optionally filtered.
    #[command(visible_alias = "ref", long_about = "Print the SQL clause/dialect reference.\n\nEXAMPLES:\n  bugtools sql clauses\n  bugtools s ref --dbms postgresql")]
    Clauses {
        /// Show only clauses the given DBMS accepts.
        #[arg(long)]
        dbms: Option<String>,
    },
    /// Run scope-checked DBMS detection against a live parameterized URL.
    #[command(visible_alias = "a", long_about = "Live scope-checked DBMS detection. Requires --i-authorize.\n\nEXAMPLES:\n  bugtools s a \"https://target/item?id=1\" --i-authorize\n  bugtools sql analyze \"https://target/item?id=1\" -p id -c session.txt --i-authorize\n  bugtools sql analyze \"https://target/item?id=1\" -H \"X-Bug-Bounty: handle\" --json --i-authorize")]
    Analyze {
        /// Full URL including at least one query parameter, e.g.
        /// https://target/item?id=1
        url: String,
        /// Parameter to probe (defaults to the first query parameter).
        #[arg(short = 'p', long)]
        param: Option<String>,
        /// Authorize this host for the scan. Without it, nothing is sent.
        #[arg(short = 'y', long)]
        i_authorize: bool,
        /// Cookie(s): `name=value`, `a=1; b=2`, or a file path. Repeatable.
        #[arg(short = 'c', long = "cookie")]
        cookies: Vec<String>,
        /// File containing a `Cookie:` header value or one `name=value` per line.
        #[arg(long, value_name = "FILE")]
        cookie_file: Option<String>,
        /// Extra request header as `Name: value`. Repeatable.
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        /// Bearer token; sent as `Authorization: Bearer <token>`.
        #[arg(short = 'b', long)]
        bearer: Option<String>,
        /// Your researcher handle; sent as an X-Bug-Bounty identity header.
        #[arg(long)]
        handle: Option<String>,
        /// Emit JSON instead of a human-readable summary.
        #[arg(short = 'j', long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub enum NosqlCommands {
    /// Fingerprint a NoSQL datastore from pasted error text (offline, no network).
    #[command(visible_alias = "id", long_about = "Identify a NoSQL datastore (MongoDB/Mongoose, CouchDB, Redis, Elasticsearch, Cassandra) from error text. Sends nothing. Use \"-\" to read from stdin.\n\nEXAMPLES:\n  bugtools n detect \"MongoError: E11000 duplicate key error\"\n  bugtools n detect - < error.txt")]
    Detect {
        /// Error text. Use "-" to read from stdin.
        text: String,
    },
    /// Run scope-checked NoSQL operator-injection detection against a live URL.
    #[command(visible_alias = "a", long_about = "Live scope-checked NoSQL injection detection. Requires --i-authorize.\n\nBaselines the endpoint, then runs a bounded, deduplicated set of read-only operator-injection experiments (error probes, `$ne`/`$gt` auth-bypass, a matched boolean pair, and a capped `$where` timing probe), each repeated before it is trusted. Reports a coverage verdict including NOT_INTERPRETED when operator injection never diverges from a stable baseline. Optionally attempts a bounded, strictly read-only `$regex` prefix extraction of --extract-field, only after an injection differential is established.\n\nEXAMPLES:\n  bugtools n a \"https://target/login?user=alice\" -p user --i-authorize\n  bugtools nosql analyze \"https://target/api?user=x\" -p user -c session.txt --i-authorize --json\n  bugtools n a \"https://target/login?user=x\" -p user --extract-field password --i-authorize")]
    Analyze {
        /// Full URL including at least one query parameter, e.g.
        /// https://target/login?user=alice
        url: String,
        /// Parameter to probe (defaults to the first query parameter).
        #[arg(short = 'p', long)]
        param: Option<String>,
        /// Authorize this host for the scan. Without it, nothing is sent.
        #[arg(short = 'y', long)]
        i_authorize: bool,
        /// Cookie(s): `name=value`, `a=1; b=2`, or a file path. Repeatable.
        #[arg(short = 'c', long = "cookie")]
        cookies: Vec<String>,
        /// File containing a `Cookie:` header value or one `name=value` per line.
        #[arg(long, value_name = "FILE")]
        cookie_file: Option<String>,
        /// Extra request header as `Name: value`. Repeatable.
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        /// Bearer token; sent as `Authorization: Bearer <token>`.
        #[arg(short = 'b', long)]
        bearer: Option<String>,
        /// Your researcher handle; sent as an X-Bug-Bounty identity header.
        #[arg(long)]
        handle: Option<String>,
        /// Attempt bounded read-only `$regex` extraction of this field (only
        /// after an injection differential is observed).
        #[arg(long, value_name = "FIELD")]
        extract_field: Option<String>,
        /// Requested `$where` timing-probe delay in milliseconds (capped by the
        /// safety gate).
        #[arg(long, default_value_t = 3_000)]
        where_delay_ms: u64,
        /// Maximum requests to spend across the whole run.
        #[arg(long, default_value_t = 16)]
        max_experiments: usize,
        /// Emit JSON instead of a human-readable summary.
        #[arg(short = 'j', long)]
        json: bool,
    },
}
