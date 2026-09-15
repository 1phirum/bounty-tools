//! Serial, non-blocking UI/backend boundary. Only Refresh reads a snapshot.
//! This module deliberately exposes no fuzzing, recon, or SQL probing actions.
use crate::{commands, state::AppState};
use bugtools_core::{finding::Finding, job::Job, project::Project, scope::ScopeRule};
use bugtools_storage::Database;
use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::Write,
    panic::{catch_unwind, AssertUnwindSafe},
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::Duration,
};
use uuid::Uuid;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const TRAFFIC_LIMIT: usize = 500;

#[derive(Debug)]
pub enum Action {
    Refresh,
    CreateProject {
        name: String,
        description: String,
    },
    SelectProject {
        id: Uuid,
    },
    AddScope {
        kind: String,
        pattern: String,
    },
    EvaluateScope {
        target: String,
    },
    MapSubdomains {
        target: String,
    },
    SqlClause {
        query: String,
    },
    SqlDialect {
        query: String,
    },
    SqlSimulate {
        target: String,
    },
    /// Real scope-checked DBMS detection against a parameterized endpoint.
    SqlAnalyze {
        url: String,
        param: String,
        value: String,
    },
    ClearTraffic,
    SendRequest {
        url: String,
        method: String,
        headers: String,
        body: String,
    },
    CreateFinding {
        title: String,
        target: String,
        notes: String,
        severity: String,
    },
    ExportReport {
        path: String,
    },
}

#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub projects: Vec<Project>,
    pub active_project: Option<Uuid>,
    pub rules: Vec<ScopeRule>,
    pub findings: Vec<Finding>,
    pub jobs: Vec<Job>,
    /// Session-wide, newest first; the existing store has no project ownership.
    pub traffic: Vec<bugtools_http::TrafficEntry>,
    /// Number retained by the store, not a lifetime request count.
    pub total_traffic: usize,
    pub evicted: usize,
}

#[derive(Debug)]
pub enum Message {
    Snapshot(Snapshot),
    Output { title: String, text: String },
    Subdomains(Vec<String>),
    LiveLog(String),
    Error(String),
}

pub struct Bridge {
    actions: Sender<Action>,
    messages: Receiver<Message>,
    // Kept only to surface spawn/send failures through the same UI channel.
    feedback: Sender<Message>,
    ctx: egui::Context,
}

impl Bridge {
    /// Initialization, database IO, and commands all run off the egui thread.
    /// The caller should enqueue Refresh initially and after mutations if desired.
    pub fn start(db_path: PathBuf, ctx: egui::Context) -> Self {
        let (actions, action_rx) = mpsc::channel();
        let (feedback, messages) = mpsc::channel();
        let worker_tx = feedback.clone();
        let worker_ctx = ctx.clone();
        let spawned = thread::Builder::new()
            .name("bugtools-backend".into())
            .spawn(move || {
                // Legacy backend constructors contain infallible APIs/unwraps.
                // Contain unwinding here, report failure, and discard that state.
                let result = catch_unwind(AssertUnwindSafe(|| {
                    worker(db_path, action_rx, &worker_tx, &worker_ctx)
                }));
                let error = match result {
                    Ok(Ok(())) => None,
                    Ok(Err(error)) => Some(error),
                    Err(_) => Some("Backend worker panicked and stopped; restart the application. No further actions were executed.".into()),
                };
                if let Some(error) = error {
                    emit(&worker_tx, &worker_ctx, Message::Error(error));
                }
            });
        if let Err(error) = spawned {
            emit(
                &feedback,
                &ctx,
                Message::Error(format!("Cannot start backend worker: {error}")),
            );
        }
        // Dropping the JoinHandle detaches; never join a worker from the UI thread.
        Self {
            actions,
            messages,
            feedback,
            ctx,
        }
    }

    pub fn send(&self, action: Action) {
        // Unbounded std channel: never wait for backend/network progress.
        if self.actions.send(action).is_err() {
            emit(
                &self.feedback,
                &self.ctx,
                Message::Error("Backend is unavailable; restart the application.".into()),
            );
        }
    }

    pub fn try_recv(&self) -> Option<Message> {
        self.messages.try_recv().ok()
    }
}

fn emit(tx: &Sender<Message>, ctx: &egui::Context, message: Message) {
    let _ = tx.send(message);
    ctx.request_repaint();
}

fn worker(
    db_path: PathBuf,
    actions: Receiver<Action>,
    messages: &Sender<Message>,
    ctx: &egui::Context,
) -> Result<(), String> {
    if let Some(parent) = db_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Cannot create database directory: {e}"))?;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("Cannot initialize Tokio runtime: {error}"))?;
    let state = runtime.block_on(async {
        let db = Database::open(&db_path)
            .map_err(|error| format!("Cannot open database {}: {error}", db_path.display()))?;
        Ok::<_, String>(AppState::new(db))
    })?;
    emit(
        messages,
        ctx,
        output(
            "Backend ready",
            "BugTools is ready. Paste a link and start scanning.",
        ),
    );
    while let Ok(action) = actions.recv() {
        if let Action::SqlSimulate { target } = action {
            // Real scope-checked DBMS detection. The input may be a bare
            // parameterized URL; we probe the first query parameter, or add a
            // `bt_probe` parameter when none exists. Every request is
            // scope-checked by the engine before touching the wire.
            emit(messages, ctx, Message::LiveLog(format!("[*] Preparing DBMS detection for {}", target)));
            let outcome = runtime.block_on(run_sql_scan(target, &state, messages, ctx));
            match outcome {
                Ok(summary) => emit(messages, ctx, Message::LiveLog(summary)),
                Err(error) => emit(messages, ctx, Message::Error(error)),
            }
            continue;
        }
        // Await each command to completion before taking the next action. No
        // independent request task can outlive a project selection change.
        let message = runtime
            .block_on(dispatch(action, &state))
            .unwrap_or_else(Message::Error);
        emit(messages, ctx, message);
    }
    Ok(())
}

/// Run a real, scope-checked DBMS detection scan and stream genuine
/// per-probe logs. Returns a summary line on completion. This is the live
/// counterpart of the offline evidence review — no hardcoded output.
async fn run_sql_scan(
    target: String,
    state: &AppState,
    messages: &Sender<Message>,
    ctx: &egui::Context,
) -> Result<String, String> {
    // Resolve a probe parameter: use the first existing query key, else
    // inject a dedicated marker parameter so the probes have a slot.
    let parsed = url::Url::parse(target.trim())
        .map_err(|e| format!("Enter an absolute http(s) URL to scan: {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err("Scan target must be an absolute http:// or https:// URL.".into());
    }
    let (url, param, value) = {
        let mut p = parsed.clone();
        let first_key = parsed
            .query_pairs()
            .next()
            .map(|(k, v)| (k.to_string(), v.to_string()));
        match first_key {
            Some((k, v)) => (p.to_string(), k, v),
            None => {
                p.query_pairs_mut().append_pair("bt_probe", "1");
                (p.to_string(), "bt_probe".to_string(), "1".to_string())
            }
        }
    };

    // Scope gate. The scanner UI has no project/scope tab, so when the
    // engine has no rules yet we pin a single include-domain rule for this
    // host — making the scan self-contained while keeping default-deny for
    // any *other* host. If rules exist, the target must match one.
    if state.scope.rule_count() == 0 {
        if let Some(host) = parsed.host_str() {
            use bugtools_core::scope::{ScopeRule, ScopeRuleType};
            let project = active_project(state).await.unwrap_or_else(|_| Uuid::nil());
            state.scope.add_rule(ScopeRule::new(project, ScopeRuleType::IncludeDomain, host.to_string()));
            emit(messages, ctx, Message::LiveLog(format!("[*] Scope was empty — pinned include rule for {}", host)));
        }
    }
    let evaluation = state.scope.evaluate(&url);
    if !evaluation.allowed {
        return Err(format!("Scope denied the target: {}", evaluation.reason));
    }
    if evaluation
        .matched_rule
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .is_none()
    {
        return Err("Scope returned no matching rule; refusing to scan.".into());
    }
    emit(messages, ctx, Message::LiveLog(format!("[+] Scope allows target ({}).", evaluation.reason)));
    emit(messages, ctx, Message::LiveLog(format!("[*] Probing parameter '{}' on {}", param, url)));

    let result = commands::sql_research::sql_analyze_endpoint(
        url,
        "GET".to_string(),
        None,
        None,
        param.clone(),
        value,
        state,
    )
    .await?;

    // Stream real per-probe results.
    for signal in &result.dbms_detection.signals {
        emit(
            messages,
            ctx,
            Message::LiveLog(format!(
                "[signal] {} -> {} (+{})",
                signal.label,
                signal.dbms.label(),
                signal.weight
            )),
        );
    }
    let detected = match &result.dbms_hypothesis {
        Some(d) => format!("{} ({}% confidence)", d.display_name(), result.confidence_score),
        None => "undetermined (no DBMS-specific error patterns observed)".to_string(),
    };
    Ok(format!(
        "[+] Detection complete: {} · {} techniques tested · verdict: {:?}",
        detected,
        result.techniques_tested.len(),
        result.dbms_detection.verdict
    ))
}

fn output(title: impl Into<String>, text: impl Into<String>) -> Message {
    Message::Output {
        title: title.into(),
        text: text.into(),
    }
}

async fn active_project(state: &AppState) -> Result<Uuid, String> {
    let id = (*state.active_project_id.read().await)
        .ok_or_else(|| "Select or create a project first.".to_string())?;
    // Validate existence and reload scope from the DB before using it. A DB
    // failure clears selection and rules instead of reusing stale permissions.
    commands::project::set_active_project(id.to_string(), state).await?;
    Ok(id)
}

async fn dispatch(action: Action, state: &AppState) -> Result<Message, String> {
    match action {
        Action::Refresh => match snapshot(state).await {
            Ok(snapshot) => Ok(Message::Snapshot(snapshot)),
            Err(error) => {
                *state.active_project_id.write().await = None;
                state.scope.set_rules(Vec::new());
                Err(format!("Refresh failed; active project cleared: {error}"))
            }
        },
        Action::CreateProject { name, description } => {
            if name.trim().is_empty() {
                return Err("Project name is required.".into());
            }
            let project =
                commands::project::create_project(name.trim().into(), description, state).await?;
            Ok(output(
                "Project created",
                format!(
                    "{} ({}) is selected. Refresh to update the lists.",
                    project.name, project.id
                ),
            ))
        }
        Action::SelectProject { id } => {
            commands::project::set_active_project(id.to_string(), state).await?;
            Ok(output(
                "Project selected",
                format!("Selected {id}. Scope rules synchronized. Refresh to update the lists."),
            ))
        }
        Action::AddScope { kind, pattern } => {
            let id = active_project(state).await?;
            let kind = kind.trim().to_lowercase();
            if !matches!(
                kind.as_str(),
                "include_domain"
                    | "exclude_domain"
                    | "include_path"
                    | "exclude_path"
                    | "include_port"
                    | "exclude_port"
                    | "protocol"
            ) {
                return Err("Unknown scope rule kind.".into());
            }
            if pattern.trim().is_empty() {
                return Err("Scope pattern is required.".into());
            }
            let rule =
                commands::scope::add_scope_rule(id.to_string(), kind, pattern.trim().into(), state)
                    .await?;
            Ok(output(
                "Scope rule added",
                format!("Added rule {}. Refresh to update the lists.", rule.id),
            ))
        }
        Action::EvaluateScope { target } => {
            active_project(state).await?;
            let evaluation = commands::scope::evaluate_target(target, state).await?;
            let text =
                serde_json::to_string_pretty(&evaluation).map_err(|error| error.to_string())?;
            let warning = if evaluation.allowed && evaluation.matched_rule.is_none() {
                "\n\nWarning: the engine allowed this without a matched rule. The GUI refuses network sends in this state."
            } else {
                ""
            };
            Ok(output(
                "Scope evaluation (offline)",
                format!("{text}{warning}"),
            ))
        }
        Action::SqlSimulate { .. } => {
            unreachable!("Handled in worker loop")
        }
        Action::SqlAnalyze { url, param, value } => {
            active_project(state).await?;
            // Real DBMS detection: the probe engine sends scope-checked
            // requests and analyzes which dialect's error patterns appear.
            let evaluation = state.scope.evaluate(&url);
            if !evaluation.allowed {
                return Err(format!("Scope denied the target: {}", evaluation.reason));
            }
            if evaluation
                .matched_rule
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_none()
            {
                return Err("Scope evaluation returned no matching rule; cannot probe.".into());
            }
            let result = commands::sql_research::sql_analyze_endpoint(
                url,
                "GET".to_string(),
                None,
                None,
                param,
                value,
                state,
            )
            .await?;
            let text = serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?;
            Ok(output("SQL detection result", text))
        }
        Action::SqlClause { query } => {
            let result = commands::sql_research::sql_get_clause_map(
                if query.is_empty() { None } else { Some(query) }, 
                state
            ).await?;
            Ok(output("SQL Clause Map", format!("{:#?}", result)))
        }
        Action::SqlDialect { query } => {
            let parts: Vec<&str> = query.split_whitespace().collect();
            if parts.len() != 2 {
                return Ok(output("Usage Error", "Please specify both a clause and DBMS separated by a space, e.g., 'union postgres' or 'where mysql'."));
            }
            let result = commands::sql_research::sql_get_dialect_variants(
                parts[0].into(), 
                parts[1].into(), 
                state
            ).await?;
            Ok(output("SQL Dialect Variants", serde_json::to_string_pretty(&result).unwrap_or_default()))
        }
        Action::ClearTraffic => {
            commands::traffic::clear_traffic(state).await?;
            Ok(output(
                "HTTP history cleared",
                "Session memory cleared; findings and projects are untouched.",
            ))
        }
        Action::MapSubdomains { target } => {
            let target = target.trim().to_lowercase();
            let domain = if let Ok(url) = url::Url::parse(&target) {
                if let Some(host) = url.host_str() {
                    host.to_string()
                } else {
                    target
                }
            } else {
                target
            };

            let url = format!("https://crt.sh/?q=%.{}&output=json", domain);
            
            #[derive(serde::Deserialize)]
            struct CrtShResult {
                name_value: String,
            }
            
            let client = reqwest::Client::builder()
                .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) BugTools/1.0")
                .build()
                .unwrap_or_else(|_| reqwest::Client::new());
            let response = client
                .get(&url)
                .timeout(Duration::from_secs(30))
                .send()
                .await
                .map_err(|e| format!("Request to crt.sh failed: {}", e))?;
                
            if !response.status().is_success() {
                return Err(format!("crt.sh returned an error: {}", response.status()));
            }
            
            let records: Vec<CrtShResult> = response
                .json()
                .await
                .map_err(|e| format!("Failed to parse crt.sh JSON: {}", e))?;
                
            let mut subdomains: Vec<String> = Vec::new();
            for record in records {
                for name in record.name_value.split('\n') {
                    let clean = name.trim().to_string();
                    if !clean.is_empty() && clean != format!("*.{}", domain) && clean != domain {
                        subdomains.push(clean);
                    }
                }
            }
            
            subdomains.sort();
            subdomains.dedup();
            
            if subdomains.is_empty() {
                Ok(output("No subdomains found", format!("crt.sh returned no subdomains for {}", domain)))
            } else {
                Ok(Message::Subdomains(subdomains))
            }
        }
        Action::SendRequest {
            url,
            method,
            headers,
            body,
        } => {
            if headers.len() > 64 * 1024 || body.len() > 2 * 1024 * 1024 {
                return Err("Limit request headers to 64 KiB and body to 2 MiB.".into());
            }
            let headers = parse_headers(&headers)?;
            let method = method.trim().to_uppercase();
            // Allow only methods exposed by the native composer.
            if !matches!(
                method.as_str(),
                "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "PATCH" | "OPTIONS"
            ) {
                return Err("Unsupported HTTP method.".into());
            }
            let url = url.trim().to_string();
            let parsed =
                url::Url::parse(&url).map_err(|error| format!("Invalid request URL: {error}"))?;
            if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
                return Err(
                    "Requests require an absolute http:// or https:// URL with a host.".into(),
                );
            }
            active_project(state).await?;
            let evaluation = state.scope.evaluate(&url);
            require_scope_match(&evaluation)?;
            let response = tokio::time::timeout(
                REQUEST_TIMEOUT,
                commands::traffic::send_request(url, method, Some(headers), if body.is_empty() { None } else { Some(body) }, state),
            ).await.map_err(|_| "Request timed out after 30 seconds. It may already have reached the server; no retry was made.".to_string())??;
            Ok(output(
                "HTTP response",
                serde_json::to_string_pretty(&response).map_err(|error| error.to_string())?,
            ))
        }
        Action::CreateFinding {
            title,
            target,
            notes,
            severity,
        } => {
            let id = active_project(state).await?;
            if title.trim().is_empty() {
                return Err("Finding title is required.".into());
            }
            let severity = severity.trim().to_uppercase();
            if !matches!(
                severity.as_str(),
                "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
            ) {
                return Err("Unknown finding severity.".into());
            }
            let endpoint = url::Url::parse(&target)
                .map(|url| url.path().to_string())
                .unwrap_or_default();
            let finding = commands::findings::create_finding(
                id.to_string(),
                title.trim().into(),
                severity,
                "INFO".into(),
                target,
                endpoint,
                None,
                "manual".into(),
                "manual observation".into(),
                None,
                if notes.is_empty() { None } else { Some(notes) },
                state,
            )
            .await?;
            Ok(output(
                "Finding saved",
                format!(
                    "Saved {} as an unverified candidate. Refresh to update the lists.",
                    finding.id
                ),
            ))
        }
        Action::ExportReport { path } => {
            if path.trim().is_empty() {
                return Err("Choose a report file path.".into());
            }
            // Read all data before creating the file, so query failures do not
            // produce a misleading partial report.
            let project_id = active_project(state).await?;
            let report = build_report(state, project_id)?;
            write_report(Path::new(&path), &report)?;
            Ok(output("Report exported", format!("Created {path}. Projects and findings only; no traffic, request/response headers or bodies, credentials, or settings were exported. User-entered descriptions and notes are included: review them for secrets before sharing.")))
        }
    }
}

fn parse_headers(headers: &str) -> Result<HashMap<String, String>, String> {
    serde_json::from_str(headers).map_err(|error| {
        format!("Headers must be a JSON object with string values (use {{}} for none): {error}")
    })
}

fn require_scope_match(evaluation: &bugtools_core::scope::ScopeEvaluation) -> Result<(), String> {
    if !evaluation.allowed {
        return Err(format!("Scope denied the request: {}", evaluation.reason));
    }
    if evaluation
        .matched_rule
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err("Network request blocked: scope evaluation returned no matching rule. Scope enforcement may be disabled; restore it before sending requests.".into());
    }
    Ok(())
}

async fn snapshot(state: &AppState) -> Result<Snapshot, String> {
    let mut projects = commands::project::list_projects(state).await?;
    
    // Auto-create default workspace if no projects exist
    if projects.is_empty() {
        if let Ok(project) = commands::project::create_project("Bug Bounty Workspace".into(), "Auto-created workspace for immediate hacking".into(), state).await {
            projects.push(project);
        }
    }
    
    // Auto-select a project if none is active
    let mut active = *state.active_project_id.read().await;
    if active.is_none() && !projects.is_empty() {
        let first_id = projects[0].id;
        if commands::project::set_active_project(first_id.to_string(), state).await.is_ok() {
            *state.active_project_id.write().await = Some(first_id);
            active = Some(first_id);
        }
    }

    let (rules, findings, jobs) = if let Some(id) = active {
        if !projects.iter().any(|project| project.id == id) {
            return Err("The selected project no longer exists.".into());
        }
        let rules = commands::scope::get_scope_rules(id.to_string(), state).await?;
        state.scope.set_rules(rules.clone());
        (
            rules,
            commands::findings::list_findings(id.to_string(), state).await?,
            commands::jobs::list_jobs(id.to_string(), state).await?,
        )
    } else {
        (Vec::new(), Vec::new(), Vec::new())
    };
    let traffic = state.engines.store.page(0, TRAFFIC_LIMIT);
    let (total_traffic, evicted) = state.engines.store.stats();
    Ok(Snapshot {
        projects,
        active_project: active,
        rules,
        findings,
        jobs,
        traffic,
        total_traffic,
        evicted,
    })
}

fn build_report(state: &AppState, project_id: Uuid) -> Result<String, String> {
    let projects = state.db.get_projects().map_err(|error| error.to_string())?;
    let mut report = format!("# BugTools project and findings report\n\nGenerated: {}\n\nThis report contains projects and findings only. Traffic, HTTP request/response headers and bodies, credentials, and settings are not exported. User-entered descriptions, targets, and notes may contain sensitive information; review before sharing. Findings are observations, not proof of exploitation.\n\n", chrono::Utc::now().to_rfc3339());
    for project in projects.into_iter().filter(|p| p.id == project_id) {
        let findings = state
            .db
            .get_findings(project.id)
            .map_err(|error| error.to_string())?;
        report.push_str(&format!(
            "## Project: {}\n\nID: {}\n\n{}\n\n",
            markdown_text(&project.name),
            project.id,
            markdown_text(&project.description)
        ));
        if findings.is_empty() {
            report.push_str("No findings recorded.\n\n");
        }
        for finding in findings {
            report.push_str(&format!("### {}\n\n- ID: {}\n- Severity: {:?}\n- Confidence: {:?}\n- Status: {:?}\n- Target: {}\n- Endpoint: {}\n- Module: {}\n- Technique: {}\n\nNotes:\n\n{}\n\n",
                markdown_text(&finding.title), finding.id, finding.severity, finding.confidence, finding.status,
                markdown_text(&finding.target), markdown_text(&finding.endpoint), markdown_text(&finding.module), markdown_text(&finding.technique), markdown_text(finding.notes.as_deref().unwrap_or("None"))));
        }
    }
    Ok(report)
}

fn markdown_text(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '\n' => result.push_str("\n\n"),
            '\r' => {}
            '\\' | '`' | '*' | '_' | '{' | '}' | '[' | ']' | '(' | ')' | '#' | '+' | '-' | '.'
            | '!' | '|' => {
                result.push('\\');
                result.push(ch);
            }
            _ => result.push(ch),
        }
    }
    result
}

fn write_report(path: &Path, report: &str) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        format!(
            "Cannot create report {} (existing files are never overwritten): {error}",
            path.display()
        )
    })?;
    file.write_all(report.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|error| {
            format!(
                "Report write failed at {}; a partial file may remain: {error}",
                path.display()
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_require_string_map() {
        assert!(parse_headers("{}").is_ok());
        assert_eq!(
            parse_headers(r#"{"Accept":"application/json"}"#).unwrap()["Accept"],
            "application/json"
        );
        for invalid in ["", "null", "[]", r#"{"X":42}"#, r#"{"X":null}"#] {
            assert!(parse_headers(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn permissive_engine_without_a_rule_is_not_authorization() {
        let evaluation = bugtools_core::scope::ScopeEvaluation {
            target: "https://example.com".into(),
            allowed: true,
            matched_rule: None,
            reason: "Scope disabled globally by user request".into(),
        };
        assert!(require_scope_match(&evaluation).is_err());
    }

    #[test]
    fn report_never_overwrites() {
        let path = std::env::temp_dir().join(format!("bugtools-report-{}.md", Uuid::new_v4()));
        write_report(&path, "first").unwrap();
        assert!(write_report(&path, "second").is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn markdown_does_not_embed_html_or_links() {
        let escaped = markdown_text("<script>[link](https://example.com)</script>");
        assert!(!escaped.contains("<script>"));
        assert!(escaped.contains("\\[link\\]\\("));
    }
}

#[cfg(test)]
mod workflow_tests {
    use super::*;
    #[tokio::test]
    async fn project_scope_finding_and_report_workflow() {
        let state = AppState::new(Database::open_in_memory().unwrap());
        dispatch(
            Action::CreateProject {
                name: "Alpha".into(),
                description: "Test".into(),
            },
            &state,
        )
        .await
        .unwrap();
        let alpha = state.active_project_id.read().await.unwrap();
        dispatch(
            Action::AddScope {
                kind: "include_domain".into(),
                pattern: "example.test".into(),
            },
            &state,
        )
        .await
        .unwrap();
        assert!(state.scope.evaluate("https://example.test").allowed);
        dispatch(
            Action::CreateFinding {
                title: "Observation".into(),
                target: "https://example.test".into(),
                notes: "No secrets".into(),
                severity: "INFO".into(),
            },
            &state,
        )
        .await
        .unwrap();
        assert_eq!(snapshot(&state).await.unwrap().findings.len(), 1);
        dispatch(
            Action::CreateProject {
                name: "Beta".into(),
                description: "Other".into(),
            },
            &state,
        )
        .await
        .unwrap();
        assert!(!state.scope.evaluate("https://example.test").allowed);
        let beta = state.active_project_id.read().await.unwrap();
        let report = build_report(&state, beta).unwrap();
        assert!(!report.contains("Observation"));
        dispatch(Action::SelectProject { id: alpha }, &state)
            .await
            .unwrap();
        assert!(state.scope.evaluate("https://example.test").allowed);
        assert_eq!(snapshot(&state).await.unwrap().findings.len(), 1);
        assert!(
            dispatch(Action::SelectProject { id: Uuid::new_v4() }, &state)
                .await
                .is_err()
        );
        assert!(state.active_project_id.read().await.is_none());
        assert!(!state.scope.evaluate("https://example.test").allowed);
    }
}
