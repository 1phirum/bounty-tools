use bugtools_core::{
    finding::{Confidence, Finding, FindingStatus, Severity},
    job::{Job, JobStatus, ModuleType},
    project::Project,
    scope::{ScopeRule, ScopeRuleType},
    settings::Settings,
};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("Entity not found: {0}")]
    NotFound(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, StorageError> {
        eprintln!("  -> Connection::open...");
        let conn = Connection::open(path)?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        eprintln!("  -> db.init_schema()...");
        db.init_schema()?;
        eprintln!("  -> Database ready.");
        Ok(db)
    }

    pub fn open_in_memory() -> Result<Self, StorageError> {
        let conn = Connection::open_in_memory()?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<(), StorageError> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            r#"
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS scope_rules (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                rule_type TEXT NOT NULL,
                pattern TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS targets (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                url TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_jobs (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                module TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                progress REAL NOT NULL DEFAULT 0.0,
                current_step TEXT NOT NULL,
                requests_sent INTEGER NOT NULL DEFAULT 0,
                max_requests INTEGER NOT NULL DEFAULT 1000,
                created_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                error_message TEXT
            );

            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                status TEXT NOT NULL,
                target TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                parameter TEXT,
                module TEXT NOT NULL,
                technique TEXT NOT NULL,
                dbms_hypothesis TEXT,
                notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                level TEXT NOT NULL,
                component TEXT NOT NULL,
                message TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                max_requests_per_second REAL NOT NULL,
                max_worker_concurrency INTEGER NOT NULL,
                max_requests_per_job INTEGER NOT NULL
            );
            "#,
        )?;
        // Insert default settings if they don't exist
        self.init_default_settings()?;
        Ok(())
    }

    fn init_default_settings(&self) -> Result<(), StorageError> {
        let conn = self.conn.lock().unwrap();
        let default_settings = Settings::default();
        conn.execute(
            "INSERT OR IGNORE INTO settings (id, max_requests_per_second, max_worker_concurrency, max_requests_per_job) VALUES (1, ?1, ?2, ?3)",
            params![
                default_settings.max_requests_per_second as f64,
                default_settings.max_worker_concurrency as i64,
                default_settings.max_requests_per_job as i64,
            ],
        )?;
        Ok(())
    }

    // --- Settings CRUD ---

    pub fn get_settings(&self) -> Result<Settings, StorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT max_requests_per_second, max_worker_concurrency, max_requests_per_job FROM settings WHERE id = 1")?;
        let mut rows = stmt.query([])?;
        
        if let Some(row) = rows.next()? {
            let rps: f64 = row.get(0)?;
            let conc: i64 = row.get(1)?;
            let max_req: i64 = row.get(2)?;
            Ok(Settings {
                max_requests_per_second: rps as f32,
                max_worker_concurrency: conc as usize,
                max_requests_per_job: max_req as usize,
            })
        } else {
            Ok(Settings::default())
        }
    }

    pub fn update_settings(&self, settings: &Settings) -> Result<(), StorageError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE settings SET max_requests_per_second = ?1, max_worker_concurrency = ?2, max_requests_per_job = ?3 WHERE id = 1",
            params![
                settings.max_requests_per_second as f64,
                settings.max_worker_concurrency as i64,
                settings.max_requests_per_job as i64,
            ],
        )?;
        Ok(())
    }

    // --- Projects CRUD ---

    pub fn insert_project(&self, project: &Project) -> Result<(), StorageError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO projects (id, name, description, created_at, updated_at, active) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                project.id.to_string(),
                project.name,
                project.description,
                project.created_at.to_rfc3339(),
                project.updated_at.to_rfc3339(),
                if project.active { 1 } else { 0 }
            ],
        )?;
        Ok(())
    }

    pub fn get_projects(&self) -> Result<Vec<Project>, StorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id, name, description, created_at, updated_at, active FROM projects ORDER BY created_at DESC")?;
        let rows = stmt.query_map([], |row| {
            let id_str: String = row.get(0)?;
            let created_str: String = row.get(3)?;
            let updated_str: String = row.get(4)?;
            let active_int: i32 = row.get(5)?;
            Ok(Project {
                id: Uuid::parse_str(&id_str).unwrap_or_default(),
                name: row.get(1)?,
                description: row.get(2)?,
                created_at: DateTime::parse_from_rfc3339(&created_str).map(|dt| dt.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now()),
                updated_at: DateTime::parse_from_rfc3339(&updated_str).map(|dt| dt.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now()),
                active: active_int != 0,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    // --- Scope Rules CRUD ---

    pub fn insert_scope_rule(&self, rule: &ScopeRule) -> Result<(), StorageError> {
        let conn = self.conn.lock().unwrap();
        let type_str = serde_json::to_string(&rule.rule_type).unwrap_or_default().replace('\"', "");
        conn.execute(
            "INSERT INTO scope_rules (id, project_id, rule_type, pattern, enabled, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                rule.id.to_string(),
                rule.project_id.to_string(),
                type_str,
                rule.pattern,
                if rule.enabled { 1 } else { 0 },
                rule.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn get_scope_rules(&self, project_id: Uuid) -> Result<Vec<ScopeRule>, StorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id, project_id, rule_type, pattern, enabled, created_at FROM scope_rules WHERE project_id = ?1")?;
        let rows = stmt.query_map(params![project_id.to_string()], |row| {
            let id_str: String = row.get(0)?;
            let proj_str: String = row.get(1)?;
            let type_str: String = row.get(2)?;
            let pattern: String = row.get(3)?;
            let enabled_int: i32 = row.get(4)?;
            let created_str: String = row.get(5)?;

            let rule_type = match type_str.as_str() {
                "include_domain" => ScopeRuleType::IncludeDomain,
                "exclude_domain" => ScopeRuleType::ExcludeDomain,
                "include_path" => ScopeRuleType::IncludePath,
                "exclude_path" => ScopeRuleType::ExcludePath,
                "include_port" => ScopeRuleType::IncludePort,
                "exclude_port" => ScopeRuleType::ExcludePort,
                _ => ScopeRuleType::Protocol,
            };

            Ok(ScopeRule {
                id: Uuid::parse_str(&id_str).unwrap_or_default(),
                project_id: Uuid::parse_str(&proj_str).unwrap_or_default(),
                rule_type,
                pattern,
                enabled: enabled_int != 0,
                created_at: DateTime::parse_from_rfc3339(&created_str).map(|dt| dt.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now()),
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    // --- Scan Jobs CRUD ---

    pub fn insert_job(&self, job: &Job) -> Result<(), StorageError> {
        let conn = self.conn.lock().unwrap();
        let mod_str = serde_json::to_string(&job.module).unwrap_or_default().replace('\"', "");
        let status_str = serde_json::to_string(&job.status).unwrap_or_default().replace('\"', "");

        conn.execute(
            r#"INSERT INTO scan_jobs 
               (id, project_id, module, target, status, progress, current_step, requests_sent, max_requests, created_at, started_at, finished_at, error_message)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)"#,
            params![
                job.id.to_string(),
                job.project_id.to_string(),
                mod_str,
                job.target,
                status_str,
                job.progress,
                job.current_step,
                job.requests_sent,
                job.max_requests,
                job.created_at.to_rfc3339(),
                job.started_at.map(|d| d.to_rfc3339()),
                job.finished_at.map(|d| d.to_rfc3339()),
                job.error_message,
            ],
        )?;
        Ok(())
    }

    pub fn get_jobs(&self, project_id: Uuid) -> Result<Vec<Job>, StorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, project_id, module, target, status, progress, current_step, requests_sent, max_requests, created_at, started_at, finished_at, error_message
               FROM scan_jobs WHERE project_id = ?1 ORDER BY created_at DESC"#
        )?;
        let rows = stmt.query_map(params![project_id.to_string()], |row| {
            let id_str: String = row.get(0)?;
            let proj_str: String = row.get(1)?;
            let mod_str: String = row.get(2)?;
            let target: String = row.get(3)?;
            let status_str: String = row.get(4)?;
            let progress: f64 = row.get(5)?;
            let current_step: String = row.get(6)?;
            let requests_sent: u64 = row.get(7)?;
            let max_requests: u64 = row.get(8)?;
            let created_str: String = row.get(9)?;
            let started_str: Option<String> = row.get(10)?;
            let finished_str: Option<String> = row.get(11)?;
            let error_msg: Option<String> = row.get(12)?;

            let module = match mod_str.as_str() {
                "dns" => ModuleType::Dns,
                "recon" => ModuleType::Recon,
                "http_probe" => ModuleType::HttpProbe,
                "crawler" => ModuleType::Crawler,
                "sql_injection" => ModuleType::SqlInjection,
                "technology" => ModuleType::Technology,
                _ => ModuleType::Custom,
            };

            let status = match status_str.as_str() {
                "RUNNING" => JobStatus::Running,
                "PAUSED" => JobStatus::Paused,
                "CANCELLED" => JobStatus::Cancelled,
                "FAILED" => JobStatus::Failed,
                "COMPLETED" => JobStatus::Completed,
                _ => JobStatus::Queued,
            };

            Ok(Job {
                id: Uuid::parse_str(&id_str).unwrap_or_default(),
                project_id: Uuid::parse_str(&proj_str).unwrap_or_default(),
                module,
                target,
                status,
                progress: progress as f32,
                current_step,
                requests_sent,
                max_requests,
                created_at: DateTime::parse_from_rfc3339(&created_str).map(|dt| dt.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now()),
                started_at: started_str.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
                finished_at: finished_str.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
                error_message: error_msg,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    // --- Findings CRUD ---

    pub fn insert_finding(&self, finding: &Finding) -> Result<(), StorageError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"INSERT INTO findings
               (id, project_id, title, severity, confidence, status, target, endpoint, parameter, module, technique, dbms_hypothesis, notes, created_at, updated_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)"#,
            params![
                finding.id.to_string(),
                finding.project_id.to_string(),
                finding.title,
                format!("{:?}", finding.severity).to_uppercase(),
                format!("{:?}", finding.confidence).to_uppercase(),
                format!("{:?}", finding.status).to_uppercase(),
                finding.target,
                finding.endpoint,
                finding.parameter,
                finding.module,
                finding.technique,
                finding.dbms_hypothesis,
                finding.notes,
                finding.created_at.to_rfc3339(),
                finding.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn get_findings(&self, project_id: Uuid) -> Result<Vec<Finding>, StorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, project_id, title, severity, confidence, status, target, endpoint, parameter, module, technique, dbms_hypothesis, notes, created_at, updated_at
               FROM findings WHERE project_id = ?1 ORDER BY created_at DESC"#
        )?;
        let rows = stmt.query_map(params![project_id.to_string()], |row| {
            let id_str: String = row.get(0)?;
            let proj_str: String = row.get(1)?;
            let title: String = row.get(2)?;
            let sev_str: String = row.get(3)?;
            let conf_str: String = row.get(4)?;
            let stat_str: String = row.get(5)?;
            let target: String = row.get(6)?;
            let endpoint: String = row.get(7)?;
            let parameter: Option<String> = row.get(8)?;
            let module: String = row.get(9)?;
            let technique: String = row.get(10)?;
            let dbms_hypothesis: Option<String> = row.get(11)?;
            let notes: Option<String> = row.get(12)?;
            let created_str: String = row.get(13)?;
            let updated_str: String = row.get(14)?;

            let severity = match sev_str.as_str() {
                "LOW" => Severity::Low,
                "MEDIUM" => Severity::Medium,
                "HIGH" => Severity::High,
                "CRITICAL" => Severity::Critical,
                _ => Severity::Info,
            };

            let confidence = match conf_str.as_str() {
                "LOW" => Confidence::Low,
                "MEDIUM" => Confidence::Medium,
                "HIGH" => Confidence::High,
                "VERYHIGH" | "VERY_HIGH" => Confidence::VeryHigh,
                _ => Confidence::Info,
            };

            let status = match stat_str.as_str() {
                "NEEDSREVIEW" | "NEEDS_REVIEW" => FindingStatus::NeedsReview,
                "VERIFIED" => FindingStatus::Verified,
                "REJECTED" => FindingStatus::Rejected,
                "DUPLICATE" => FindingStatus::Duplicate,
                "REPORTED" => FindingStatus::Reported,
                "RESOLVED" => FindingStatus::Resolved,
                _ => FindingStatus::Candidate,
            };

            Ok(Finding {
                id: Uuid::parse_str(&id_str).unwrap_or_default(),
                project_id: Uuid::parse_str(&proj_str).unwrap_or_default(),
                title,
                severity,
                confidence,
                status,
                target,
                endpoint,
                parameter,
                module,
                technique,
                dbms_hypothesis,
                notes,
                created_at: DateTime::parse_from_rfc3339(&created_str).map(|dt| dt.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now()),
                updated_at: DateTime::parse_from_rfc3339(&updated_str).map(|dt| dt.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now()),
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_project_and_scope_crud() {
        let db = Database::open_in_memory().unwrap();
        let project = Project::new("Bug Bounty Target Alpha", "Testing bug bounty targets");
        db.insert_project(&project).unwrap();

        let projects = db.get_projects().unwrap();
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].name, "Bug Bounty Target Alpha");

        let rule = ScopeRule::new(project.id, ScopeRuleType::IncludeDomain, "*.alpha.corp");
        db.insert_scope_rule(&rule).unwrap();

        let rules = db.get_scope_rules(project.id).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].pattern, "*.alpha.corp");
    }
}
