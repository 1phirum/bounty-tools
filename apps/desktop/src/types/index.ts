export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type Confidence = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'VERY_HIGH';
export type FindingStatus = 'CANDIDATE' | 'NEEDS_REVIEW' | 'VERIFIED' | 'REJECTED' | 'DUPLICATE' | 'REPORTED' | 'RESOLVED';

export type ScopeRuleType =
  | 'include_domain'
  | 'exclude_domain'
  | 'include_path'
  | 'exclude_path'
  | 'include_port'
  | 'exclude_port'
  | 'protocol';

export interface Project {
  id: string;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
  active: boolean;
}

export interface ScopeRule {
  id: string;
  project_id: string;
  rule_type: ScopeRuleType;
  pattern: string;
  enabled: boolean;
  created_at: string;
}

export interface ScopeEvaluation {
  target: string;
  allowed: boolean;
  matched_rule: string | null;
  reason: string;
}

export type JobStatus = 'QUEUED' | 'RUNNING' | 'PAUSED' | 'CANCELLED' | 'FAILED' | 'COMPLETED';

export type ModuleType =
  | 'dns'
  | 'recon'
  | 'http_probe'
  | 'crawler'
  | 'sql_injection'
  | 'technology'
  | 'custom';

export interface Job {
  id: string;
  project_id: string;
  module: ModuleType;
  target: string;
  status: JobStatus;
  progress: number;
  current_step: string;
  requests_sent: number;
  max_requests: number;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  error_message: string | null;
}

export interface Finding {
  id: string;
  project_id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  status: FindingStatus;
  target: string;
  endpoint: string;
  parameter: string | null;
  module: string;
  technique: string;
  dbms_hypothesis: string | null;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

// ── Traffic types (new) ───────────────────────────────────────────

/** Origin of a captured exchange. */
export type TrafficSource = 'proxy' | 'repeater' | 'fuzzer';

export interface TrafficHttpRequest {
  id: string;
  job_id: string | null;
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string | null;
  timestamp: string;
}

export interface TrafficHttpResponse {
  id: string;
  request_id: string;
  status_code: number;
  headers: Record<string, string>;
  body: string;
  size_bytes: number;
  duration_ms: number;
  timestamp: string;
}

export interface TrafficEntry {
  id: string;
  request: TrafficHttpRequest;
  response: TrafficHttpResponse | null;
  captured_at: string;
  fingerprint: string;
  source: TrafficSource;
}

export interface TrafficPage {
  entries: TrafficEntry[];
  total: number;
  evicted: number;
}

// ── Fuzzer types (new) ────────────────────────────────────────────

export interface FuzzIterationResult {
  replacements: Record<string, string>;
  status: number;
  duration_ms: number;
  size_bytes: number;
  body_hash: string;
}

export interface FuzzRunSummary {
  total: number;
  completed: number;
  failed: number;
  deduped: number;
  results: FuzzIterationResult[];
}

export interface SystemInfo {
  cpu_name: string;
  cpu_cores: number;
  cpu_usage_percent: number;
  ram_total_mb: number;
  ram_used_mb: number;
  ram_usage_percent: number;
  datetime: string;
}

export interface Settings {
  max_requests_per_second: number;
  max_worker_concurrency: number;
  max_requests_per_job: number;
}
