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
