import { Finding, Job, Project, ScopeEvaluation, ScopeRule, TrafficEntry, TrafficPage, FuzzRunSummary } from '../types';

declare global {
  interface Window {
    __TAURI_INTERNALS__?: unknown;
  }
}

const isTauri = () => typeof window !== 'undefined' && Boolean(window.__TAURI_INTERNALS__);

// Mock store for browser preview / development
const mockProjects: Project[] = [
  {
    id: 'p-001',
    name: 'BugCrowd Target Alpha',
    description: 'Bounty research target for authorized scope',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    active: true,
  }
];

let activeProjId: string | null = 'p-001';

const mockScopeRules: ScopeRule[] = [
  {
    id: 's-001',
    project_id: 'p-001',
    rule_type: 'include_domain',
    pattern: '*.targetalpha.com',
    enabled: true,
    created_at: new Date().toISOString(),
  },
  {
    id: 's-002',
    project_id: 'p-001',
    rule_type: 'exclude_domain',
    pattern: 'admin.targetalpha.com',
    enabled: true,
    created_at: new Date().toISOString(),
  },
  {
    id: 's-003',
    project_id: 'p-001',
    rule_type: 'exclude_path',
    pattern: '/logout',
    enabled: true,
    created_at: new Date().toISOString(),
  }
];

const mockJobs: Job[] = [
  {
    id: 'j-001',
    project_id: 'p-001',
    module: 'sql_injection',
    target: 'https://api.targetalpha.com/v1/search',
    status: 'RUNNING',
    progress: 67,
    current_step: 'Differential response baseline testing...',
    requests_sent: 201,
    max_requests: 500,
    created_at: new Date().toISOString(),
    started_at: new Date().toISOString(),
    finished_at: null,
    error_message: null,
  },
  {
    id: 'j-002',
    project_id: 'p-001',
    module: 'recon',
    target: 'https://targetalpha.com',
    status: 'COMPLETED',
    progress: 100,
    current_step: 'Completed host and port inventory',
    requests_sent: 84,
    max_requests: 200,
    created_at: new Date(Date.now() - 3600000).toISOString(),
    started_at: new Date(Date.now() - 3600000).toISOString(),
    finished_at: new Date(Date.now() - 3400000).toISOString(),
    error_message: null,
  }
];

const mockFindings: Finding[] = [
  {
    id: 'f-001',
    project_id: 'p-001',
    title: 'PostgreSQL Syntax Error Differential in Query Parameter `filter`',
    severity: 'HIGH',
    confidence: 'HIGH',
    status: 'NEEDS_REVIEW',
    target: 'https://api.targetalpha.com/v1/search',
    endpoint: '/v1/search',
    parameter: 'filter',
    module: 'SQL Research Engine',
    technique: 'differential-analysis',
    dbms_hypothesis: 'PostgreSQL',
    notes: 'Consistent 500 error triggered by unescaped single quote with pg_catalog dialect signature.',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  }
];

// Traffic mocks: one page of realistic entries + counters.
const mockTraffic: TrafficEntry[] = [
  {
    id: 't-1025',
    request: {
      id: 'r-1025',
      job_id: null,
      url: 'https://api.targetalpha.com/v1/admin/users/export?orgId=8942',
      method: 'POST',
      headers: { host: 'api.targetalpha.com', authorization: 'Bearer eyJ...' },
      body: '{"format":"csv"}',
      timestamp: new Date().toISOString(),
    },
    response: {
      id: 'resp-1025',
      request_id: 'r-1025',
      status_code: 403,
      headers: { 'content-type': 'application/problem+json' },
      body: '{"title":"Insufficient Administrative Privileges"}',
      size_bytes: 188,
      duration_ms: 32,
      timestamp: new Date().toISOString(),
    },
    captured_at: new Date().toISOString(),
    fingerprint: 'a1b2c3d4e5f60718',
    source: 'proxy',
  },
  {
    id: 't-1024',
    request: {
      id: 'r-1024',
      job_id: null,
      url: 'https://api.targetalpha.com/v1/auth/session/token',
      method: 'GET',
      headers: { host: 'api.targetalpha.com' },
      body: null,
      timestamp: new Date(Date.now() - 4000).toISOString(),
    },
    response: {
      id: 'resp-1024',
      request_id: 'r-1024',
      status_code: 200,
      headers: { 'content-type': 'application/json' },
      body: '{"token":"..."}',
      size_bytes: 1456,
      duration_ms: 14,
      timestamp: new Date(Date.now() - 4000).toISOString(),
    },
    captured_at: new Date(Date.now() - 4000).toISOString(),
    fingerprint: 'b2c3d4e5f60718a1',
    source: 'proxy',
  },
];

export const api = {
  async listProjects(): Promise<Project[]> {
    if (isTauri()) {
      const { invoke } = await import('@tauri-apps/api/core');
      return invoke('list_projects');
    }
    return mockProjects;
  },

  async createProject(name: string, description: string): Promise<Project> {
    if (isTauri()) {
      const { invoke } = await import('@tauri-apps/api/core');
      return invoke('create_project', { name, description });
    }
    const newProj: Project = {
      id: `p-${Date.now()}`,
      name,
      description,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      active: true,
    };
    mockProjects.push(newProj);
    activeProjId = newProj.id;
    return newProj;
  },

  async setActiveProject(projectId: string): Promise<void> {
    if (isTauri()) {
      const { invoke } = await import('@tauri-apps/api/core');
      return invoke('set_active_project', { projectId });
    }
    activeProjId = projectId;
  },

  async getActiveProject(): Promise<string | null> {
    if (isTauri()) {
      const { invoke } = await import('@tauri-apps/api/core');
      return invoke('get_active_project');
    }
    return activeProjId;
  },

  async getScopeRules(projectId: string): Promise<ScopeRule[]> {
    if (isTauri()) {
      const { invoke } = await import('@tauri-apps/api/core');
      return invoke('get_scope_rules', { projectId });
    }
    return mockScopeRules.filter(r => r.project_id === projectId);
  },

  async addScopeRule(projectId: string, ruleType: string, pattern: string): Promise<ScopeRule> {
    if (isTauri()) {
      const { invoke } = await import('@tauri-apps/api/core');
      return invoke('add_scope_rule', { projectId, ruleType, pattern });
    }
    const newRule: ScopeRule = {
      id: `s-${Date.now()}`,
      project_id: projectId,
      rule_type: ruleType as any,
      pattern,
      enabled: true,
      created_at: new Date().toISOString(),
    };
    mockScopeRules.push(newRule);
    return newRule;
  },

  async evaluateTarget(target: string): Promise<ScopeEvaluation> {
    if (isTauri()) {
      const { invoke } = await import('@tauri-apps/api/core');
      return invoke('evaluate_target', { target });
    }
    const lower = target.toLowerCase();
    if (lower.includes('admin.targetalpha.com') || lower.includes('/logout')) {
      return {
        target,
        allowed: false,
        matched_rule: 'Explicit exclusion',
        reason: 'Target is explicitly excluded by scope rules',
      };
    }
    if (lower.includes('targetalpha.com')) {
      return {
        target,
        allowed: true,
        matched_rule: '*.targetalpha.com',
        reason: 'Target is within approved program scope',
      };
    }
    return {
      target,
      allowed: false,
      matched_rule: null,
      reason: 'Target hostname is outside approved scope',
    };
  },

  async listJobs(projectId: string): Promise<Job[]> {
    if (isTauri()) {
      const { invoke } = await import('@tauri-apps/api/core');
      return invoke('list_jobs', { projectId });
    }
    return mockJobs.filter(j => j.project_id === projectId);
  },

  async startTestJob(projectId: string, target: string, module: string): Promise<Job> {
    if (isTauri()) {
      const { invoke } = await import('@tauri-apps/api/core');
      return invoke('start_test_job', { projectId, target, module });
    }
    const newJob: Job = {
      id: `j-${Date.now()}`,
      project_id: projectId,
      module: module as any,
      target,
      status: 'RUNNING',
      progress: 5,
      current_step: 'Resolving DNS and baseline target fingerprint...',
      requests_sent: 1,
      max_requests: 500,
      created_at: new Date().toISOString(),
      started_at: new Date().toISOString(),
      finished_at: null,
      error_message: null,
    };
    mockJobs.unshift(newJob);
    return newJob;
  },

  async cancelJob(jobId: string): Promise<boolean> {
    if (isTauri()) {
      const { invoke } = await import('@tauri-apps/api/core');
      return invoke('cancel_job', { jobId });
    }
    const j = mockJobs.find(x => x.id === jobId);
    if (j) {
      j.status = 'CANCELLED';
      return true;
    }
    return false;
  },

  async listFindings(projectId: string): Promise<Finding[]> {
    if (isTauri()) {
      const { invoke } = await import('@tauri-apps/api/core');
      return invoke('list_findings', { projectId });
    }
    return mockFindings.filter(f => f.project_id === projectId);
  },

  async createFinding(payload: {
    projectId: string;
    title: string;
    severity: string;
    confidence: string;
    target: string;
    endpoint: string;
    parameter?: string;
    module: string;
    technique: string;
    dbmsHypothesis?: string;
    notes?: string;
  }): Promise<Finding> {
    if (isTauri()) {
      const { invoke } = await import('@tauri-apps/api/core');
      return invoke('create_finding', {
        projectId: payload.projectId,
        title: payload.title,
        severity: payload.severity,
        confidence: payload.confidence,
        target: payload.target,
        endpoint: payload.endpoint,
        parameter: payload.parameter ?? null,
        module: payload.module,
        technique: payload.technique,
        dbmsHypothesis: payload.dbmsHypothesis ?? null,
        notes: payload.notes ?? null,
      });
    }
    const newFinding: Finding = {
      id: `f-${Date.now()}`,
      project_id: payload.projectId,
      title: payload.title,
      severity: payload.severity as any,
      confidence: payload.confidence as any,
      status: 'CANDIDATE',
      target: payload.target,
      endpoint: payload.endpoint,
      parameter: payload.parameter ?? null,
      module: payload.module,
      technique: payload.technique,
      dbms_hypothesis: payload.dbmsHypothesis ?? null,
      notes: payload.notes ?? null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    mockFindings.unshift(newFinding);
    return newFinding;
  },

  // ── Traffic / engine APIs (new) ─────────────────────────────────

  async getTrafficPage(offset: number, limit: number): Promise<TrafficPage> {
    if (isTauri()) {
      const { invoke } = await import('@tauri-apps/api/core');
      return invoke('get_traffic_page', { offset, limit });
    }
    const end = Math.max(0, mockTraffic.length - offset);
    const start = Math.max(0, end - limit);
    return {
      entries: mockTraffic.slice(start, end).reverse(),
      total: mockTraffic.length,
      evicted: 0,
    };
  },

  async getTrafficEntry(entryId: string): Promise<TrafficEntry | null> {
    if (isTauri()) {
      const { invoke } = await import('@tauri-apps/api/core');
      return invoke('get_traffic_entry', { entryId });
    }
    return mockTraffic.find(t => t.id === entryId) ?? null;
  },

  async clearTraffic(): Promise<boolean> {
    if (isTauri()) {
      const { invoke } = await import('@tauri-apps/api/core');
      return invoke('clear_traffic');
    }
    mockTraffic.length = 0;
    return true;
  },

  async sendRequest(payload: {
    url: string;
    method: string;
    headers?: Record<string, string>;
    body?: string;
  }): Promise<{ status_code: number; headers: Record<string, string>; body: string; size_bytes: number; duration_ms: number }> {
    if (isTauri()) {
      const { invoke } = await import('@tauri-apps/api/core');
      return invoke('send_request', {
        url: payload.url,
        method: payload.method,
        headers: payload.headers ?? null,
        body: payload.body ?? null,
      });
    }
    return {
      status_code: 200,
      headers: { 'content-type': 'application/json' },
      body: '{"mock": true}',
      size_bytes: 16,
      duration_ms: 12,
    };
  },

  async repeaterSend(payload: {
    baseEntryId: string;
    method?: string;
    url?: string;
    headerOverrides?: Record<string, string>;
    body?: string;
  }): Promise<{
    sent: { method: string; url: string; headers: Record<string, string>; body: string | null };
    response: { status_code: number; headers: Record<string, string>; body: string; size_bytes: number; duration_ms: number };
  }> {
    if (isTauri()) {
      const { invoke } = await import('@tauri-apps/api/core');
      return invoke('repeater_send', {
        baseEntryId: payload.baseEntryId,
        method: payload.method ?? null,
        url: payload.url ?? null,
        headerOverrides: payload.headerOverrides ?? null,
        body: payload.body ?? null,
      });
    }
    return {
      sent: {
        method: payload.method ?? 'GET',
        url: payload.url ?? 'https://api.targetalpha.com/v1/mock',
        headers: payload.headerOverrides ?? {},
        body: payload.body ?? null,
      },
      response: {
        status_code: 200,
        headers: {},
        body: '{"mock": true}',
        size_bytes: 16,
        duration_ms: 9,
      },
    };
  },

  async fuzzerRun(payload: {
    urlTemplate: string;
    method: string;
    headers?: Record<string, string>;
    body?: string;
    positions: Array<{ marker: string; payloads: string[] }>;
    maxCombos?: number;
    concurrency?: number;
  }): Promise<FuzzRunSummary> {
    if (isTauri()) {
      const { invoke } = await import('@tauri-apps/api/core');
      return invoke('fuzzer_run', {
        urlTemplate: payload.urlTemplate,
        method: payload.method,
        headers: payload.headers ?? null,
        body: payload.body ?? null,
        positions: payload.positions,
        maxCombos: payload.maxCombos ?? null,
        concurrency: payload.concurrency ?? null,
      });
    }
    const total = payload.positions.reduce((acc, p) => acc * Math.max(1, p.payloads.length), 1);
    return {
      total,
      completed: total,
      failed: 0,
      deduped: 0,
      results: payload.positions.flatMap(p =>
        p.payloads.slice(0, 3).map(v => ({
          replacements: { [p.marker]: v },
          status: 200,
          duration_ms: 10,
          size_bytes: 100,
          body_hash: `mock-${v.length}`,
        }))
      ),
    };
  },

  /** Subscribe to the backend event stream (traffic captures, job
   *  progress, findings). Returns an unlisten function. */
  async subscribeEvents(onEvent: (event: BugToolsEventPayload) => void): Promise<() => void> {
    if (isTauri()) {
      const { listen } = await import('@tauri-apps/api/event');
      const unlisten = await listen<BugToolsEventPayload>('bugtools-event', e => onEvent(e.payload));
      return unlisten;
    }
    // Browser preview: no backend events — return a no-op unlisten.
    return () => undefined;
  },
};

/** Shape of events emitted on the `bugtools-event` channel.
 *  Tagged-union mirrored from Rust's BugToolsEvent enum. */
export type BugToolsEventPayload =
  | { type: 'ProjectCreated'; payload: Project }
  | { type: 'ProjectUpdated'; payload: Project }
  | { type: 'JobCreated'; payload: Job }
  | { type: 'JobStarted'; payload: { job_id: string } }
  | { type: 'JobProgress'; payload: { job_id: string; progress: number; current_step: string } }
  | { type: 'JobPaused'; payload: { job_id: string } }
  | { type: 'JobCancelled'; payload: { job_id: string } }
  | { type: 'JobFailed'; payload: { job_id: string; error: string } }
  | { type: 'JobCompleted'; payload: { job_id: string } }
  | { type: 'ScopeChecked'; payload: ScopeEvaluation }
  | { type: 'TargetDiscovered'; payload: { project_id: string; url: string } }
  | { type: 'EndpointDiscovered'; payload: { project_id: string; host: string; path: string; method: string } }
  | { type: 'ParameterDiscovered'; payload: { project_id: string; endpoint: string; parameter: string } }
  | { type: 'FindingDiscovered'; payload: Finding }
  | { type: 'FindingUpdated'; payload: Finding }
  | {
      type: 'TrafficCaptured';
      payload: {
        entry_id: string;
        request_id: string;
        source: string;
        method: string;
        url: string;
        status_code: number | null;
        duration_ms: number | null;
        size_bytes: number | null;
        fingerprint: string;
        captured_at: string;
      };
    }
  | { type: 'RepeaterSent'; payload: { request_id: string; status_code: number; duration_ms: number } }
  | { type: 'FuzzerRunCompleted'; payload: { total: number; completed: number; failed: number; deduped: number } }
  | { type: 'TrafficDeduped'; payload: { fingerprint: string } }
  | { type: 'ScopeViolationBlocked'; payload: { url: string; reason: string } }
  | { type: 'AuditLog'; payload: { timestamp: string; level: string; component: string; message: string } };
