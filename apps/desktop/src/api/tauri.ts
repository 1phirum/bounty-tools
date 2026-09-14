import { Finding, Job, Project, ScopeEvaluation, ScopeRule } from '../types';

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
  }
};
