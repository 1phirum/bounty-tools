import React, { useEffect, useState } from 'react';
import { Routes, Route, useNavigate } from 'react-router-dom';
import { Sidebar } from '../components/Sidebar';
import { TopNav } from '../components/TopNav';
import { Dashboard } from '../pages/Dashboard/Dashboard';
import { Projects } from '../pages/Projects/Projects';
import { SqlPage } from '../pages/SQL/SqlPage';
import { Findings } from '../pages/Findings/Findings';
import { Recon } from '../pages/Recon/Recon';
import { HttpPage } from '../pages/HTTP/HttpPage';
import { Settings } from '../pages/Settings/Settings';
import { api } from '../api/tauri';
import { Finding, Job, Project, ScopeRule, ScopeRuleType } from '../types';

export const App: React.FC = () => {
  const navigate = useNavigate();
  const [projects, setProjects] = useState<Project[]>([]);
  const [activeProjectId, setActiveProjectId] = useState<string | null>(null);
  const [scopeRules, setScopeRules] = useState<ScopeRule[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);

  const loadData = async () => {
    try {
      const projs = await api.listProjects();
      setProjects(projs);
      if (projs.length > 0 && !activeProjectId) {
        setActiveProjectId(projs[0].id);
        const rules = await api.getScopeRules(projs[0].id);
        setScopeRules(rules);
        const j = await api.listJobs(projs[0].id);
        setJobs(j);
        const f = await api.listFindings(projs[0].id);
        setFindings(f);
      }
    } catch (err) {
      console.error('Failed to load initial data:', err);
    }
  };

  useEffect(() => {
    loadData();

    // Live event subscription from Rust controller & Go worker
    let unlistenFn: (() => void) | undefined;
    if (typeof window !== 'undefined' && Boolean((window as any).__TAURI_INTERNALS__)) {
      import('@tauri-apps/api/event').then(({ listen }) => {
        listen<any>('bugtools-event', (event) => {
          const payload = event.payload;
          if (!payload) return;

          if (payload.type === 'JobProgress') {
            const { job_id, progress, current_step } = payload.payload;
            setJobs((prev) =>
              prev.map((j) =>
                j.id === job_id
                  ? { ...j, status: 'RUNNING', progress, current_step }
                  : j
              )
            );
          } else if (payload.type === 'JobCompleted') {
            const { job_id } = payload.payload;
            setJobs((prev) =>
              prev.map((j) =>
                j.id === job_id
                  ? { ...j, status: 'COMPLETED', progress: 100, current_step: 'Completed' }
                  : j
              )
            );
            // Refresh findings on completion
            if (activeProjectId) {
              api.listFindings(activeProjectId).then(setFindings);
            }
          } else if (payload.type === 'JobFailed') {
            const { job_id, error } = payload.payload;
            setJobs((prev) =>
              prev.map((j) =>
                j.id === job_id
                  ? { ...j, status: 'FAILED', current_step: error || 'Job failed' }
                  : j
              )
            );
          } else if (payload.type === 'FindingDiscovered') {
            setFindings((prev) => [payload.payload, ...prev]);
          }
        }).then((unsub) => {
          unlistenFn = unsub;
        });
      });
    }

    return () => {
      if (unlistenFn) unlistenFn();
    };
  }, [activeProjectId]);

  const handleSelectProject = async (id: string) => {
    setActiveProjectId(id);
    await api.setActiveProject(id);
    const rules = await api.getScopeRules(id);
    setScopeRules(rules);
    const j = await api.listJobs(id);
    setJobs(j);
    const f = await api.listFindings(id);
    setFindings(f);
  };

  const handleCreateProject = async (name: string, description: string) => {
    const proj = await api.createProject(name, description);
    setProjects((prev) => [proj, ...prev]);
    await handleSelectProject(proj.id);
  };

  const handleAddScopeRule = async (ruleType: ScopeRuleType, pattern: string) => {
    if (!activeProjectId) return;
    const rule = await api.addScopeRule(activeProjectId, ruleType, pattern);
    setScopeRules((prev) => [rule, ...prev]);
  };

  const handleTriggerTestJob = async (target: string, module: string) => {
    if (!activeProjectId) return;
    try {
      const job = await api.startTestJob(activeProjectId, target, module);
      setJobs((prev) => [job, ...prev]);

      // If running in browser mode (fallback), simulate progress
      if (typeof window !== 'undefined' && !(window as any).__TAURI_INTERNALS__) {
        let pct = 10;
        const interval = setInterval(() => {
          pct += 25;
          if (pct >= 100) {
            clearInterval(interval);
            setJobs((prev) =>
              prev.map((j) =>
                j.id === job.id
                  ? { ...j, status: 'COMPLETED', progress: 100, current_step: 'Completed scan operations.' }
                  : j
              )
            );
          } else {
            setJobs((prev) =>
              prev.map((j) =>
                j.id === job.id
                  ? { ...j, progress: pct, current_step: `Scanning step ${pct}% verified...` }
                  : j
              )
            );
          }
        }, 700);
      }
    } catch (err: any) {
      alert(`Scope violation: ${err}`);
    }
  };

  const handleCancelJob = async (jobId: string) => {
    await api.cancelJob(jobId);
    setJobs((prev) =>
      prev.map((j) => (j.id === jobId ? { ...j, status: 'CANCELLED' } : j))
    );
  };

  const activeProject = projects.find((p) => p.id === activeProjectId) || null;

  return (
    <div className="flex h-screen w-screen bg-[#0a0d13] text-slate-100 select-none overflow-hidden font-sans">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopNav
          projects={projects}
          activeProject={activeProject}
          onSelectProject={handleSelectProject}
        />

        <main className="flex-1 overflow-y-auto p-6 bg-radial-gradient">
          <Routes>
            <Route
              path="/"
              element={
                <Dashboard
                  jobs={jobs}
                  findings={findings}
                  onTriggerTestJob={handleTriggerTestJob}
                  onCancelJob={handleCancelJob}
                  onRefresh={loadData}
                />
              }
            />
            <Route
              path="/projects"
              element={
                <Projects
                  projects={projects}
                  activeProjectId={activeProjectId}
                  onSelectProject={handleSelectProject}
                  onCreateProject={handleCreateProject}
                />
              }
            />
            <Route path="/sql" element={<SqlPage activeProjectId={activeProjectId} onTriggerTestJob={handleTriggerTestJob} />} />
            <Route path="/findings" element={<Findings findings={findings} />} />
            <Route path="/recon" element={<Recon />} />
            <Route path="/http" element={<HttpPage />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<Dashboard jobs={jobs} findings={findings} onTriggerTestJob={handleTriggerTestJob} onCancelJob={handleCancelJob} onRefresh={loadData} />} />
          </Routes>
        </main>
      </div>
    </div>
  );
};
