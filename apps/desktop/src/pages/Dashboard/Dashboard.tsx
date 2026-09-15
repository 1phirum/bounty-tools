import React, { useState } from 'react';
import {
  Globe,
  Server,
  Link,
  ShieldAlert,
  Play,
  RotateCw,
  XCircle,
  Clock,
  ArrowUpRight,
  CheckCircle2,
  ChevronDown
} from 'lucide-react';
import { Finding, Job } from '../../types';

interface DashboardProps {
  jobs: Job[];
  findings: Finding[];
  onTriggerTestJob: (target: string, module: string) => void;
  onCancelJob: (jobId: string) => void;
  onRefresh: () => void;
}

export const Dashboard: React.FC<DashboardProps> = ({
  jobs,
  findings,
  onTriggerTestJob,
  onCancelJob,
  onRefresh,
}) => {
  const [quickTarget, setQuickTarget] = useState('https://api.targetalpha.com/v1/search');
  const [quickModule, setQuickModule] = useState('sql_injection');
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);

  const MODULE_OPTIONS = [
    { value: "sql_injection", label: "SQL Research Engine (Differential)" },
    { value: "recon", label: "Recon Worker (Go DNS & Host)" },
    { value: "http_probe", label: "HTTP Probing & Fingerprint" },
    { value: "crawler", label: "Scope-bounded Crawler" }
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-extrabold text-white tracking-tight">Workstation Overview</h2>
          <p className="text-xs font-mono text-slate-400 mt-1">
            Real-time telemetry, active scan jobs, and discovered bounty evidence.
          </p>
        </div>
        <button
          onClick={onRefresh}
          className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-[#161d2d] border border-[#2c3850] text-slate-300 hover:text-white text-xs font-semibold hover:border-slate-500 transition"
        >
          <RotateCw className="w-3.5 h-3.5" />
          <span>Refresh State</span>
        </button>
      </div>

      {/* Metrics Row (Architecture Section 33) */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-5 rounded-xl bg-[#111622] border border-[#1e2638] relative overflow-hidden group hover:border-slate-500/40 transition">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">Domains</span>
            <Globe className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-3xl font-mono font-bold text-white mt-2">0</div>
          <div className="text-[11px] font-mono text-emerald-400 mt-1 flex items-center gap-1">
            <span>+14 newly resolved</span>
          </div>
        </div>

        <div className="p-5 rounded-xl bg-[#111622] border border-[#1e2638] relative overflow-hidden group hover:border-slate-500/40 transition">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">Hosts</span>
            <Server className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-3xl font-mono font-bold text-white mt-2">0</div>
          <div className="text-[11px] font-mono text-slate-400 mt-1">Live HTTP services</div>
        </div>

        <div className="p-5 rounded-xl bg-[#111622] border border-[#1e2638] relative overflow-hidden group hover:border-slate-500/40 transition">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">URLs & Endpoints</span>
            <Link className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-3xl font-mono font-bold text-white mt-2">0</div>
          <div className="text-[11px] font-mono text-slate-400 mt-1">Normalized inventory</div>
        </div>

        <div className="p-5 rounded-xl bg-[#111622] border border-[#1e2638] relative overflow-hidden group hover:border-slate-500/40 transition">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">Candidates</span>
            <ShieldAlert className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-3xl font-mono font-bold text-amber-400 mt-2">{findings.length}</div>
          <div className="text-[11px] font-mono text-amber-400/80 mt-1">Requires researcher verification</div>
        </div>
      </div>

      {/* Main Grid: Scan Jobs + Launcher */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Active Scan Jobs (2 columns) */}
        <div className="lg:col-span-2 space-y-4">
          <div className="p-5 rounded-xl bg-[#111622] border border-[#1e2638] shadow-xl">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-bold font-mono uppercase tracking-wider text-slate-200 flex items-center gap-2">
                <Clock className="w-4 h-4 text-cyan-400" />
                Active Scan Pipeline
              </h3>
              <span className="text-xs font-mono text-slate-400">
                {jobs.filter((j) => j.status === 'RUNNING').length} running
              </span>
            </div>

            {jobs.length === 0 ? (
              <div className="p-8 text-center text-slate-500 font-mono text-xs border border-dashed border-[#1e2638] rounded-lg">
                No active jobs. Launch a test scan using the control panel on the right.
              </div>
            ) : (
              <div className="space-y-3">
                {jobs.map((job) => (
                  <div
                    key={job.id}
                    className="p-4 rounded-lg bg-[#161d2d] border border-[#2c3850] space-y-2.5"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span
                          className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase border ${
                            job.status === 'RUNNING'
                              ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
                              : job.status === 'COMPLETED'
                              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                              : 'bg-slate-700/30 text-slate-400 border-slate-600'
                          }`}
                        >
                          {job.status}
                        </span>
                        <span className="text-xs font-mono font-bold text-white uppercase">{job.module}</span>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="text-xs font-mono text-cyan-400 font-bold">{Math.round(job.progress)}%</span>
                        {job.status === 'RUNNING' && (
                          <button
                            onClick={() => onCancelJob(job.id)}
                            className="text-slate-400 hover:text-red-400 transition"
                            title="Cancel Job"
                          >
                            <XCircle className="w-4 h-4" />
                          </button>
                        )}
                      </div>
                    </div>

                    <div className="text-xs font-mono text-slate-300 truncate">{job.target}</div>

                    {/* Progress Bar */}
                    <div className="w-full h-2 rounded-full bg-black/40 overflow-hidden border border-black/50">
                      <div
                        className={`h-full transition-all duration-300 ${
                          job.status === 'COMPLETED'
                            ? 'bg-emerald-400'
                            : 'bg-gradient-to-r from-cyan-400 to-blue-500'
                        }`}
                        style={{ width: `${job.progress}%` }}
                      ></div>
                    </div>

                    <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                      <span className="truncate">{job.current_step}</span>
                      <span className="shrink-0">{job.requests_sent} / {job.max_requests} req</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Phase 4 Verification Job Launcher */}
        <div className="space-y-4">
          <div className="p-5 rounded-xl bg-[#111622] border border-[#1e2638] shadow-xl space-y-4">
            <div>
              <h3 className="text-sm font-bold font-mono uppercase tracking-wider text-slate-200 flex items-center gap-2">
                <Play className="w-4 h-4 text-emerald-400" />
                Launch Scan Job
              </h3>
              <p className="text-xs text-slate-400 mt-1 font-mono">
                Passes through rate limiter before execution.
              </p>
            </div>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Target URL / Host</label>
                <input
                  type="text"
                  value={quickTarget}
                  onChange={(e) => setQuickTarget(e.target.value)}
                  className="w-full bg-[#0a0d13] border border-[#1e2638] focus:border-cyan-400 rounded-lg px-3 py-2 text-xs font-mono text-white outline-none"
                  placeholder="https://example.com"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Scanner Engine Module</label>
                <div className="relative">
                  <div
                    onClick={() => setIsDropdownOpen(!isDropdownOpen)}
                    className="w-full bg-[#0a0d13] border border-[#1e2638] hover:border-cyan-400 rounded-lg px-3 py-2 text-xs font-mono text-white cursor-pointer flex items-center justify-between transition-colors"
                  >
                    <span>{MODULE_OPTIONS.find(m => m.value === quickModule)?.label}</span>
                    <ChevronDown className="w-4 h-4 text-slate-400" />
                  </div>
                  
                  {isDropdownOpen && (
                    <>
                      <div 
                        className="fixed inset-0 z-40" 
                        onClick={() => setIsDropdownOpen(false)}
                      />
                      <div className="absolute z-50 top-full left-0 right-0 mt-1 bg-[#0a0d13] border border-[#1e2638] rounded-lg shadow-xl overflow-hidden py-1">
                        {MODULE_OPTIONS.map((opt) => (
                          <div
                            key={opt.value}
                            onClick={() => {
                              setQuickModule(opt.value);
                              setIsDropdownOpen(false);
                            }}
                            className={`px-3 py-2 text-xs font-mono cursor-pointer hover:bg-[#1a2540] transition-colors ${
                              quickModule === opt.value ? 'text-cyan-400 font-bold bg-[#1a2540]/50' : 'text-slate-300'
                            }`}
                          >
                            {opt.label}
                          </div>
                        ))}
                      </div>
                    </>
                  )}
                </div>
              </div>

              <div className="p-3 rounded-lg bg-black/30 border border-[#1e2638] text-[11px] font-mono text-slate-400 space-y-1">

                <div className="flex justify-between">
                  <span>Max Requests:</span>
                  <span className="text-white">500</span>
                </div>
                <div className="flex justify-between">
                  <span>Rate Limit:</span>
                  <span className="text-white">5.0 req/s</span>
                </div>
              </div>

              <button
                onClick={() => onTriggerTestJob(quickTarget, quickModule)}
                className="w-full py-2 px-4 rounded bg-cyan-500 hover:bg-cyan-400 active:bg-cyan-600 text-slate-950 font-bold text-xs uppercase tracking-wider flex items-center justify-center gap-2 cursor-pointer font-mono"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Start Verified Job</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Discovered Candidates Table */}
      <div className="p-4 rounded-lg bg-[#0e1526] border border-[#1a2540]">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-300 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-amber-400" />
            <span>Recent Security Candidates & Evidence</span>
          </h3>
          <span className="text-[11px] font-mono text-slate-500">Non-destructive evidence</span>
        </div>

        <div className="rounded border border-[#1a2540] overflow-hidden bg-[#090d16]">
          <table className="w-full text-left text-xs font-mono border-collapse">
            <thead>
              <tr className="bg-[#0b1222] border-b border-[#1a2540] text-slate-400 text-[10.5px] uppercase tracking-wider">
                <th className="py-2 px-3 border-r border-[#1a2540] font-semibold w-24">Severity</th>
                <th className="py-2 px-3 border-r border-[#1a2540] font-semibold">Finding Title</th>
                <th className="py-2 px-3 border-r border-[#1a2540] font-semibold">Target & Parameter</th>
                <th className="py-2 px-3 border-r border-[#1a2540] font-semibold w-32">Module</th>
                <th className="py-2 px-3 border-r border-[#1a2540] font-semibold w-32">Status</th>
                <th className="py-2 px-3 font-semibold w-20 text-center">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1a2540] text-[11.5px]">
              {findings.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500 font-mono text-xs">
                    No candidates found. Trigger a verified job to discover evidence.
                  </td>
                </tr>
              ) : (
                findings.map((f) => (
                  <tr key={f.id} className="hover:bg-[#121c32]">
                    <td className="py-2 px-3 border-r border-[#1a2540]">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                          f.severity === 'CRITICAL'
                            ? 'bg-red-500/10 text-red-400 border-red-500/30'
                            : f.severity === 'HIGH'
                            ? 'bg-orange-500/10 text-orange-400 border-orange-500/30'
                            : f.severity === 'MEDIUM'
                            ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                            : 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
                        }`}
                      >
                        {f.severity}
                      </span>
                    </td>
                    <td className="py-2 px-3 font-semibold text-white border-r border-[#1a2540]">{f.title}</td>
                    <td className="py-2 px-3 text-slate-300 border-r border-[#1a2540]">
                      <div>{f.endpoint}</div>
                      {f.parameter && <span className="text-cyan-400 text-[10px]">param: {f.parameter}</span>}
                    </td>
                    <td className="py-2 px-3 text-slate-400 border-r border-[#1a2540]">{f.module}</td>
                    <td className="py-2 px-3 border-r border-[#1a2540]">
                      <span className="flex items-center gap-1.5 text-amber-400 text-[11px]">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>{f.status}</span>
                      </span>
                    </td>
                    <td className="py-2 px-3 text-center">
                      <button className="text-cyan-400 hover:text-cyan-300 text-[11px] inline-flex items-center gap-1 cursor-pointer">
                        <span>Inspect</span>
                        <ArrowUpRight className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
