import React from 'react';
import { ShieldCheck, Zap, Activity, FolderKanban, ChevronDown } from 'lucide-react';
import { Project } from '../types';

interface TopNavProps {
  projects: Project[];
  activeProject: Project | null;
  onSelectProject: (id: string) => void;
  onOpenScopeModal?: () => void;
}

export const TopNav: React.FC<TopNavProps> = ({
  projects,
  activeProject,
  onSelectProject,
  onOpenScopeModal,
}) => {
  return (
    <header className="h-16 border-b border-[#1e2638] bg-[#111622]/80 backdrop-blur-md px-6 flex items-center justify-between select-none">
      {/* Left: Active Project Selector */}
      <div className="flex items-center gap-4">
        <div className="relative group">
          <div className="flex items-center gap-2.5 px-3.5 py-1.5 rounded-lg bg-[#161d2d] border border-[#2c3850] text-white text-sm font-semibold hover:border-cyan-500/50 cursor-pointer transition">
            <FolderKanban className="w-4 h-4 text-cyan-400" />
            <span>{activeProject ? activeProject.name : 'Select Project'}</span>
            <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
          </div>

          <div className="absolute left-0 mt-1 w-64 bg-[#161d2d] border border-[#2c3850] rounded-lg shadow-2xl py-1 hidden group-hover:block z-50">
            <div className="px-3 py-1.5 text-[11px] font-mono text-slate-400 border-b border-[#2c3850]">
              Select Active Workspace
            </div>
            {projects.map((p) => (
              <button
                key={p.id}
                onClick={() => onSelectProject(p.id)}
                className={`w-full text-left px-3 py-2 text-xs flex items-center justify-between hover:bg-[#1c2538] ${
                  activeProject?.id === p.id ? 'text-cyan-400 font-bold' : 'text-slate-300'
                }`}
              >
                <span>{p.name}</span>
                {activeProject?.id === p.id && (
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                )}
              </button>
            ))}
          </div>
        </div>

        <div className="h-5 w-[1px] bg-[#1e2638]"></div>

        {/* Scope Enforced Badge */}
        <button
          onClick={onOpenScopeModal}
          className="flex items-center gap-2 px-3 py-1 rounded-full text-xs font-mono font-semibold bg-emerald-950/60 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-900/40 cursor-pointer"
        >
          <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>SCOPE ENFORCED (RULE 2)</span>
        </button>
      </div>

      {/* Right: Telemetry & Limits */}
      <div className="flex items-center gap-4 text-xs font-mono">
        <div className="flex items-center gap-2 text-slate-400 bg-black/30 px-3 py-1.5 rounded-md border border-[#1e2638]">
          <Activity className="w-3.5 h-3.5 text-cyan-400" />
          <span>Rate: <strong className="text-white">5.0 req/s</strong></span>
          <span className="text-slate-600">|</span>
          <span>Workers: <strong className="text-white">4</strong></span>
          <span className="text-slate-600">|</span>
          <span>Budget: <strong className="text-white">720 / 1000</strong></span>
        </div>

        <div className="flex items-center gap-2 text-slate-400 bg-black/30 px-3 py-1.5 rounded-md border border-[#1e2638]">
          <Zap className="w-3.5 h-3.5 text-amber-400" />
          <span>Proxy: <strong className="text-slate-300">Direct</strong></span>
        </div>
      </div>
    </header>
  );
};
