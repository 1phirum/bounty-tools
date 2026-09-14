import React, { useState } from 'react';
import { FolderKanban, Plus, Check, Clock, ShieldCheck } from 'lucide-react';
import { Project } from '../../types';

interface ProjectsProps {
  projects: Project[];
  activeProjectId: string | null;
  onSelectProject: (id: string) => void;
  onCreateProject: (name: string, description: string) => Promise<void>;
}

export const Projects: React.FC<ProjectsProps> = ({
  projects,
  activeProjectId,
  onSelectProject,
  onCreateProject,
}) => {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [creating, setCreating] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setCreating(true);
    try {
      await onCreateProject(name.trim(), description.trim());
      setName('');
      setDescription('');
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-3">
          <FolderKanban className="w-7 h-7 text-cyan-400" />
          Project Management
        </h2>
        <p className="text-xs font-mono text-slate-400 mt-1">
          Every scan, scope rule, request baseline, and finding is isolated within a project domain.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Project List */}
        <div className="lg:col-span-2 space-y-3">
          {projects.map((proj) => {
            const isActive = proj.id === activeProjectId;
            return (
              <div
                key={proj.id}
                className={`p-5 rounded-xl border transition cursor-pointer flex items-center justify-between ${
                  isActive
                    ? 'bg-[#161d2d] border-cyan-500/40 shadow-[0_0_20px_rgba(0,229,255,0.08)]'
                    : 'bg-[#111622] border-[#1e2638] hover:border-slate-600'
                }`}
                onClick={() => onSelectProject(proj.id)}
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-bold text-white font-mono">{proj.name}</h3>
                    {isActive && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                        ACTIVE
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-400">{proj.description}</p>
                  <div className="flex items-center gap-4 text-[11px] font-mono text-slate-500 pt-2">
                    <span className="flex items-center gap-1">
                      <Clock className="w-3.5 h-3.5" />
                      {new Date(proj.created_at).toLocaleDateString()}
                    </span>
                    <span className="flex items-center gap-1 text-emerald-400">
                      <ShieldCheck className="w-3.5 h-3.5" />
                      Scope Configured
                    </span>
                  </div>
                </div>

                <div>
                  <button
                    className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition ${
                      isActive
                        ? 'bg-cyan-500 text-slate-950'
                        : 'bg-[#1c2538] text-slate-300 hover:text-white'
                    }`}
                  >
                    {isActive ? 'Current' : 'Activate'}
                  </button>
                </div>
              </div>
            );
          })}
        </div>

        {/* New Project Form */}
        <div className="p-5 rounded-xl bg-[#111622] border border-[#1e2638] shadow-xl space-y-4">
          <div className="flex items-center gap-2">
            <Plus className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold font-mono uppercase tracking-wider text-slate-200">
              Create New Program / Target
            </h3>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">Program Name</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. HackerOne - Acme Corp"
                className="w-full bg-[#0a0d13] border border-[#1e2638] focus:border-cyan-400 rounded-lg px-3 py-2 text-xs font-mono text-white outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">Description / Notes</label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={3}
                placeholder="Authorized testing program details & policy limits..."
                className="w-full bg-[#0a0d13] border border-[#1e2638] focus:border-cyan-400 rounded-lg px-3 py-2 text-xs font-mono text-white outline-none resize-none"
              />
            </div>

            <button
              type="submit"
              disabled={creating || !name.trim()}
              className="w-full py-2.5 px-4 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono uppercase tracking-wider flex items-center justify-center gap-2 transition cursor-pointer"
            >
              <Check className="w-4 h-4" />
              <span>{creating ? 'Creating...' : 'Initialize Project'}</span>
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
