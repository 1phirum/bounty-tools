import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  FolderKanban,
  ShieldCheck,
  Radar,
  Globe,
  Link2,
  FileCode2,
  DatabaseZap,
  AlertTriangle,
  FileText,
  Settings,
  Terminal,
  Cpu
} from 'lucide-react';

export const Sidebar: React.FC = () => {
  const navItems = [
    { to: '/', label: 'Dashboard', icon: LayoutDashboard },
    { to: '/projects', label: 'Projects', icon: FolderKanban },
    { to: '/scope', label: 'Scope Rules', icon: ShieldCheck },
    { to: '/recon', label: 'Recon & DNS', icon: Radar },
    { to: '/http', label: 'HTTP History', icon: Globe },
    { to: '/urls', label: 'Endpoints', icon: Link2 },
    { to: '/js', label: 'JavaScript', icon: FileCode2 },
    { to: '/sql', label: 'SQL Research', icon: DatabaseZap },
    { to: '/findings', label: 'Findings', icon: AlertTriangle },
    { to: '/reports', label: 'Reports', icon: FileText },
    { to: '/settings', label: 'Settings', icon: Settings },
  ];

  return (
    <aside className="w-64 min-w-64 h-screen bg-[#111622] border-r border-[#1e2638] flex flex-col select-none">
      {/* Brand Header */}
      <div className="p-5 flex items-center gap-3 border-b border-[#1e2638]">
        <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-400 to-blue-600 flex items-center justify-center text-black font-extrabold shadow-[0_0_15px_rgba(0,229,255,0.35)]">
          <Terminal className="w-5 h-5 text-gray-950" />
        </div>
        <div>
          <h1 className="text-base font-bold tracking-tight text-white flex items-center gap-1.5">
            BugTools
            <span className="text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              PRO
            </span>
          </h1>
          <p className="text-[10px] font-mono text-cyan-400 uppercase tracking-wider">Research Station</p>
        </div>
      </div>

      {/* Navigation */}
      <div className="flex-1 overflow-y-auto p-3 space-y-1">
        <div className="px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-wider text-slate-500">
          Workstation Modules
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 ${
                  isActive
                    ? 'bg-[#161d2d] text-cyan-400 border border-cyan-500/30 shadow-[0_2px_12px_rgba(0,229,255,0.08)]'
                    : 'text-slate-400 hover:text-white hover:bg-[#1c2538]'
                }`
              }
            >
              <Icon className="w-4 h-4 shrink-0" />
              <span>{item.label}</span>
            </NavLink>
          );
        })}
      </div>

      {/* Footer / Engine Status */}
      <div className="p-4 border-t border-[#1e2638] bg-black/20 space-y-2">
        <div className="flex items-center justify-between text-xs font-mono text-slate-400">
          <span className="flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5 text-emerald-400" /> Rust + Go Core
          </span>
          <span className="text-emerald-400 font-semibold text-[11px]">READY</span>
        </div>
        <div className="flex items-center justify-between text-[11px] font-mono text-slate-500">
          <span>Tauri IPC v2</span>
          <span>SQLite WAL</span>
        </div>
      </div>
    </aside>
  );
};
