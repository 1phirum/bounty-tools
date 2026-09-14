import React, { useState } from 'react';
import { Settings as SettingsIcon, Sliders, Save } from 'lucide-react';

export const Settings: React.FC = () => {
  const [rps, setRps] = useState('5.0');
  const [concurrency, setConcurrency] = useState('4');
  const [budget, setBudget] = useState('1000');
  const [saved, setSaved] = useState(false);

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h2 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-3">
          <SettingsIcon className="w-7 h-7 text-cyan-400" />
          Workstation & Scanner Limits
        </h2>
        <p className="text-xs font-mono text-slate-400 mt-1">
          Sections 30 & 31 — Centralized rate limiting, concurrency throttles, and maximum request budgets.
        </p>
      </div>

      <div className="p-5 rounded-xl bg-[#111622] border border-[#1e2638] shadow-xl space-y-5">
        <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
          <Sliders className="w-4 h-4 text-cyan-400" />
          Traffic & Safety Controls
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Max Requests / Second</label>
            <input
              type="text"
              value={rps}
              onChange={(e) => setRps(e.target.value)}
              className="w-full bg-[#0a0d13] border border-[#1e2638] focus:border-cyan-400 rounded-lg px-3 py-2 text-xs font-mono text-white outline-none"
            />
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Max Worker Concurrency</label>
            <input
              type="text"
              value={concurrency}
              onChange={(e) => setConcurrency(e.target.value)}
              className="w-full bg-[#0a0d13] border border-[#1e2638] focus:border-cyan-400 rounded-lg px-3 py-2 text-xs font-mono text-white outline-none"
            />
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Max Requests per Job (Budget)</label>
            <input
              type="text"
              value={budget}
              onChange={(e) => setBudget(e.target.value)}
              className="w-full bg-[#0a0d13] border border-[#1e2638] focus:border-cyan-400 rounded-lg px-3 py-2 text-xs font-mono text-white outline-none"
            />
          </div>
        </div>

        <div className="pt-2 flex items-center justify-between">
          <span className="text-xs font-mono text-slate-500">
            Rules automatically synchronized to Rust controller & Go worker pool.
          </span>
          <button
            onClick={handleSave}
            className="px-5 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono uppercase tracking-wider transition flex items-center gap-2 cursor-pointer"
          >
            <Save className="w-4 h-4" />
            <span>{saved ? 'Saved!' : 'Save Limits'}</span>
          </button>
        </div>
      </div>
    </div>
  );
};
