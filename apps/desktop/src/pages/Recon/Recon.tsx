import React, { useState } from 'react';
import { Radar, Play, Globe } from 'lucide-react';

export const Recon: React.FC = () => {
  const [domain, setDomain] = useState('targetalpha.com');
  const [resolving, setResolving] = useState(false);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-3">
          <Radar className="w-7 h-7 text-cyan-400" />
          Reconnaissance & DNS Engine (Go Worker)
        </h2>
        <p className="text-xs font-mono text-slate-400 mt-1">
          High-concurrency Go worker pool communicating via versioned JSON IPC over stdin/stdout.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="p-5 rounded-xl bg-[#111622] border border-[#1e2638] shadow-xl space-y-4">
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
            Recon Task Dispatch
          </h3>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Target Apex / Domain</label>
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              className="w-full bg-[#0a0d13] border border-[#1e2638] focus:border-cyan-400 rounded-lg px-3 py-2 text-xs font-mono text-white outline-none"
            />
          </div>

          <div className="p-3 rounded-lg bg-black/30 border border-[#1e2638] text-[11px] font-mono text-slate-400 space-y-1">
            <div className="flex justify-between">
              <span>Engine Binary:</span>
              <span className="text-cyan-400">engines/recon-go</span>
            </div>
            <div className="flex justify-between">
              <span>Protocol Version:</span>
              <span className="text-white">1</span>
            </div>
            <div className="flex justify-between">
              <span>Resolver Mode:</span>
              <span className="text-white">Parallel Non-Blocking</span>
            </div>
          </div>

          <button
            onClick={() => setResolving(true)}
            disabled={resolving}
            className="w-full py-2.5 px-4 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono uppercase tracking-wider flex items-center justify-center gap-2 transition cursor-pointer"
          >
            <Play className="w-4 h-4 fill-current" />
            <span>{resolving ? 'Executing Go Worker...' : 'Start DNS Enumeration'}</span>
          </button>
        </div>

        <div className="lg:col-span-2 p-5 rounded-xl bg-[#111622] border border-[#1e2638] shadow-xl space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              Discovered Subdomains & Host Mappings
            </h3>
            <span className="text-xs font-mono text-slate-500">0 Hosts Found</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-[#1e2638] text-slate-400 text-[11px] uppercase">
                  <th className="pb-3 px-3">Host</th>
                  <th className="pb-3 px-3">Resolved IP</th>
                  <th className="pb-3 px-3">HTTP Status</th>
                  <th className="pb-3 px-3">Scope</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2638]/60">
                <tr>
                  <td colSpan={4} className="py-8 text-center text-slate-500 font-mono text-xs">
                    No hosts discovered yet. Enter a target to begin reconnaissance.
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
