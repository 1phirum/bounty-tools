import React from 'react';
import { Globe, Fingerprint } from 'lucide-react';

export const HttpPage: React.FC = () => {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-3">
          <Globe className="w-7 h-7 text-cyan-400" />
          HTTP Abstraction & Response Fingerprints
        </h2>
        <p className="text-xs font-mono text-slate-400 mt-1">
          Sections 10, 11 & 12 — Shared HTTP client with normalized body hashing, dynamic token redaction, and structural signatures.
        </p>
      </div>

      <div className="p-5 rounded-xl bg-[#111622] border border-[#1e2638] shadow-xl space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
            <Fingerprint className="w-4 h-4 text-cyan-400" />
            Recent Logged Requests & Fingerprints
          </h3>
          <span className="text-xs font-mono text-slate-500">Ready</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-[#1e2638] text-slate-400 text-[11px] uppercase">
                <th className="pb-3 px-3">Method</th>
                <th className="pb-3 px-3">URL</th>
                <th className="pb-3 px-3">Status</th>
                <th className="pb-3 px-3">Normalized SHA256</th>
                <th className="pb-3 px-3">Duration</th>
                <th className="pb-3 px-3">Structural Sig</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2638]/60">
              <tr>
                <td colSpan={6} className="py-8 text-center text-slate-500 font-mono text-xs">
                  No HTTP history recorded.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
