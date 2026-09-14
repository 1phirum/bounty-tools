import React, { useState } from 'react';
import { AlertTriangle, CheckCircle, FileText, ChevronRight } from 'lucide-react';
import { Finding } from '../../types';

interface FindingsProps {
  findings: Finding[];
}

export const Findings: React.FC<FindingsProps> = ({ findings }) => {
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(findings[0] || null);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-3">
          <AlertTriangle className="w-7 h-7 text-amber-400" />
          Findings & Evidence Repository
        </h2>
        <p className="text-xs font-mono text-slate-400 mt-1">
          Rule 3 & Section 23 — Never store only 'vulnerability detected'. Store reproducible, auditable evidence.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Finding List */}
        <div className="lg:col-span-2 space-y-3">
          {findings.length === 0 ? (
            <div className="p-8 text-center text-slate-500 font-mono text-xs border border-dashed border-[#1e2638] rounded-xl">
              No findings recorded yet. Launch a scan to discover evidence.
            </div>
          ) : (
            findings.map((f) => (
              <div
                key={f.id}
                onClick={() => setSelectedFinding(f)}
                className={`p-4 rounded-xl border transition cursor-pointer flex items-center justify-between ${
                  selectedFinding?.id === f.id
                    ? 'bg-[#161d2d] border-cyan-500/40 shadow-lg'
                    : 'bg-[#111622] border-[#1e2638] hover:border-slate-600'
                }`}
              >
                <div className="space-y-1.5">
                  <div className="flex items-center gap-2">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                        f.severity === 'CRITICAL'
                          ? 'bg-red-500/10 text-red-400 border-red-500/30'
                          : f.severity === 'HIGH'
                          ? 'bg-orange-500/10 text-orange-400 border-orange-500/30'
                          : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                      }`}
                    >
                      {f.severity}
                    </span>
                    <h3 className="text-sm font-bold text-white font-mono">{f.title}</h3>
                  </div>
                  <div className="text-xs font-mono text-slate-400">
                    {f.endpoint} {f.parameter && `(param: ${f.parameter})`}
                  </div>
                  <div className="flex items-center gap-3 text-[11px] font-mono text-slate-500">
                    <span>Confidence: <strong className="text-emerald-400">{f.confidence}</strong></span>
                    <span>•</span>
                    <span>Module: {f.module}</span>
                  </div>
                </div>
                <ChevronRight className="w-5 h-5 text-slate-500" />
              </div>
            ))
          )}
        </div>

        {/* Evidence Drawer */}
        <div className="p-5 rounded-xl bg-[#111622] border border-[#1e2638] shadow-2xl space-y-4">
          <div className="flex items-center justify-between border-b border-[#1e2638] pb-3">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
              <FileText className="w-4 h-4 text-cyan-400" />
              Evidence & Audit Trail
            </h3>
            <span className="text-[11px] font-mono text-cyan-400">Verifiable</span>
          </div>

          {selectedFinding ? (
            <div className="space-y-4 text-xs font-mono">
              <div>
                <span className="text-slate-500 uppercase text-[10px]">Title</span>
                <div className="text-white font-bold mt-0.5">{selectedFinding.title}</div>
              </div>

              <div>
                <span className="text-slate-500 uppercase text-[10px]">Analysis Technique</span>
                <div className="text-slate-300 mt-0.5">{selectedFinding.technique}</div>
              </div>

              {selectedFinding.dbms_hypothesis && (
                <div>
                  <span className="text-slate-500 uppercase text-[10px]">DBMS Hypothesis</span>
                  <div className="text-cyan-400 mt-0.5">{selectedFinding.dbms_hypothesis}</div>
                </div>
              )}

              <div>
                <span className="text-slate-500 uppercase text-[10px]">Verification Notes</span>
                <p className="text-slate-300 bg-[#0a0d13] p-3 rounded-lg border border-[#1e2638] mt-1 leading-relaxed">
                  {selectedFinding.notes || 'No notes entered.'}
                </p>
              </div>

              <div className="pt-2 flex items-center gap-2">
                <button className="flex-1 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs font-mono uppercase transition flex items-center justify-center gap-1.5 cursor-pointer">
                  <CheckCircle className="w-4 h-4" />
                  <span>Verify</span>
                </button>
                <button className="flex-1 py-2 rounded-lg bg-[#161d2d] border border-[#2c3850] text-slate-300 hover:text-white font-bold text-xs font-mono uppercase transition cursor-pointer">
                  Reject
                </button>
              </div>
            </div>
          ) : (
            <div className="text-center py-10 text-slate-500 font-mono text-xs">
              Select a finding to inspect raw evidence.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
