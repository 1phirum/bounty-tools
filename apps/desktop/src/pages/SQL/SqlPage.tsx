import React, { useState } from 'react';
import {
  DatabaseZap,
  Play,
  ShieldCheck,
  Layers
} from 'lucide-react';

export const SqlPage: React.FC = () => {
  const [target, setTarget] = useState('https://api.targetalpha.com/v1/search');
  const [analyzing, setAnalyzing] = useState(false);

  const [techniques, setTechniques] = useState({
    baseline: true,
    context: true,
    error: true,
    differential: true,
    fingerprinting: true,
    timing: false,
  });

  const handleStart = () => {
    setAnalyzing(true);
    // A real implementation would connect to the Go worker via Tauri here.
    setTimeout(() => {
      setAnalyzing(false);
      // Wait for backend to send results. Fake data has been removed.
    }, 1200);
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="border-b border-[#1a2540] pb-4">
        <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2.5">
          <DatabaseZap className="w-5 h-5 text-cyan-400" />
          <span>SQL Research Workbench</span>
        </h2>
        <p className="text-xs font-mono text-slate-400 mt-1">
          Non-destructive hypothesis testing, baseline differential analysis, and DBMS error dialect detection.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Left Column: Configuration & Techniques */}
        <div className="space-y-4">
          {/* Target Box */}
          <div className="p-4 rounded-lg bg-[#0e1526] border border-[#1a2540] space-y-3">
            <h3 className="text-[11px] font-mono font-bold uppercase tracking-wider text-slate-400">
              Analysis Configuration
            </h3>

            <div>
              <label className="block text-[11px] font-mono text-slate-400 mb-1">Target Endpoint</label>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                className="w-full bg-[#090d16] border border-[#1a2540] focus:border-cyan-400 rounded px-3 py-1.5 text-xs font-mono text-white outline-none"
              />
            </div>

            <div className="flex items-center justify-between text-xs font-mono p-2 rounded bg-[#090d16] border border-[#1a2540]">
              <span className="text-slate-400 flex items-center gap-1.5 text-[11px]">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" /> Scope Validation
              </span>
              <span className="text-emerald-400 font-semibold text-[11px] flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                ENFORCED
              </span>
            </div>
          </div>

          {/* Analysis Techniques (Section 34) */}
          <div className="p-4 rounded-lg bg-[#0e1526] border border-[#1a2540] space-y-3">
            <h3 className="text-[11px] font-mono font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-cyan-400" />
              <span>Active Analysis Engines</span>
            </h3>

            <div className="space-y-2 text-xs font-mono text-slate-300">
              {Object.entries({
                baseline: 'Baseline Analysis (Variance check)',
                context: 'Context Analysis (Numeric vs String)',
                error: 'Error Analysis (Loaded TOML Rules)',
                differential: 'Differential Analysis (Fingerprint diff)',
                fingerprinting: 'DBMS Fingerprinting',
                timing: 'Timing Analysis (Latency correlation)',
              }).map(([key, label]) => (
                <label key={key} className="flex items-center gap-2.5 cursor-pointer hover:text-white select-none">
                  <input
                    type="checkbox"
                    checked={techniques[key as keyof typeof techniques]}
                    onChange={(e) =>
                      setTechniques({ ...techniques, [key]: e.target.checked })
                    }
                    className="rounded bg-[#090d16] border-[#1a2540] text-cyan-500 focus:ring-0"
                  />
                  <span className="text-[11.5px]">{label}</span>
                </label>
              ))}
            </div>

            <button
              onClick={handleStart}
              disabled={analyzing}
              className="w-full mt-3 py-2 px-4 rounded bg-cyan-500 hover:bg-cyan-400 active:bg-cyan-600 text-slate-950 font-bold text-xs font-mono uppercase tracking-wider flex items-center justify-center gap-2 cursor-pointer"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>{analyzing ? 'Testing Hypothesis...' : 'Start SQL Analysis'}</span>
            </button>
          </div>
        </div>

        {/* Right Column: Parameters & Evidence Output */}
        <div className="lg:col-span-2 space-y-4">
          {/* Parameters Table */}
          <div className="p-4 rounded-lg bg-[#0e1526] border border-[#1a2540] space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-[11px] font-mono font-bold uppercase tracking-wider text-slate-400">
                Identified Parameters
              </h3>
              <span className="text-[11px] font-mono text-slate-500">0 Parameters Detected</span>
            </div>

            {/* High-density workstation data table */}
            <div className="rounded border border-[#1a2540] overflow-hidden bg-[#090d16]">
              <table className="w-full text-left text-xs font-mono border-collapse">
                <thead>
                  <tr className="bg-[#0b1222] border-b border-[#1a2540] text-slate-400 text-[10.5px] uppercase tracking-wider">
                    <th className="py-2 px-3 border-r border-[#1a2540] font-semibold">Parameter</th>
                    <th className="py-2 px-3 border-r border-[#1a2540] font-semibold">Hypothesized Context</th>
                    <th className="py-2 px-3 border-r border-[#1a2540] font-semibold">Confidence</th>
                    <th className="py-2 px-3 font-semibold">State</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1a2540] text-[11.5px]">
                  <tr>
                    <td colSpan={4} className="py-8 text-center text-slate-500 font-mono text-xs">
                      No parameters identified. Start analysis to extract parameters.
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>


        </div>
      </div>
    </div>
  );
};
