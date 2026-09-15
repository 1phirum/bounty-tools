import React, { useState } from 'react';
import {
  DatabaseZap,
  Play,
  ShieldCheck,
  Layers,
  Sparkles,
  Check,
  AlertCircle
} from 'lucide-react';

interface SqlPageProps {
  activeProjectId: string | null;
  onTriggerTestJob: (target: string, module: string) => void;
}

export const SqlPage: React.FC<SqlPageProps> = ({ activeProjectId, onTriggerTestJob }) => {
  const [target, setTarget] = useState('');
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [techniques, setTechniques] = useState({
    baseline: true,
    context: true,
    error: true,
    differential: true,
    fingerprinting: true,
    timing: false,
  });

  const handleStart = () => {
    setError(null);

    if (!target.trim()) {
      setError('Please enter a target endpoint URL.');
      return;
    }

    if (!activeProjectId) {
      setError('No active project selected. Please select a project first.');
      return;
    }

    setAnalyzing(true);
    try {
      onTriggerTestJob(target.trim(), 'sql_injection');
    } catch (err: any) {
      setError(err?.toString() ?? 'An unexpected error occurred.');
    } finally {
      // The button resets after a short delay; real progress comes via events.
      setTimeout(() => setAnalyzing(false), 1500);
    }
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

      {/* Error Display */}
      {error && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

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
              }).map(([key, label]) => {
                const isChecked = techniques[key as keyof typeof techniques];
                return (
                  <label key={key} className="flex items-center gap-3 cursor-pointer group select-none">
                    <div className="relative flex items-center justify-center">
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={(e) =>
                          setTechniques({ ...techniques, [key]: e.target.checked })
                        }
                        className="sr-only"
                      />
                      <div className={`w-4 h-4 rounded flex items-center justify-center transition-all ${
                        isChecked 
                          ? 'bg-cyan-500 border border-cyan-500 text-[#090d16]' 
                          : 'bg-[#090d16] border border-[#1a2540] text-transparent group-hover:border-[#2c3850]'
                      }`}>
                        <Check className="w-3 h-3" strokeWidth={4} />
                      </div>
                    </div>
                    <span className={`text-[11.5px] transition-colors ${isChecked ? 'text-white' : 'text-slate-400 group-hover:text-slate-300'}`}>
                      {label}
                    </span>
                  </label>
                );
              })}
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
