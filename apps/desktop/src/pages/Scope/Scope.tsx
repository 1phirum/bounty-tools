import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Plus,
  Trash2,
  CheckCircle,
  XCircle,
  Search,
  ChevronDown
} from 'lucide-react';
import { ScopeEvaluation, ScopeRule, ScopeRuleType } from '../../types';

const RULE_OPTIONS: { value: ScopeRuleType; label: string }[] = [
  { value: 'include_domain', label: 'Include Domain (e.g. *.example.com)' },
  { value: 'exclude_domain', label: 'Exclude Domain (e.g. admin.example.com)' },
  { value: 'include_path', label: 'Include Path (e.g. /api/)' },
  { value: 'exclude_path', label: 'Exclude Path (e.g. /logout)' },
  { value: 'include_port', label: 'Include Port (e.g. 443)' },
  { value: 'exclude_port', label: 'Exclude Port (e.g. 22)' },
  { value: 'protocol', label: 'Protocol (e.g. https)' }
];

interface ScopeProps {
  rules: ScopeRule[];
  onAddRule: (ruleType: ScopeRuleType, pattern: string) => Promise<void>;
  onEvaluate: (target: string) => Promise<ScopeEvaluation>;
}

export const Scope: React.FC<ScopeProps> = ({ rules, onAddRule, onEvaluate }) => {
  const [newType, setNewType] = useState<ScopeRuleType>('include_domain');
  const [newPattern, setNewPattern] = useState('');
  const [testInput, setTestInput] = useState('https://api.targetalpha.com/v1/users');
  const [evalResult, setEvalResult] = useState<ScopeEvaluation | null>(null);
  const [isEvaluating, setIsEvaluating] = useState(false);
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newPattern.trim()) return;
    await onAddRule(newType, newPattern.trim());
    setNewPattern('');
  };

  const handleTest = async () => {
    if (!testInput.trim()) return;
    setIsEvaluating(true);
    try {
      const res = await onEvaluate(testInput.trim());
      setEvalResult(res);
    } finally {
      setIsEvaluating(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div>
        <h2 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-3">
          <ShieldCheck className="w-7 h-7 text-emerald-400" />
          Scope Engine & Boundary Enforcement
        </h2>
        <p className="text-xs font-mono text-slate-400 mt-1">
          Rule 2 — Scope enforcement happens before network execution. Unauthorized targets are rejected and audited.
        </p>
      </div>

      {/* Live Scope Tester Card */}
      <div className="p-5 rounded-xl bg-[#111622] border border-[#1e2638] shadow-2xl space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold font-mono uppercase tracking-wider text-slate-200 flex items-center gap-2">
            <Search className="w-4 h-4 text-cyan-400" />
            Interactive Scope Decision Validator
          </h3>
          <span className="text-xs font-mono text-slate-400">Pre-flight check</span>
        </div>

        <div className="flex items-center gap-3">
          <input
            type="text"
            value={testInput}
            onChange={(e) => setTestInput(e.target.value)}
            className="flex-1 bg-[#0a0d13] border border-[#1e2638] focus:border-cyan-400 rounded-lg px-4 py-2.5 text-xs font-mono text-white outline-none"
            placeholder="e.g. https://api.example.com/v1/search or *.example.com"
          />
          <button
            onClick={handleTest}
            disabled={isEvaluating}
            className="px-5 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs uppercase tracking-wider transition cursor-pointer"
          >
            {isEvaluating ? 'Evaluating...' : 'Test Scope'}
          </button>
        </div>

        {evalResult && (
          <div
            className={`p-4 rounded-lg border flex items-start gap-3 transition-all ${
              evalResult.allowed
                ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                : 'bg-red-950/40 border-red-500/40 text-red-300'
            }`}
          >
            {evalResult.allowed ? (
              <CheckCircle className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            ) : (
              <XCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
            )}
            <div className="text-xs font-mono space-y-1">
              <div className="font-bold flex items-center gap-2">
                <span>{evalResult.allowed ? 'TARGET PERMITTED' : 'TARGET REJECTED BY SCOPE ENGINE'}</span>
                {evalResult.matched_rule && (
                  <span className="px-1.5 py-0.5 rounded bg-black/40 border border-current text-[10px]">
                    Matched: {evalResult.matched_rule}
                  </span>
                )}
              </div>
              <div className="opacity-90">{evalResult.reason}</div>
            </div>
          </div>
        )}
      </div>

      {/* Scope Rules List & Add Form */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Rules Table */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-[#111622] border border-[#1e2638] shadow-xl space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold font-mono uppercase tracking-wider text-slate-200">
              Active Scope Rules ({rules.length})
            </h3>
            <span className="text-xs font-mono text-emerald-400">Strict Enforcement</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-[#1e2638] text-slate-400 text-[11px] uppercase">
                  <th className="pb-3 px-3">Type</th>
                  <th className="pb-3 px-3">Pattern / Value</th>
                  <th className="pb-3 px-3">Status</th>
                  <th className="pb-3 px-3">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2638]/60">
                {rules.map((rule) => (
                  <tr key={rule.id} className="hover:bg-[#161d2d]/60 transition">
                    <td className="py-3 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                          rule.rule_type.startsWith('include')
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                            : 'bg-red-500/10 text-red-400 border-red-500/30'
                        }`}
                      >
                        {rule.rule_type}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-white font-semibold">{rule.pattern}</td>
                    <td className="py-3 px-3 text-emerald-400">
                      <span className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5"></span>
                      ACTIVE
                    </td>
                    <td className="py-3 px-3">
                      <button className="text-slate-500 hover:text-red-400 transition" title="Delete Rule">
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Add Scope Rule Form */}
        <div className="p-5 rounded-xl bg-[#111622] border border-[#1e2638] shadow-xl space-y-4">
          <div>
            <h3 className="text-sm font-bold font-mono uppercase tracking-wider text-slate-200 flex items-center gap-2">
              <Plus className="w-4 h-4 text-cyan-400" />
              Add Scope Rule
            </h3>
            <p className="text-xs text-slate-400 mt-1 font-mono">
              Enforced across Rust HTTP client, Go workers, and SQL analyzer.
            </p>
          </div>

          <form onSubmit={handleAdd} className="space-y-4">
            <div className="relative">
              <label className="block text-xs font-mono text-slate-400 mb-1">Rule Type</label>
              <button
                type="button"
                onClick={() => setIsDropdownOpen(!isDropdownOpen)}
                onBlur={() => setTimeout(() => setIsDropdownOpen(false), 200)}
                className={`w-full flex items-center justify-between bg-[#0a0d13] border ${isDropdownOpen ? 'border-cyan-400' : 'border-[#1e2638]'} rounded-lg px-3 py-2 text-xs font-mono text-white outline-none cursor-pointer text-left transition-colors`}
              >
                <span>{RULE_OPTIONS.find(o => o.value === newType)?.label}</span>
                <ChevronDown className={`w-4 h-4 text-slate-400 transition-transform ${isDropdownOpen ? 'rotate-180' : ''}`} />
              </button>

              {isDropdownOpen && (
                <div className="absolute z-10 w-full mt-1 bg-[#0a0d13] border border-[#1e2638] rounded-lg shadow-2xl overflow-hidden font-mono text-xs text-slate-300">
                  {RULE_OPTIONS.map((opt) => (
                    <button
                      key={opt.value}
                      type="button"
                      onClick={() => {
                        setNewType(opt.value);
                        setIsDropdownOpen(false);
                      }}
                      className={`w-full text-left px-3 py-2.5 hover:bg-[#161d2d] hover:text-white transition-colors cursor-pointer ${
                        newType === opt.value ? 'bg-[#161d2d] text-cyan-400 border-l-2 border-cyan-400' : 'border-l-2 border-transparent'
                      }`}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
              )}
            </div>

            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">Pattern</label>
              <input
                type="text"
                value={newPattern}
                onChange={(e) => setNewPattern(e.target.value)}
                placeholder="*.target.com"
                className="w-full bg-[#0a0d13] border border-[#1e2638] focus:border-cyan-400 rounded-lg px-3 py-2 text-xs font-mono text-white outline-none"
              />
            </div>

            <button
              type="submit"
              className="w-full py-2.5 px-4 rounded-lg bg-[#161d2d] border border-cyan-500/40 hover:bg-cyan-500/10 text-cyan-400 font-bold text-xs font-mono uppercase tracking-wider flex items-center justify-center gap-2 transition cursor-pointer"
            >
              <ShieldAlert className="w-4 h-4" />
              <span>Register Rule</span>
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
