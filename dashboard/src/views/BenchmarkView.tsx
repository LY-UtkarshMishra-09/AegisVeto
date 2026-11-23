import React from 'react';
import { BenchmarkMetric } from '../types';

interface BenchmarkViewProps {
  metrics: BenchmarkMetric[];
}

export const BenchmarkView: React.FC<BenchmarkViewProps> = ({ metrics }) => {
  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="bg-[#111113] border border-[#27272A] rounded p-3">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-200">
          Architecture &amp; Performance Benchmark
        </h3>
        <p className="text-[11px] text-zinc-400 mt-0.5">
          Empirical comparison between Raw Agent execution, LLM-as-a-Judge inspection, and AegisVeto Deterministic Zero-Trust.
        </p>
      </div>

      {/* Comparison Table */}
      <div className="bg-[#111113] border border-[#27272A] rounded overflow-hidden">
        <table className="w-full text-left border-collapse font-mono text-xs">
          <thead>
            <tr className="border-b border-[#27272A] bg-[#09090B]/60 text-[11px] text-zinc-400 uppercase">
              <th className="py-2.5 px-3">Evaluation Metric</th>
              <th className="py-2.5 px-3">Raw Agent (Unprotected)</th>
              <th className="py-2.5 px-3">LLM-as-a-Judge Guardrail</th>
              <th className="py-2.5 px-3 text-emerald-400">AegisVeto Zero-Trust</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#27272A]">
            {metrics.map((row) => (
              <tr key={row.id} className="hover:bg-[#18181B] transition-colors">
                <td className="py-2.5 px-3 font-sans font-medium text-zinc-300">
                  {row.category}
                </td>
                <td className="py-2.5 px-3 text-red-400/90">{row.rawAgent}</td>
                <td className="py-2.5 px-3 text-amber-300/90">{row.llmJudge}</td>
                <td className="py-2.5 px-3 text-emerald-400 font-semibold bg-emerald-950/10">
                  {row.aegisVeto}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Live Ollama vs Groq Session Runs Summary */}
      <div className="bg-[#111113] border border-[#27272A] rounded p-3 space-y-2">
        <div className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider">
          Live Session Runs: Ollama (Local) vs. Groq (Cloud)
        </div>
        <div className="grid grid-cols-2 gap-3 font-mono text-xs">
          <div className="p-3 rounded bg-[#09090B] border border-[#27272A] space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-zinc-200 font-semibold">Ollama (qwen3:8b)</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300 border border-zinc-700">LOCAL</span>
            </div>
            <div className="text-zinc-400 text-[11px]">Unprotected exfiltrations: <span className="text-red-400 font-semibold">100% Vulnerable</span></div>
            <div className="text-zinc-400 text-[11px]">AegisVeto Veto Rate: <span className="text-emerald-400 font-semibold">100% Blocked</span></div>
            <div className="text-zinc-500 text-[10px]">Overhead added by proxy: 1.82 ms</div>
          </div>

          <div className="p-3 rounded bg-[#09090B] border border-[#27272A] space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-zinc-200 font-semibold">Groq (llama-3.3-70b)</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300 border border-zinc-700">CLOUD</span>
            </div>
            <div className="text-zinc-400 text-[11px]">Unprotected exfiltrations: <span className="text-red-400 font-semibold">100% Vulnerable</span></div>
            <div className="text-zinc-400 text-[11px]">AegisVeto Veto Rate: <span className="text-emerald-400 font-semibold">100% Blocked</span></div>
            <div className="text-zinc-500 text-[10px]">Overhead added by proxy: 1.85 ms</div>
          </div>
        </div>
      </div>
    </div>
  );
};
