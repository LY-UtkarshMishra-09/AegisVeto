import React from 'react';
import { BenchmarkMetric } from '../types';

interface BenchmarkViewProps {
  metrics: BenchmarkMetric[];
}

export const BenchmarkView: React.FC<BenchmarkViewProps> = ({ metrics }) => {
  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="bg-[#16221D] border border-[#263830] rounded p-3">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-[#ECF2EE]">
          Architecture &amp; Performance Benchmark
        </h3>
        <p className="text-[11px] text-[#7E9489] mt-0.5">
          Empirical comparison between Raw Agent execution, LLM-as-a-Judge inspection, and AegisVeto Deterministic Zero-Trust.
        </p>
      </div>

      {/* Comparison Table */}
      <div className="bg-[#0E1317] border border-[#263830] rounded overflow-hidden">
        <table className="w-full text-left border-collapse font-mono text-xs">
          <thead>
            <tr className="border-b border-[#263830] bg-[#080B0E]/80 text-[11px] text-[#7E9489] uppercase">
              <th className="py-2.5 px-3">Evaluation Metric</th>
              <th className="py-2.5 px-3">Raw Agent (Unprotected)</th>
              <th className="py-2.5 px-3">LLM-as-a-Judge Guardrail</th>
              <th className="py-2.5 px-3 text-[#D4F849] bg-[#16221D] border-l border-[#263830]">
                AegisVeto Zero-Trust
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#263830]">
            {metrics.map((row) => (
              <tr key={row.id} className="hover:bg-[#16221D]/40 transition-colors">
                <td className="py-2.5 px-3 font-sans font-medium text-[#ECF2EE]">
                  {row.category}
                </td>
                <td className="py-2.5 px-3 text-[#F43F5E]/90">{row.rawAgent}</td>
                <td className="py-2.5 px-3 text-[#F59E0B]/90">{row.llmJudge}</td>
                <td className="py-2.5 px-3 text-[#D4F849] font-semibold bg-[#16221D] border-l border-[#263830]">
                  {row.aegisVeto}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Live Ollama vs Groq Session Runs Summary */}
      <div className="bg-[#16221D] border border-[#263830] rounded p-3 space-y-2">
        <div className="text-[11px] font-mono text-[#7E9489] uppercase tracking-wider">
          Live Session Runs: Ollama (Local) vs. Groq (Cloud)
        </div>
        <div className="grid grid-cols-2 gap-3 font-mono text-xs">
          <div className="p-3 rounded bg-[#0E1317] border border-[#263830] space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[#ECF2EE] font-semibold">Ollama (qwen3:8b)</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#16221D] text-[#D4F849] border border-[#263830]">LOCAL</span>
            </div>
            <div className="text-[#7E9489] text-[11px]">Unprotected exfiltrations: <span className="text-[#F43F5E] font-semibold">100% Vulnerable</span></div>
            <div className="text-[#7E9489] text-[11px]">AegisVeto Veto Rate: <span className="text-[#D4F849] font-semibold">100% Blocked</span></div>
            <div className="text-[#7E9489] text-[10px]">Overhead added by proxy: 0.41 ms</div>
          </div>

          <div className="p-3 rounded bg-[#0E1317] border border-[#263830] space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[#ECF2EE] font-semibold">Groq (llama-3.3-70b)</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#16221D] text-[#D4F849] border border-[#263830]">CLOUD</span>
            </div>
            <div className="text-[#7E9489] text-[11px]">Unprotected exfiltrations: <span className="text-[#F43F5E] font-semibold">100% Vulnerable</span></div>
            <div className="text-[#7E9489] text-[11px]">AegisVeto Veto Rate: <span className="text-[#D4F849] font-semibold">100% Blocked</span></div>
            <div className="text-[#7E9489] text-[10px]">Overhead added by proxy: 0.43 ms</div>
          </div>
        </div>
      </div>
    </div>
  );
};
