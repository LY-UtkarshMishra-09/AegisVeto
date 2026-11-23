import React from 'react';

interface KpiRowProps {
  totalCalls: number;
  attacksVetoed: number;
  avgLatencyMs: number;
}

export const KpiRow: React.FC<KpiRowProps> = ({
  totalCalls,
  attacksVetoed,
  avgLatencyMs,
}) => {
  return (
    <div className="grid grid-cols-3 gap-3">
      <div className="bg-[#111113] border border-[#27272A] rounded p-3">
        <div className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider">
          Total Calls
        </div>
        <div className="mt-1 flex items-baseline gap-2">
          <span className="text-xl font-mono font-semibold text-zinc-100">
            {totalCalls}
          </span>
          <span className="text-[11px] text-zinc-500 font-mono">100% Deterministic</span>
        </div>
      </div>

      <div className="bg-[#111113] border border-[#27272A] rounded p-3">
        <div className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider">
          Attacks Vetoed
        </div>
        <div className="mt-1 flex items-baseline gap-2">
          <span className="text-xl font-mono font-semibold text-red-400">
            {attacksVetoed}
          </span>
          <span className="text-[11px] text-red-500/70 font-mono font-medium">
            0% Data Leakage
          </span>
        </div>
      </div>

      <div className="bg-[#111113] border border-[#27272A] rounded p-3">
        <div className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider">
          Avg Proxy Latency
        </div>
        <div className="mt-1 flex items-baseline gap-2">
          <span className="text-xl font-mono font-semibold text-emerald-400">
            {avgLatencyMs.toFixed(2)} ms
          </span>
          <span className="text-[11px] text-zinc-500 font-mono">&lt; 10ms hard limit</span>
        </div>
      </div>
    </div>
  );
};
