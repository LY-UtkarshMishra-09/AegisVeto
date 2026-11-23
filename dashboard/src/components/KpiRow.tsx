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
      <div className="bg-[#0E1317] border border-[#263830] rounded p-3.5">
        <div className="text-[11px] font-mono text-[#7E9489] uppercase tracking-wider">
          Total Calls
        </div>
        <div className="mt-1 flex items-baseline gap-2">
          <span className="text-2xl font-mono font-semibold text-[#ECF2EE]">
            {totalCalls}
          </span>
          <span className="text-[11px] text-[#7E9489] font-mono">100% Deterministic</span>
        </div>
      </div>

      <div className="bg-[#0E1317] border border-[#263830] rounded p-3.5">
        <div className="text-[11px] font-mono text-[#7E9489] uppercase tracking-wider">
          Attacks Vetoed
        </div>
        <div className="mt-1 flex items-baseline gap-2">
          <span className="text-2xl font-mono font-semibold text-[#F43F5E]">
            {attacksVetoed}
          </span>
          <span className="text-[11px] text-[#F43F5E]/80 font-mono font-medium">
            0% Data Leakage
          </span>
        </div>
      </div>

      <div className="bg-[#0E1317] border border-[#263830] rounded p-3.5">
        <div className="text-[11px] font-mono text-[#7E9489] uppercase tracking-wider">
          Avg Proxy Latency
        </div>
        <div className="mt-1 flex items-baseline gap-2">
          <span className="text-2xl font-mono font-semibold text-[#D4F849]">
            {avgLatencyMs.toFixed(2)} ms
          </span>
          <span className="text-[11px] text-[#7E9489] font-mono">&lt; 10ms hard limit</span>
        </div>
      </div>
    </div>
  );
};
