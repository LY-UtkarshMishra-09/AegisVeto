import React from 'react';
import { ReplayCards } from '../components/ReplayCards';
import { PipelineStrip } from '../components/PipelineStrip';
import { KpiRow } from '../components/KpiRow';
import { StreamTable } from '../components/StreamTable';
import { ToolCall, PipelineStatus, LLMProvider } from '../types';
import { ShieldCheck, ShieldAlert, Cpu } from 'lucide-react';

interface LiveConsoleViewProps {
  toolCalls: ToolCall[];
  pipelineStatus: PipelineStatus;
  stats: {
    totalCalls: number;
    attacksVetoed: number;
    avgLatencyMs: number;
  };
  provider: LLMProvider;
  setProvider: (p: LLMProvider) => void;
  isProtected: boolean;
  setIsProtected: (v: boolean) => void;
  onRunBenign: () => void;
  onRunAttack: () => void;
  isRunningScenario: boolean;
}

export const LiveConsoleView: React.FC<LiveConsoleViewProps> = ({
  toolCalls,
  pipelineStatus,
  stats,
  provider,
  setProvider,
  isProtected,
  setIsProtected,
  onRunBenign,
  onRunAttack,
  isRunningScenario,
}) => {
  return (
    <div className="space-y-3.5">
      {/* Top Bar: Title on left, Segmented Pill Toggles on right */}
      <div className="flex items-center justify-between pb-1 border-b border-[#263830]">
        <div>
          <h2 className="text-sm font-semibold tracking-tight text-[#ECF2EE]">
            Live Interception Console
          </h2>
          <p className="text-[11px] text-[#7E9489] font-mono mt-0.5">
            Deterministic zero-trust security gate for tool calls
          </p>
        </div>

        {/* Right Segmented Toggles */}
        <div className="flex items-center gap-3">
          {/* Provider Toggle */}
          <div className="flex items-center gap-1.5">
            <span className="text-[11px] font-mono uppercase tracking-wider text-[#7E9489] flex items-center gap-1">
              <Cpu className="w-3.5 h-3.5 text-[#D4F849]" /> LLM:
            </span>
            <div className="flex items-center p-0.5 rounded bg-[#0E1317] border border-[#263830] text-xs font-mono">
              <button
                onClick={() => setProvider('ollama')}
                className={`px-2.5 py-1 rounded transition-colors ${
                  provider === 'ollama'
                    ? 'bg-[#D4F849] text-[#080B0E] font-bold'
                    : 'text-[#7E9489] hover:text-[#ECF2EE]'
                }`}
              >
                Ollama (Local)
              </button>
              <button
                onClick={() => setProvider('groq')}
                className={`px-2.5 py-1 rounded transition-colors ${
                  provider === 'groq'
                    ? 'bg-[#D4F849] text-[#080B0E] font-bold'
                    : 'text-[#7E9489] hover:text-[#ECF2EE]'
                }`}
              >
                Groq (Cloud)
              </button>
            </div>
          </div>

          {/* Mode Toggle */}
          <div className="flex items-center gap-1.5">
            <span className="text-[11px] font-mono uppercase tracking-wider text-[#7E9489]">
              Mode:
            </span>
            <div className="flex items-center p-0.5 rounded bg-[#0E1317] border border-[#263830] text-xs font-mono">
              <button
                onClick={() => setIsProtected(true)}
                className={`px-2.5 py-1 rounded flex items-center gap-1.5 transition-colors ${
                  isProtected
                    ? 'bg-[#D4F849] text-[#080B0E] font-bold'
                    : 'text-[#7E9489] hover:text-[#ECF2EE]'
                }`}
              >
                <ShieldCheck className="w-3.5 h-3.5" />
                Protected (AegisVeto)
              </button>
              <button
                onClick={() => setIsProtected(false)}
                className={`px-2.5 py-1 rounded flex items-center gap-1.5 transition-colors ${
                  !isProtected
                    ? 'bg-[#F43F5E] text-[#080B0E] font-bold'
                    : 'text-[#7E9489] hover:text-[#ECF2EE]'
                }`}
              >
                <ShieldAlert className="w-3.5 h-3.5" />
                Unprotected (Raw)
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Interactive Replay Row */}
      <ReplayCards
        onRunBenign={onRunBenign}
        onRunAttack={onRunAttack}
        isRunningScenario={isRunningScenario}
      />

      {/* Live Interception Pipeline Strip */}
      <PipelineStrip status={pipelineStatus} />

      {/* KPI Row */}
      <KpiRow
        totalCalls={stats.totalCalls}
        attacksVetoed={stats.attacksVetoed}
        avgLatencyMs={stats.avgLatencyMs}
      />

      {/* Live Tool-Call Stream Table */}
      <StreamTable toolCalls={toolCalls} />
    </div>
  );
};
