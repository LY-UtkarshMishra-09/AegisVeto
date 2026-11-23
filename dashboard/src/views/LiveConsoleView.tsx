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
    <div className="space-y-3">
      {/* Header Controls: Segmented Pill for Provider and Protection Toggle */}
      <div className="bg-[#111113] border border-[#27272A] rounded p-2.5 flex items-center justify-between">
        {/* Provider Segmented Pill */}
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-500 flex items-center gap-1">
            <Cpu className="w-3.5 h-3.5 text-zinc-400" /> Victim LLM:
          </span>
          <div className="flex items-center gap-1 bg-[#09090B] border border-[#27272A] p-0.5 rounded text-xs font-mono">
            <button
              onClick={() => setProvider('ollama')}
              className={`px-2 py-0.5 rounded transition-colors ${
                provider === 'ollama'
                  ? 'bg-zinc-800 text-zinc-100 font-semibold border border-zinc-700'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              Ollama (Local · qwen3:8b)
            </button>
            <button
              onClick={() => setProvider('groq')}
              className={`px-2 py-0.5 rounded transition-colors ${
                provider === 'groq'
                  ? 'bg-zinc-800 text-zinc-100 font-semibold border border-zinc-700'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              Groq (Cloud · llama-3.3-70b)
            </button>
          </div>
        </div>

        {/* Protection Mode Segmented Pill */}
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-500">
            Proxy Mode:
          </span>
          <div className="flex items-center gap-1 bg-[#09090B] border border-[#27272A] p-0.5 rounded text-xs font-mono">
            <button
              onClick={() => setIsProtected(true)}
              className={`px-2 py-0.5 rounded flex items-center gap-1.5 transition-colors ${
                isProtected
                  ? 'bg-emerald-500/20 text-emerald-300 font-semibold border border-emerald-500/30'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              Protected (AegisVeto)
            </button>
            <button
              onClick={() => setIsProtected(false)}
              className={`px-2 py-0.5 rounded flex items-center gap-1.5 transition-colors ${
                !isProtected
                  ? 'bg-red-500/20 text-red-300 font-semibold border border-red-500/30'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
              Unprotected (Raw)
            </button>
          </div>
        </div>
      </div>

      {/* Top Interactive Replay Cards */}
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
