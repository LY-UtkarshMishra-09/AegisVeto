import React from 'react';
import { ReplayCards } from '../components/ReplayCards';
import { PipelineStrip } from '../components/PipelineStrip';
import { KpiRow } from '../components/KpiRow';
import { StreamTable } from '../components/StreamTable';
import { ToolCall, PipelineStatus } from '../types';

interface LiveConsoleViewProps {
  toolCalls: ToolCall[];
  pipelineStatus: PipelineStatus;
  stats: {
    totalCalls: number;
    attacksVetoed: number;
    avgLatencyMs: number;
  };
  onRunBenign: () => void;
  onRunAttack: () => void;
  isProtected: boolean;
  setIsProtected: (v: boolean) => void;
  isRunningScenario: boolean;
}

export const LiveConsoleView: React.FC<LiveConsoleViewProps> = ({
  toolCalls,
  pipelineStatus,
  stats,
  onRunBenign,
  onRunAttack,
  isProtected,
  setIsProtected,
  isRunningScenario,
}) => {
  return (
    <div className="space-y-3">
      {/* Top Interactive Replay Cards */}
      <ReplayCards
        onRunBenign={onRunBenign}
        onRunAttack={onRunAttack}
        isProtected={isProtected}
        setIsProtected={setIsProtected}
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
