import React from 'react';
import { Bot, KeyRound, Network, ShieldCheck, Wrench, ArrowRight } from 'lucide-react';
import { PipelineStatus } from '../types';

interface PipelineStripProps {
  status: PipelineStatus;
}

export const PipelineStrip: React.FC<PipelineStripProps> = ({ status }) => {
  const isTainted = status.taintState === 'TAINTED';

  const nodes = [
    {
      label: 'Agent Session',
      sub: status.agentStatus === 'active' ? 'Active' : 'Idle',
      icon: Bot,
      stateColor: 'text-zinc-300 border-zinc-700 bg-zinc-900',
    },
    {
      label: 'JWT Scope',
      sub: status.jwtVerified ? 'Verified' : 'Invalid',
      icon: KeyRound,
      stateColor: 'text-emerald-400 border-emerald-500/30 bg-emerald-950/20',
    },
    {
      label: 'Taint Lattice',
      sub: status.taintState,
      icon: Network,
      stateColor: isTainted
        ? 'text-red-400 border-red-500/30 bg-red-950/20'
        : 'text-emerald-400 border-emerald-500/30 bg-emerald-950/20',
    },
    {
      label: 'Policy Gate',
      sub: status.policyGateVerdict,
      icon: ShieldCheck,
      stateColor:
        status.policyGateVerdict === 'ALLOW'
          ? 'text-emerald-400 border-emerald-500/30 bg-emerald-950/20'
          : status.policyGateVerdict === 'QUARANTINE'
          ? 'text-amber-400 border-amber-500/30 bg-amber-950/20'
          : 'text-red-400 border-red-500/30 bg-red-950/20',
    },
    {
      label: 'Target Tool',
      sub: status.targetTool,
      icon: Wrench,
      stateColor: 'text-zinc-300 border-zinc-700 bg-zinc-900',
    },
  ];

  return (
    <div className="bg-[#111113] border border-[#27272A] rounded p-3">
      <div className="flex items-center justify-between mb-2">
        <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-500">
          Live Interception Pipeline Strip
        </span>
        <div className="flex items-center gap-3 text-xs font-mono">
          <span className="text-zinc-400">
            Taint Lattice:{' '}
            <span className={isTainted ? 'text-red-400 font-semibold' : 'text-emerald-400 font-semibold'}>
              {status.taintState}
            </span>
          </span>
          <span className="text-zinc-500">|</span>
          <span className="text-zinc-400">
            Pipeline Overhead: <span className="text-zinc-200 font-semibold">{status.latencyMs.toFixed(2)}ms</span>
          </span>
        </div>
      </div>

      <div className="flex items-center justify-between gap-2 overflow-x-auto py-1">
        {nodes.map((node, idx) => {
          const Icon = node.icon;
          const isLast = idx === nodes.length - 1;
          return (
            <React.Fragment key={node.label}>
              <div
                className={`flex-1 min-w-[130px] p-2 rounded border ${node.stateColor} flex flex-col justify-between`}
              >
                <div className="flex items-center gap-1.5 text-zinc-400 mb-1">
                  <Icon className="w-3.5 h-3.5" />
                  <span className="text-[11px] font-medium text-zinc-300 truncate">{node.label}</span>
                </div>
                <div className="font-mono text-xs font-semibold truncate tracking-tight">
                  {node.sub}
                </div>
              </div>
              {!isLast && (
                <div className="text-zinc-600 px-0.5">
                  <ArrowRight className="w-3.5 h-3.5" />
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
};
