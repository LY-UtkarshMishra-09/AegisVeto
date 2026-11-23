import React from 'react';
import { Bot, KeyRound, Network, ShieldCheck, Wrench, ArrowRight, Cpu } from 'lucide-react';
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
      stateColor: 'text-[#ECF2EE] border-[#263830] bg-[#0E1317]',
    },
    {
      label: 'JWT Scope',
      sub: status.jwtVerified ? 'Verified' : 'Invalid',
      icon: KeyRound,
      stateColor: 'text-[#D4F849] border-[#D4F849]/30 bg-[#16221D]',
    },
    {
      label: 'Taint Lattice',
      sub: status.taintState,
      icon: Network,
      stateColor: isTainted
        ? 'text-[#F43F5E] border-[#F43F5E]/30 bg-[#F43F5E]/10'
        : 'text-[#D4F849] border-[#D4F849]/30 bg-[#16221D]',
    },
    {
      label: 'Policy Gate',
      sub: status.policyGateVerdict,
      icon: ShieldCheck,
      stateColor:
        status.policyGateVerdict === 'ALLOW'
          ? 'text-[#D4F849] border-[#D4F849]/30 bg-[#16221D]'
          : status.policyGateVerdict === 'QUARANTINE'
          ? 'text-[#F59E0B] border-[#F59E0B]/30 bg-[#F59E0B]/10'
          : 'text-[#F43F5E] border-[#F43F5E]/30 bg-[#F43F5E]/10',
    },
    {
      label: 'Target Tool',
      sub: status.targetTool,
      icon: Wrench,
      stateColor: 'text-[#ECF2EE] border-[#263830] bg-[#0E1317]',
    },
  ];

  return (
    <div className="bg-[#16221D] border border-[#263830] rounded p-3">
      <div className="flex items-center justify-between mb-2.5">
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono uppercase tracking-wider text-[#7E9489]">
            Live Interception Pipeline Strip
          </span>
          {/* Active Provider Badge */}
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-[#0E1317] border border-[#263830] text-[10px] font-mono text-[#ECF2EE]">
            <Cpu className="w-3 h-3 text-[#D4F849]" />
            <span className="uppercase text-[#7E9489]">{status.provider}:</span>
            <span className="font-semibold text-[#ECF2EE]">{status.model}</span>
          </span>
        </div>

        <div className="flex items-center gap-3 text-xs font-mono">
          <span className="text-[#7E9489]">
            Taint Lattice:{' '}
            <span className={isTainted ? 'text-[#F43F5E] font-semibold' : 'text-[#D4F849] font-semibold'}>
              {status.taintState}
            </span>
          </span>
          <span className="text-[#263830]">|</span>
          <span className="text-[#7E9489]">
            Overhead: <span className="text-[#ECF2EE] font-semibold">{status.latencyMs.toFixed(2)}ms</span>
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
                className={`flex-1 min-w-[130px] p-2.5 rounded border ${node.stateColor} flex flex-col justify-between`}
              >
                <div className="flex items-center gap-1.5 text-[#7E9489] mb-1">
                  <Icon className="w-3.5 h-3.5" />
                  <span className="text-[11px] font-medium text-[#ECF2EE] truncate">{node.label}</span>
                </div>
                <div className="font-mono text-xs font-semibold truncate tracking-tight">
                  {node.sub}
                </div>
              </div>
              {!isLast && (
                <div className="text-[#7E9489]/50 px-0.5">
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
