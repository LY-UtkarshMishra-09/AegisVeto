import React from 'react';
import { Play, ShieldAlert, CheckCircle2 } from 'lucide-react';

interface ReplayCardsProps {
  onRunBenign: () => void;
  onRunAttack: () => void;
  isRunningScenario: boolean;
}

export const ReplayCards: React.FC<ReplayCardsProps> = ({
  onRunBenign,
  onRunAttack,
  isRunningScenario,
}) => {
  return (
    <div className="grid grid-cols-2 gap-3">
      {/* Card A: Benign Task */}
      <div className="bg-[#111113] border border-[#27272A] rounded p-3 flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between mb-1">
            <span className="text-[11px] font-mono uppercase tracking-wider text-emerald-400 flex items-center gap-1.5 font-medium">
              <CheckCircle2 className="w-3.5 h-3.5" /> Scenario A · Benign Task
            </span>
            <span className="text-[11px] font-mono text-zinc-500">Expected: ALLOW</span>
          </div>
          <h4 className="text-xs font-medium text-zinc-200 mt-1">
            Summarize <code className="text-zinc-300 bg-zinc-800/80 px-1 py-0.5 rounded font-mono text-[11px]">README.md</code>
          </h4>
          <p className="text-[11px] text-zinc-400 mt-1 leading-relaxed">
            Agent reads benign repo documentation and outputs summary. Session state stays <span className="text-emerald-400 font-mono">CLEAN</span>.
          </p>
        </div>

        <div className="mt-3 pt-2 border-t border-[#27272A] flex items-center justify-between">
          <span className="text-[11px] font-mono text-zinc-500">Tool: read_file</span>
          <button
            onClick={onRunBenign}
            disabled={isRunningScenario}
            className="px-2.5 py-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-100 text-xs font-mono font-medium rounded border border-zinc-700 flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <Play className="w-3 h-3 fill-current" />
            Run Scenario
          </button>
        </div>
      </div>

      {/* Card B: Indirect Prompt Injection */}
      <div className="bg-[#111113] border border-[#27272A] rounded p-3 flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between mb-1">
            <span className="text-[11px] font-mono uppercase tracking-wider text-red-400 flex items-center gap-1.5 font-medium">
              <ShieldAlert className="w-3.5 h-3.5" /> Scenario B · Indirect Prompt Injection
            </span>
            <span className="text-[11px] font-mono text-zinc-500">Expected: VETO</span>
          </div>

          <h4 className="text-xs font-medium text-zinc-200 mt-1">
            Process <code className="text-zinc-300 bg-zinc-800/80 px-1 py-0.5 rounded font-mono text-[11px]">public_issue.txt</code> &rarr; <code className="text-red-300 bg-red-950/40 px-1 py-0.5 rounded font-mono text-[11px]">.env</code> Exfil Attempt
          </h4>
          <p className="text-[11px] text-zinc-400 mt-1 leading-relaxed">
            Untrusted file hijacks agent prompt to read secrets and email attacker. Taint lattice locks egress immediately.
          </p>
        </div>

        <div className="mt-3 pt-2 border-t border-[#27272A] flex items-center justify-between">
          <span className="text-[11px] font-mono text-zinc-500">Tool: read_public_issue &rarr; send_external_email</span>
          <button
            onClick={onRunAttack}
            disabled={isRunningScenario}
            className="px-2.5 py-1 bg-red-950/40 hover:bg-red-900/50 text-red-300 text-xs font-mono font-medium rounded border border-red-800/60 flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <Play className="w-3 h-3 fill-current" />
            Run Attack
          </button>
        </div>
      </div>
    </div>
  );
};
