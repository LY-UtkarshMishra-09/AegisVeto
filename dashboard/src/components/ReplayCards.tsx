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
      <div className="bg-[#16221D] border border-[#263830] rounded p-4 flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between mb-1">
            <span className="text-[11px] font-mono uppercase tracking-wider text-[#D4F849] flex items-center gap-1.5 font-medium">
              <CheckCircle2 className="w-3.5 h-3.5" /> Scenario A · Benign Task
            </span>
            <span className="text-[11px] font-mono text-[#7E9489]">Expected: ALLOW</span>
          </div>
          <h4 className="text-xs font-medium text-[#ECF2EE] mt-1.5">
            Summarize <code className="text-[#D4F849] bg-[#0E1317] px-1.5 py-0.5 rounded font-mono text-[11px] border border-[#263830]">README.md</code>
          </h4>
          <p className="text-[11px] text-[#7E9489] mt-1.5 leading-relaxed">
            Agent reads benign repo documentation and outputs summary. Session state stays <span className="text-[#D4F849] font-mono font-semibold">CLEAN</span>.
          </p>
        </div>

        <div className="mt-4 pt-3 border-t border-[#263830] flex items-center justify-between">
          <span className="text-[11px] font-mono text-[#7E9489]">Tool: read_file</span>
          <button
            onClick={onRunBenign}
            disabled={isRunningScenario}
            className="px-3 py-1.5 bg-[#0E1317] hover:bg-[#16221D] text-[#ECF2EE] hover:text-[#D4F849] text-xs font-mono font-medium rounded border border-[#263830] flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <Play className="w-3 h-3 fill-current" />
            Run Scenario
          </button>
        </div>
      </div>

      {/* Card B: Indirect Prompt Injection */}
      <div className="bg-[#16221D] border border-[#263830] rounded p-4 flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between mb-1">
            <span className="text-[11px] font-mono uppercase tracking-wider text-[#F43F5E] flex items-center gap-1.5 font-medium">
              <ShieldAlert className="w-3.5 h-3.5" /> Scenario B · Indirect Prompt Injection
            </span>
            <span className="text-[11px] font-mono text-[#7E9489]">Expected: VETO</span>
          </div>

          <h4 className="text-xs font-medium text-[#ECF2EE] mt-1.5">
            Process <code className="text-[#ECF2EE] bg-[#0E1317] px-1.5 py-0.5 rounded font-mono text-[11px] border border-[#263830]">public_issue.txt</code> &rarr; <code className="text-[#F43F5E] bg-[#0E1317] px-1.5 py-0.5 rounded font-mono text-[11px] border border-[#F43F5E]/30">.env</code> Exfil Attempt
          </h4>
          <p className="text-[11px] text-[#7E9489] mt-1.5 leading-relaxed">
            Untrusted file hijacks agent prompt to read secrets and email attacker. Taint lattice locks egress immediately.
          </p>
        </div>

        <div className="mt-4 pt-3 border-t border-[#263830] flex items-center justify-between">
          <span className="text-[11px] font-mono text-[#7E9489]">read_public_issue &rarr; send_external_email</span>
          <button
            onClick={onRunAttack}
            disabled={isRunningScenario}
            className="px-3.5 py-1.5 bg-[#D4F849] hover:bg-[#c2e838] text-[#080B0E] text-xs font-mono font-bold rounded flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <Play className="w-3 h-3 fill-current" />
            Run Attack
          </button>
        </div>
      </div>
    </div>
  );
};
