import React from 'react';
import { Check, X, ShieldAlert, AlertTriangle } from 'lucide-react';
import { QuarantineItem } from '../types';

interface QuarantineViewProps {
  queue: QuarantineItem[];
  onApprove: (id: string) => void;
  onVeto: (id: string) => void;
}

export const QuarantineView: React.FC<QuarantineViewProps> = ({
  queue,
  onApprove,
  onVeto,
}) => {
  const pendingItems = queue.filter((item) => item.status === 'PENDING');
  const resolvedItems = queue.filter((item) => item.status !== 'PENDING');

  return (
    <div className="space-y-4">
      {/* Header Info */}
      <div className="bg-[#16221D] border border-[#263830] rounded p-3 flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-[#F59E0B]" />
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[#ECF2EE]">
              Human-in-the-Loop Quarantine Queue
            </h3>
          </div>
          <p className="text-[11px] text-[#7E9489] mt-0.5 font-sans">
            Destructive commands and high-risk operations deterministically paused for operator verdict.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="text-[#7E9489]">Pending:</span>
          <span className="px-2 py-0.5 rounded bg-[#F59E0B]/10 text-[#F59E0B] border border-[#F59E0B]/30 font-semibold">
            {pendingItems.length}
          </span>
        </div>
      </div>

      {/* Pending Items List */}
      <div className="space-y-3">
        {pendingItems.length === 0 ? (
          <div className="bg-[#16221D] border border-[#263830] rounded p-8 text-center">
            <div className="inline-flex items-center justify-center w-8 h-8 rounded bg-[#0E1317] text-[#7E9489] mb-2 border border-[#263830]">
              <ShieldAlert className="w-4 h-4 text-[#D4F849]" />
            </div>
            <p className="text-xs font-mono text-[#ECF2EE]">Quarantine queue is empty</p>
            <p className="text-[11px] text-[#7E9489] mt-1 font-sans">All agent tool invocations have been evaluated cleanly.</p>
          </div>
        ) : (
          pendingItems.map((item) => (
            <div
              key={item.id}
              className="bg-[#16221D] border border-[#263830] rounded overflow-hidden"
            >
              <div className="p-3 border-b border-[#263830] flex items-center justify-between bg-[#0E1317]">
                <div className="flex items-center gap-2 font-mono text-xs">
                  <span className="text-[#ECF2EE] font-semibold">{item.id}</span>
                  <span className="text-[#263830]">·</span>
                  <span className="text-[#7E9489]">{item.session}</span>
                  <span className="text-[#263830]">·</span>
                  <span className="bg-[#16221D] px-1.5 py-0.5 rounded text-[11px] text-[#ECF2EE] border border-[#263830]">
                    {item.tool}
                  </span>
                  <span className="text-[#263830]">·</span>
                  <span
                    className={`text-[10px] font-semibold ${
                      item.taint === 'TAINTED' ? 'text-[#F43F5E]' : 'text-[#D4F849]'
                    }`}
                  >
                    {item.taint}
                  </span>
                </div>

                <div className="text-[11px] font-mono text-[#7E9489]">{item.timestamp}</div>
              </div>

              {/* Split View Content */}
              <div className="p-3.5 grid grid-cols-2 gap-3.5">
                {/* Left: Tool Name, Reason & JSON Arguments */}
                <div className="space-y-2.5">
                  <div className="p-2.5 rounded bg-[#0E1317] border border-[#263830]">
                    <div className="flex items-center gap-1.5 text-[#F59E0B] text-[11px] font-mono mb-1 font-medium">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      Risk Assessment
                    </div>
                    <p className="text-xs text-[#ECF2EE] font-sans leading-relaxed">
                      {item.riskSummary}
                    </p>
                  </div>

                  <div className="p-2.5 rounded bg-[#0E1317] border border-[#263830] text-xs font-mono">
                    <span className="text-[10px] uppercase text-[#7E9489] block mb-0.5">
                      Matched Rule Trigger
                    </span>
                    <span className="text-[#ECF2EE] font-semibold">{item.ruleMatched}</span>
                  </div>

                  <div>
                    <div className="text-[10px] font-mono uppercase text-[#7E9489] mb-1">
                      Intercepted Tool Arguments (JSON)
                    </div>
                    <pre className="p-2.5 rounded bg-[#0E1317] border border-[#263830] text-[#ECF2EE] text-[11px] font-mono overflow-x-auto max-h-[120px]">
                      {JSON.stringify(item.args, null, 2)}
                    </pre>
                  </div>
                </div>

                {/* Right: Approve & Veto Action Buttons */}
                <div className="flex flex-col justify-center gap-3 p-4 rounded bg-[#0E1317] border border-[#263830]">
                  <div className="text-xs text-[#7E9489] text-center mb-1">
                    Operator Decision Required
                  </div>

                  <button
                    onClick={() => onApprove(item.id)}
                    className="w-full py-2.5 px-4 rounded bg-[#D4F849] hover:bg-[#c2e838] text-[#080B0E] text-xs font-mono font-bold flex items-center justify-center gap-2 transition-colors"
                  >
                    <Check className="w-4 h-4 stroke-[2.5]" />
                    Approve Execution
                  </button>

                  <button
                    onClick={() => onVeto(item.id)}
                    className="w-full py-2.5 px-4 rounded bg-transparent hover:bg-[#F43F5E]/10 text-[#F43F5E] border border-[#F43F5E] text-xs font-mono font-bold flex items-center justify-center gap-2 transition-colors"
                  >
                    <X className="w-4 h-4 stroke-[2.5]" />
                    Veto &amp; Terminate
                  </button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Resolved History */}
      {resolvedItems.length > 0 && (
        <div className="bg-[#16221D] border border-[#263830] rounded p-3">
          <div className="text-[11px] font-mono text-[#7E9489] uppercase tracking-wider mb-2">
            Resolved Session Items
          </div>
          <div className="space-y-1.5">
            {resolvedItems.map((item) => (
              <div
                key={item.id}
                className="flex items-center justify-between text-xs font-mono p-2 rounded bg-[#0E1317] border border-[#263830]"
              >
                <div className="flex items-center gap-2">
                  <span className="text-[#ECF2EE] font-semibold">{item.id}</span>
                  <span className="text-[#263830]">·</span>
                  <span className="text-[#7E9489]">{item.tool}</span>
                </div>
                <div>
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-semibold border ${
                      item.status === 'APPROVED'
                        ? 'bg-[#D4F849]/10 text-[#D4F849] border-[#D4F849]/30'
                        : 'bg-[#F43F5E]/10 text-[#F43F5E] border-[#F43F5E]/30'
                    }`}
                  >
                    {item.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
