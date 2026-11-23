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
      <div className="bg-[#111113] border border-[#27272A] rounded p-3 flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-amber-400" />
            <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-200">
              Human-in-the-Loop Quarantine Queue
            </h3>
          </div>
          <p className="text-[11px] text-zinc-400 mt-0.5">
            Destructive commands and high-risk operations deterministically paused for operator verdict.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="text-zinc-500">Pending:</span>
          <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 font-semibold">
            {pendingItems.length}
          </span>
        </div>
      </div>

      {/* Pending Items List */}
      <div className="space-y-3">
        {pendingItems.length === 0 ? (
          <div className="bg-[#111113] border border-[#27272A] rounded p-8 text-center">
            <div className="inline-flex items-center justify-center w-8 h-8 rounded bg-zinc-800 text-zinc-400 mb-2">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <p className="text-xs font-mono text-zinc-400">Quarantine queue is empty</p>
            <p className="text-[11px] text-zinc-500 mt-1">All agent tool invocations have been processed.</p>
          </div>
        ) : (
          pendingItems.map((item) => (
            <div
              key={item.id}
              className="bg-[#111113] border border-[#27272A] rounded overflow-hidden"
            >
              <div className="p-3 border-b border-[#27272A] flex items-center justify-between bg-[#09090B]/60">
                <div className="flex items-center gap-2 font-mono text-xs">
                  <span className="text-zinc-200 font-semibold">{item.id}</span>
                  <span className="text-zinc-500">·</span>
                  <span className="text-zinc-400">{item.session}</span>
                  <span className="text-zinc-500">·</span>
                  <span className="bg-zinc-800 px-1.5 py-0.5 rounded text-[11px] text-zinc-200 border border-zinc-700">
                    {item.tool}
                  </span>
                  <span className="text-zinc-500">·</span>
                  <span
                    className={`text-[10px] ${
                      item.taint === 'TAINTED' ? 'text-red-400' : 'text-emerald-400'
                    }`}
                  >
                    {item.taint}
                  </span>
                </div>

                <div className="text-[11px] font-mono text-zinc-500">{item.timestamp}</div>
              </div>

              {/* Split View Content */}
              <div className="p-3 grid grid-cols-2 gap-3">
                {/* Risk and Rule Card */}
                <div className="space-y-2.5">
                  <div className="p-2.5 rounded bg-[#09090B] border border-[#27272A]">
                    <div className="flex items-center gap-1.5 text-amber-400 text-[11px] font-mono mb-1 font-medium">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      Risk Assessment
                    </div>
                    <p className="text-xs text-zinc-300 font-sans leading-relaxed">
                      {item.riskSummary}
                    </p>
                  </div>

                  <div className="p-2.5 rounded bg-[#09090B] border border-[#27272A] text-xs font-mono">
                    <span className="text-[10px] uppercase text-zinc-500 block mb-0.5">
                      Matched Rule Trigger
                    </span>
                    <span className="text-zinc-300 font-semibold">{item.ruleMatched}</span>
                  </div>

                  {/* Actions */}
                  <div className="pt-2 flex items-center gap-2">
                    <button
                      onClick={() => onApprove(item.id)}
                      className="flex-1 py-1.5 px-3 rounded bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-xs font-mono font-medium flex items-center justify-center gap-1.5 transition-colors"
                    >
                      <Check className="w-3.5 h-3.5" />
                      Approve Execution
                    </button>
                    <button
                      onClick={() => onVeto(item.id)}
                      className="flex-1 py-1.5 px-3 rounded bg-red-500/10 hover:bg-red-500/20 text-red-300 border border-red-500/30 text-xs font-mono font-medium flex items-center justify-center gap-1.5 transition-colors"
                    >
                      <X className="w-3.5 h-3.5" />
                      Veto &amp; Terminate
                    </button>
                  </div>
                </div>

                {/* Formatted JSON Arguments */}
                <div>
                  <div className="text-[10px] font-mono uppercase text-zinc-500 mb-1">
                    Intercepted Tool Arguments (JSON)
                  </div>
                  <pre className="p-2.5 rounded bg-[#09090B] border border-[#27272A] text-zinc-300 text-[11px] font-mono overflow-x-auto h-[160px]">
                    {JSON.stringify(item.args, null, 2)}
                  </pre>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Resolved History */}
      {resolvedItems.length > 0 && (
        <div className="bg-[#111113] border border-[#27272A] rounded p-3">
          <div className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider mb-2">
            Resolved Session Items
          </div>
          <div className="space-y-1.5">
            {resolvedItems.map((item) => (
              <div
                key={item.id}
                className="flex items-center justify-between text-xs font-mono p-2 rounded bg-[#09090B] border border-[#27272A]"
              >
                <div className="flex items-center gap-2">
                  <span className="text-zinc-400 font-semibold">{item.id}</span>
                  <span className="text-zinc-500">·</span>
                  <span className="text-zinc-300">{item.tool}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-semibold border ${
                      item.status === 'APPROVED'
                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                        : 'bg-red-500/10 text-red-400 border-red-500/20'
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
