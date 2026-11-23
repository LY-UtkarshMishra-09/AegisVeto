import React, { useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { ToolCall, Verdict, TaintState } from '../types';

interface StreamTableProps {
  toolCalls: ToolCall[];
}

export const StreamTable: React.FC<StreamTableProps> = ({ toolCalls }) => {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const toggleRow = (id: string) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  const getVerdictBadge = (verdict: Verdict) => {
    switch (verdict) {
      case 'ALLOW':
        return (
          <span className="font-mono text-[10px] font-medium px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            ALLOW
          </span>
        );
      case 'DENY':
        return (
          <span className="font-mono text-[10px] font-medium px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">
            DENY
          </span>
        );
      case 'QUARANTINE':
        return (
          <span className="font-mono text-[10px] font-medium px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
            QUARANTINE
          </span>
        );
    }
  };

  const getTaintBadge = (taint: TaintState) => {
    return taint === 'CLEAN' ? (
      <span className="font-mono text-[10px] text-emerald-400">CLEAN</span>
    ) : (
      <span className="font-mono text-[10px] font-medium text-red-400">TAINTED</span>
    );
  };

  return (
    <div className="bg-[#111113] border border-[#27272A] rounded overflow-hidden flex flex-col">
      <div className="p-3 border-b border-[#27272A] flex items-center justify-between">
        <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-500">
          Live Tool-Call Stream Table
        </span>
        <span className="text-[11px] font-mono text-zinc-500">
          Click any row to inspect AST &amp; JSON payload
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-[#27272A] bg-[#09090B]/60 text-[11px] font-mono text-zinc-400 uppercase">
              <th className="py-2 px-3 w-8"></th>
              <th className="py-2 px-3">Time</th>
              <th className="py-2 px-3">Session</th>
              <th className="py-2 px-3">Tool</th>
              <th className="py-2 px-3">Taint</th>
              <th className="py-2 px-3">Verdict</th>
              <th className="py-2 px-3">Latency</th>
              <th className="py-2 px-3">Reason</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#27272A] text-xs">
            {toolCalls.map((call) => {
              const isExpanded = expandedId === call.id;
              return (
                <React.Fragment key={call.id}>
                  <tr
                    onClick={() => toggleRow(call.id)}
                    className="hover:bg-[#18181B] cursor-pointer transition-colors font-mono select-none"
                  >
                    <td className="py-2 px-3 text-zinc-500">
                      {isExpanded ? (
                        <ChevronDown className="w-3.5 h-3.5 text-zinc-400" />
                      ) : (
                        <ChevronRight className="w-3.5 h-3.5 text-zinc-600" />
                      )}
                    </td>
                    <td className="py-2 px-3 text-zinc-400 whitespace-nowrap">{call.timestamp}</td>
                    <td className="py-2 px-3 text-zinc-300 font-semibold">{call.session}</td>
                    <td className="py-2 px-3 text-zinc-100 font-medium">
                      <span className="bg-zinc-800 px-1.5 py-0.5 rounded text-[11px] border border-zinc-700">
                        {call.tool}
                      </span>
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap">{getTaintBadge(call.taint)}</td>
                    <td className="py-2 px-3 whitespace-nowrap">{getVerdictBadge(call.verdict)}</td>
                    <td className="py-2 px-3 text-zinc-300 font-mono">{call.latencyMs.toFixed(2)}ms</td>
                    <td className="py-2 px-3 text-zinc-400 font-sans truncate max-w-[280px]">
                      {call.reason}
                    </td>
                  </tr>

                  {isExpanded && (
                    <tr className="bg-[#09090B]">
                      <td colSpan={8} className="p-3 border-t border-[#27272A]">
                        <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                          <div>
                            <div className="text-[10px] uppercase text-zinc-500 mb-1">
                              Intercepted Arguments (AST Normalized)
                            </div>
                            <pre className="p-2.5 rounded bg-[#111113] border border-[#27272A] text-zinc-300 text-[11px] overflow-x-auto">
                              {JSON.stringify(call.args, null, 2)}
                            </pre>
                          </div>
                          <div>
                            <div className="text-[10px] uppercase text-zinc-500 mb-1">
                              Proxy Response &amp; Security Metadata
                            </div>
                            <pre className="p-2.5 rounded bg-[#111113] border border-[#27272A] text-zinc-300 text-[11px] overflow-x-auto">
                              {JSON.stringify(
                                {
                                  verdict: call.verdict,
                                  taintState: call.taint,
                                  reason: call.reason,
                                  payload: call.responsePayload,
                                },
                                null,
                                2
                              )}
                            </pre>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
