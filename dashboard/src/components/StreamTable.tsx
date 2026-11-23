import React, { useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { ToolCall, Verdict, TaintState, LLMProvider } from '../types';

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
          <span className="font-mono text-[10px] font-semibold px-2 py-0.5 rounded bg-[#D4F849]/10 text-[#D4F849] border border-[#D4F849]/30">
            ALLOW
          </span>
        );
      case 'DENY':
        return (
          <span className="font-mono text-[10px] font-semibold px-2 py-0.5 rounded bg-[#F43F5E]/10 text-[#F43F5E] border border-[#F43F5E]/30">
            DENY
          </span>
        );
      case 'QUARANTINE':
        return (
          <span className="font-mono text-[10px] font-semibold px-2 py-0.5 rounded bg-[#F59E0B]/10 text-[#F59E0B] border border-[#F59E0B]/30">
            QUARANTINE
          </span>
        );
    }
  };

  const getTaintBadge = (taint: TaintState) => {
    return taint === 'CLEAN' ? (
      <span className="font-mono text-[10px] font-semibold text-[#D4F849]">CLEAN</span>
    ) : (
      <span className="font-mono text-[10px] font-semibold text-[#F43F5E]">TAINTED</span>
    );
  };

  const getProviderBadge = (provider: LLMProvider) => {
    return (
      <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-[#16221D] text-[#ECF2EE] border border-[#263830] uppercase">
        {provider}
      </span>
    );
  };

  return (
    <div className="bg-[#0E1317] border border-[#263830] rounded overflow-hidden flex flex-col">
      <div className="p-3 border-b border-[#263830] flex items-center justify-between">
        <span className="text-[11px] font-mono uppercase tracking-wider text-[#7E9489]">
          Live Tool-Call Stream Table
        </span>
        <span className="text-[11px] font-mono text-[#7E9489]">
          Click any row to expand JSON payload drawer
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-[#263830] bg-[#080B0E]/80 text-[11px] font-mono text-[#7E9489] uppercase">
              <th className="py-2.5 px-3 w-8"></th>
              <th className="py-2.5 px-3">Time</th>
              <th className="py-2.5 px-3">Session</th>
              <th className="py-2.5 px-3">Provider</th>
              <th className="py-2.5 px-3">Tool</th>
              <th className="py-2.5 px-3">Taint</th>
              <th className="py-2.5 px-3">Verdict</th>
              <th className="py-2.5 px-3">Latency</th>
              <th className="py-2.5 px-3">Reason</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#263830] text-xs">
            {toolCalls.length === 0 ? (
              <tr>
                <td colSpan={9} className="py-8 text-center text-[#7E9489] font-mono text-xs">
                  No tool calls recorded yet. Run a scenario to view real-time interception.
                </td>
              </tr>
            ) : (
              toolCalls.map((call) => {
                const isExpanded = expandedId === call.id;
                return (
                  <React.Fragment key={call.id}>
                    <tr
                      onClick={() => toggleRow(call.id)}
                      className="hover:bg-[#16221D]/50 cursor-pointer transition-colors font-mono select-none"
                    >
                      <td className="py-2.5 px-3 text-[#7E9489]">
                        {isExpanded ? (
                          <ChevronDown className="w-3.5 h-3.5 text-[#D4F849]" />
                        ) : (
                          <ChevronRight className="w-3.5 h-3.5 text-[#7E9489]" />
                        )}
                      </td>
                      <td className="py-2.5 px-3 text-[#7E9489] whitespace-nowrap">{call.timestamp}</td>
                      <td className="py-2.5 px-3 text-[#ECF2EE] font-semibold">{call.session}</td>
                      <td className="py-2.5 px-3 whitespace-nowrap">{getProviderBadge(call.provider)}</td>
                      <td className="py-2.5 px-3 text-[#ECF2EE] font-medium">
                        <span className="bg-[#16221D] px-1.5 py-0.5 rounded text-[11px] border border-[#263830]">
                          {call.tool}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">{getTaintBadge(call.taint)}</td>
                      <td className="py-2.5 px-3 whitespace-nowrap">{getVerdictBadge(call.verdict)}</td>
                      <td className="py-2.5 px-3 text-[#ECF2EE] font-mono">{call.latencyMs.toFixed(2)}ms</td>
                      <td className="py-2.5 px-3 text-[#7E9489] font-sans truncate max-w-[280px]">
                        {call.reason}
                      </td>
                    </tr>

                    {isExpanded && (
                      <tr className="bg-[#080B0E]">
                        <td colSpan={9} className="p-3 border-t border-[#263830]">
                          <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                            <div>
                              <div className="text-[10px] uppercase text-[#7E9489] mb-1">
                                Intercepted Arguments (AST Normalized)
                              </div>
                              <pre className="p-3 rounded bg-[#0E1317] border border-[#263830] text-[#ECF2EE] text-[11px] overflow-x-auto">
                                {JSON.stringify(call.args, null, 2)}
                              </pre>
                            </div>
                            <div>
                              <div className="text-[10px] uppercase text-[#7E9489] mb-1">
                                Proxy Response &amp; Security Metadata
                              </div>
                              <pre className="p-3 rounded bg-[#0E1317] border border-[#263830] text-[#ECF2EE] text-[11px] overflow-x-auto">
                                {JSON.stringify(
                                  {
                                    verdict: call.verdict,
                                    taintState: call.taint,
                                    provider: call.provider,
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
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
