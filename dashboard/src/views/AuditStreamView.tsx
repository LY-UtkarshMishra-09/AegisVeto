import React, { useState } from 'react';
import { AuditEvent } from '../types';
import { Search, CheckCircle2, XCircle, Terminal } from 'lucide-react';

interface AuditStreamViewProps {
  events: AuditEvent[];
}

export const AuditStreamView: React.FC<AuditStreamViewProps> = ({ events }) => {
  const [selectedEventId, setSelectedEventId] = useState<string | null>(events[0]?.id || null);
  const [search, setSearch] = useState('');
  const [verdictFilter, setVerdictFilter] = useState<string>('ALL');
  const [taintFilter, setTaintFilter] = useState<string>('ALL');
  const [agentFilter, setAgentFilter] = useState<string>('ALL');

  // Filter unique agents
  const agentsList = Array.from(new Set(events.map((e) => e.agent_id)));

  // Filter events
  const filteredEvents = events.filter((ev) => {
    if (verdictFilter !== 'ALL' && ev.verdict !== verdictFilter) return false;
    if (taintFilter !== 'ALL' && ev.taint_state !== taintFilter) return false;
    if (agentFilter !== 'ALL' && ev.agent_id !== agentFilter) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      const matchTool = ev.tool_name.toLowerCase().includes(q);
      const matchRule = ev.rule_matched.toLowerCase().includes(q);
      const matchAgent = ev.agent_id.toLowerCase().includes(q);
      const matchPayload = (ev.payload_json || '').toLowerCase().includes(q);
      if (!matchTool && !matchRule && !matchAgent && !matchPayload) return false;
    }
    return true;
  });

  const selectedEvent = events.find((e) => e.id === selectedEventId) || null;

  // Synthesize or extract 5-step vertical trace
  const getTraceSteps = (event: AuditEvent) => {
    const isDeny = event.verdict === 'DENY' || event.verdict === 'CRITICAL_TRIPWIRE';
    const isQuarantine = event.verdict === 'QUARANTINE';
    const isTripwire = event.verdict === 'CRITICAL_TRIPWIRE';

    return [
      {
        name: 'JWT Scope Verification',
        passed: !event.rule_matched.includes('JWT'),
        details: event.rule_matched.includes('JWT') ? event.rule_matched : 'Ed25519 signature valid & tool within authorized scopes',
      },
      {
        name: 'Schema Pin Integrity',
        passed: event.verdict !== 'SCHEMA_DRIFT',
        details: event.verdict === 'SCHEMA_DRIFT' ? 'Drift detected in tool schema hash' : 'Canonical SHA-256 schema pin verified',
      },
      {
        name: 'Taint Lattice Check',
        passed: !(event.rule_matched.includes('TAINT') || isTripwire),
        details: isTripwire ? 'Lattice collapsed: TERMINATED' : `Current state: ${event.taint_state}`,
      },
      {
        name: 'Policy Gate Resolution',
        passed: !(isDeny || isQuarantine),
        details: event.rule_matched,
      },
      {
        name: 'Target Tool Execution',
        passed: event.verdict === 'ALLOW' || event.verdict === 'SHADOW_DENY',
        details: event.verdict === 'ALLOW' ? `Executed '${event.tool_name}'` : event.verdict === 'SHADOW_DENY' ? 'Allowed under Shadow Mode' : 'Execution prevented (Fail-Closed)',
      },
    ];
  };

  return (
    <div className="flex flex-col h-full bg-[#000000] text-[#F4F6F8]">
      {/* Top Filter Toolbar */}
      <div className="h-12 border-b border-[#1E1E22] px-4 flex items-center gap-3 bg-[#000000] overflow-x-auto text-xs font-mono">
        {/* Search */}
        <div className="relative flex items-center min-w-[200px] max-w-[280px]">
          <Search className="w-3.5 h-3.5 absolute left-2.5 text-[#8E95A2]" />
          <input
            type="text"
            placeholder="Search tool, rule, payload..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-[#09090B] border border-[#1E1E22] pl-8 pr-3 py-1 text-xs text-[#F4F6F8] placeholder-[#8E95A2] focus:outline-none focus:border-[#4D8BFF]"
          />
        </div>

        {/* Verdict Filter */}
        <div className="flex items-center gap-1.5">
          <span className="text-[#8E95A2] text-[11px]">Verdict:</span>
          <select
            value={verdictFilter}
            onChange={(e) => setVerdictFilter(e.target.value)}
            className="bg-[#09090B] border border-[#1E1E22] px-2 py-1 text-xs text-[#F4F6F8] focus:outline-none focus:border-[#4D8BFF]"
          >
            <option value="ALL">ALL</option>
            <option value="ALLOW">ALLOW</option>
            <option value="DENY">DENY</option>
            <option value="QUARANTINE">QUARANTINE</option>
            <option value="SHADOW_DENY">SHADOW_DENY</option>
            <option value="SCHEMA_DRIFT">SCHEMA_DRIFT</option>
            <option value="CRITICAL_TRIPWIRE">CRITICAL_TRIPWIRE</option>
          </select>
        </div>

        {/* Taint Filter */}
        <div className="flex items-center gap-1.5">
          <span className="text-[#8E95A2] text-[11px]">Taint:</span>
          <select
            value={taintFilter}
            onChange={(e) => setTaintFilter(e.target.value)}
            className="bg-[#09090B] border border-[#1E1E22] px-2 py-1 text-xs text-[#F4F6F8] focus:outline-none focus:border-[#4D8BFF]"
          >
            <option value="ALL">ALL</option>
            <option value="CLEAN">CLEAN</option>
            <option value="TAINTED">TAINTED</option>
            <option value="TERMINATED">TERMINATED</option>
          </select>
        </div>

        {/* Agent Filter */}
        {agentsList.length > 0 && (
          <div className="flex items-center gap-1.5">
            <span className="text-[#8E95A2] text-[11px]">Agent:</span>
            <select
              value={agentFilter}
              onChange={(e) => setAgentFilter(e.target.value)}
              className="bg-[#09090B] border border-[#1E1E22] px-2 py-1 text-xs text-[#F4F6F8] focus:outline-none focus:border-[#4D8BFF]"
            >
              <option value="ALL">ALL</option>
              {agentsList.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>
          </div>
        )}

        <div className="ml-auto text-[11px] text-[#8E95A2] tabular-nums whitespace-nowrap">
          {filteredEvents.length} events
        </div>
      </div>

      {/* Main Asymmetric 8/4 Split */}
      <div className="grid grid-cols-1 lg:grid-cols-12 flex-1 min-h-0">
        {/* Left: Dense Audit Table (col-span-8) */}
        <div className="lg:col-span-8 border-r border-[#1E1E22] overflow-auto min-h-0 bg-[#000000]">
          {filteredEvents.length === 0 ? (
            <div className="h-64 flex flex-col items-center justify-center text-xs text-[#8E95A2] font-mono">
              No audit events matched current criteria.
            </div>
          ) : (
            <table className="w-full text-left text-xs border-collapse">
              <thead className="sticky top-0 bg-[#000000] z-10 border-b border-[#1E1E22]">
                <tr className="text-[#8E95A2] font-mono text-[11px]">
                  <th className="py-2.5 px-3 font-normal">Time</th>
                  <th className="py-2.5 px-3 font-normal">Agent</th>
                  <th className="py-2.5 px-3 font-normal">Target Tool</th>
                  <th className="py-2.5 px-3 font-normal">Taint</th>
                  <th className="py-2.5 px-3 font-normal">Verdict</th>
                  <th className="py-2.5 px-3 font-normal">Latency</th>
                  <th className="py-2.5 px-3 font-normal">Rule</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1E1E22] font-mono">
                {filteredEvents.map((ev) => {
                  const isSelected = ev.id === selectedEventId;
                  return (
                    <tr
                      key={ev.id}
                      onClick={() => setSelectedEventId(ev.id)}
                      className={`cursor-pointer transition-colors ${
                        isSelected ? 'bg-[#141417]' : 'hover:bg-[#09090B]'
                      }`}
                    >
                      <td className="py-2 px-3 text-[#8E95A2] tabular-nums whitespace-nowrap">
                        {new Date(ev.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </td>
                      <td className="py-2 px-3 text-[#F4F6F8] font-medium truncate max-w-[120px]">
                        {ev.agent_id}
                      </td>
                      <td className="py-2 px-3 text-[#F4F6F8] truncate max-w-[140px]">
                        {ev.tool_name}
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap">
                        <span
                          className={`text-[10px] px-1.5 py-0.2 border ${
                            ev.taint_state === 'CLEAN'
                              ? 'border-[#1E1E22] text-[#8E95A2]'
                              : ev.taint_state === 'TAINTED'
                              ? 'border-[#EF4444] text-[#EF4444] bg-[#EF4444]/10'
                              : 'border-[#EF4444] text-[#EF4444] bg-[#EF4444]/20 font-bold'
                          }`}
                        >
                          {ev.taint_state}
                        </span>
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap">
                        <span
                          className={`text-[10px] px-1.5 py-0.2 border ${
                            ev.verdict === 'ALLOW'
                              ? 'border-[#1E1E22] text-[#F4F6F8]'
                              : ev.verdict === 'DENY' || ev.verdict === 'CRITICAL_TRIPWIRE'
                              ? 'border-[#EF4444] text-[#EF4444] bg-[#EF4444]/10'
                              : ev.verdict === 'QUARANTINE'
                              ? 'border-[#F59E0B] text-[#F59E0B] bg-[#F59E0B]/10'
                              : 'border-[#F59E0B] text-[#F59E0B]'
                          }`}
                        >
                          {ev.verdict}
                        </span>
                      </td>
                      <td className="py-2 px-3 text-[#8E95A2] tabular-nums whitespace-nowrap">
                        {ev.latency_ms.toFixed(2)} ms
                      </td>
                      <td className="py-2 px-3 text-[#8E95A2] truncate max-w-[160px]" title={ev.rule_matched}>
                        {ev.rule_matched}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* Right: Fixed Trace Inspector (col-span-4 bg-[#09090B]) */}
        <div className="lg:col-span-4 bg-[#09090B] flex flex-col min-h-0 overflow-y-auto divide-y divide-[#1E1E22]">
          {selectedEvent ? (
            <>
              {/* Header */}
              <div className="p-4 bg-[#000000]">
                <div className="text-[10px] font-mono text-[#8E95A2] uppercase tracking-wider mb-1">
                  Trace Inspector
                </div>
                <div className="text-sm font-mono font-medium text-[#F4F6F8] truncate">
                  {selectedEvent.tool_name}
                </div>
                <div className="text-[11px] font-mono text-[#8E95A2] mt-0.5 truncate">
                  ID: {selectedEvent.id}
                </div>
              </div>

              {/* 5-Step Vertical Pipeline Trace */}
              <div className="p-4 space-y-3">
                <div className="text-[11px] font-mono text-[#8E95A2] uppercase tracking-wider mb-2">
                  5-Step Pipeline Verification
                </div>

                <div className="space-y-2.5 font-mono text-xs">
                  {getTraceSteps(selectedEvent).map((step, idx) => (
                    <div
                      key={step.name}
                      className="p-2.5 border border-[#1E1E22] bg-[#000000] flex items-start gap-2.5"
                    >
                      <div className="mt-0.5">
                        {step.passed ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-[#4D8BFF]" />
                        ) : (
                          <XCircle className="w-3.5 h-3.5 text-[#EF4444]" />
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between">
                          <span className="font-medium text-[#F4F6F8]">{step.name}</span>
                          <span className="text-[10px] text-[#8E95A2]">Stage {idx + 1}</span>
                        </div>
                        <div className="text-[11px] text-[#8E95A2] mt-0.5 break-words">
                          {step.details}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Raw JSON Payload */}
              <div className="p-4 flex-1 flex flex-col min-h-[200px]">
                <div className="text-[11px] font-mono text-[#8E95A2] uppercase tracking-wider mb-2 flex items-center justify-between">
                  <span>Raw Request Payload</span>
                  <Terminal className="w-3.5 h-3.5 text-[#8E95A2]" />
                </div>
                <div className="p-3 bg-[#000000] border border-[#1E1E22] font-mono text-xs text-[#F4F6F8] overflow-auto flex-1 max-h-[300px]">
                  <pre className="whitespace-pre-wrap break-all">
                    {(() => {
                      try {
                        return JSON.stringify(JSON.parse(selectedEvent.payload_json || '{}'), null, 2);
                      } catch {
                        return selectedEvent.payload_json || '{}';
                      }
                    })()}
                  </pre>
                </div>
              </div>
            </>
          ) : (
            <div className="h-full flex items-center justify-center p-8 text-center text-xs text-[#8E95A2] font-mono">
              Select an event from the audit stream to inspect trace pipeline and arguments.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
