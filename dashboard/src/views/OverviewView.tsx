import React from 'react';
import { OverviewData, Agent, Upstream } from '../types';
import { ShieldCheck, Cpu, Network, ArrowRight } from 'lucide-react';

interface OverviewViewProps {
  overview: OverviewData | null;
  agents: Agent[];
  upstreams: Upstream[];
  onNavigate: (route: string) => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  overview,
  agents,
  upstreams,
  onNavigate,
}) => {
  const totalCalls = overview?.total ?? 0;
  const activeAgents = overview?.activeAgents ?? agents.filter((a) => a.status === 'active').length;
  const incidents = overview?.activeIncidents ?? 0;
  const p95Latency = overview?.p95LatencyMs ?? 0;
  const recentBlocked = overview?.recentBlocked ?? [];

  return (
    <div className="flex flex-col h-full bg-[#000000] text-[#F4F6F8]">
      {/* Flush 4-Column Metric Strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 divide-x divide-[#1E1E22] border-b border-[#1E1E22] bg-[#000000]">
        <div className="p-4 sm:p-5">
          <div className="text-xs text-[#8E95A2] font-mono tracking-tight mb-1">Active Agents</div>
          <div className="text-2xl font-mono font-medium tracking-tight text-[#F4F6F8] tabular-nums">
            {activeAgents}
          </div>
          <div className="text-[11px] text-[#8E95A2] mt-1 font-mono">Registered identities</div>
        </div>

        <div className="p-4 sm:p-5">
          <div className="text-xs text-[#8E95A2] font-mono tracking-tight mb-1">24h Tool Calls</div>
          <div className="text-2xl font-mono font-medium tracking-tight text-[#F4F6F8] tabular-nums">
            {totalCalls.toLocaleString()}
          </div>
          <div className="text-[11px] text-[#8E95A2] mt-1 font-mono">Data plane throughput</div>
        </div>

        <div className="p-4 sm:p-5">
          <div className="text-xs text-[#8E95A2] font-mono tracking-tight mb-1">Vetoed / Drift Incidents</div>
          <div className={`text-2xl font-mono font-medium tracking-tight tabular-nums ${incidents > 0 ? 'text-[#EF4444]' : 'text-[#F4F6F8]'}`}>
            {incidents}
          </div>
          <div className="text-[11px] text-[#8E95A2] mt-1 font-mono">Blocked & quarantined</div>
        </div>

        <div className="p-4 sm:p-5">
          <div className="text-xs text-[#8E95A2] font-mono tracking-tight mb-1">Layer 1 p95 Latency</div>
          <div className="text-2xl font-mono font-medium tracking-tight text-[#4D8BFF] tabular-nums">
            {p95Latency.toFixed(2)} ms
          </div>
          <div className="text-[11px] text-[#8E95A2] mt-1 font-mono">&lt;10ms deterministic SLA</div>
        </div>
      </div>

      {/* Main 2-Column Split */}
      <div className="grid grid-cols-1 lg:grid-cols-12 flex-1 min-h-0">
        {/* Left: Recent Security Incidents & Blocked Calls (col-span-8) */}
        <div className="lg:col-span-8 border-r border-[#1E1E22] flex flex-col min-h-0 bg-[#000000]">
          <div className="h-10 px-5 flex items-center justify-between border-b border-[#1E1E22]">
            <span className="text-xs font-mono font-medium text-[#F4F6F8] tracking-wider uppercase">
              Recent Security Incidents & Blocked Calls
            </span>
            <button
              onClick={() => onNavigate('logs')}
              className="text-xs text-[#8E95A2] hover:text-[#F4F6F8] flex items-center gap-1 font-mono transition-colors"
            >
              View Full Audit Log
              <ArrowRight className="w-3 h-3 text-[#8E95A2]" />
            </button>
          </div>

          <div className="flex-1 overflow-auto">
            {recentBlocked.length === 0 ? (
              <div className="h-48 flex flex-col items-center justify-center text-xs text-[#8E95A2] font-mono">
                <ShieldCheck className="w-6 h-6 text-[#8E95A2] mb-2 stroke-1" />
                No security violations detected in the last 24 hours.
              </div>
            ) : (
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-[#1E1E22] text-[#8E95A2] font-mono text-[11px]">
                    <th className="py-2.5 px-4 font-normal">Timestamp</th>
                    <th className="py-2.5 px-4 font-normal">Agent</th>
                    <th className="py-2.5 px-4 font-normal">Target Tool</th>
                    <th className="py-2.5 px-4 font-normal">Verdict</th>
                    <th className="py-2.5 px-4 font-normal">Rule Matched</th>
                    <th className="py-2.5 px-4 font-normal text-right">Latency</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1E1E22] font-mono">
                  {recentBlocked.map((ev) => (
                    <tr
                      key={ev.id}
                      onClick={() => onNavigate('logs')}
                      className="hover:bg-[#141417] cursor-pointer transition-colors"
                    >
                      <td className="py-2.5 px-4 text-[#8E95A2] tabular-nums whitespace-nowrap">
                        {new Date(ev.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </td>
                      <td className="py-2.5 px-4 text-[#F4F6F8] font-medium">{ev.agentId}</td>
                      <td className="py-2.5 px-4 text-[#8E95A2]">{ev.toolName}</td>
                      <td className="py-2.5 px-4">
                        <span
                          className={`px-1.5 py-0.5 text-[10px] border ${
                            ev.verdict === 'DENY' || ev.verdict === 'CRITICAL_TRIPWIRE'
                              ? 'border-[#EF4444] text-[#EF4444] bg-[#EF4444]/10'
                              : ev.verdict === 'SHADOW_DENY'
                              ? 'border-[#F59E0B] text-[#F59E0B] bg-[#F59E0B]/10'
                              : 'border-[#1E1E22] text-[#8E95A2]'
                          }`}
                        >
                          {ev.verdict}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-[#8E95A2] max-w-[200px] truncate" title={ev.ruleMatched}>
                        {ev.ruleMatched}
                      </td>
                      <td className="py-2.5 px-4 text-right text-[#8E95A2] tabular-nums">
                        {ev.latencyMs.toFixed(2)} ms
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Right: Agent Posture & Active Upstreams (col-span-4 bg-[#09090B]) */}
        <div className="lg:col-span-4 bg-[#09090B] flex flex-col min-h-0 divide-y divide-[#1E1E22]">
          {/* Agent Posture Section */}
          <div className="p-5">
            <div className="flex items-center justify-between mb-3">
              <div className="text-xs font-mono font-medium text-[#F4F6F8] flex items-center gap-1.5 uppercase">
                <Cpu className="w-3.5 h-3.5 text-[#4D8BFF]" />
                Agent Posture
              </div>
              <button
                onClick={() => onNavigate('inventory')}
                className="text-[11px] text-[#8E95A2] hover:text-[#F4F6F8] font-mono"
              >
                Manage
              </button>
            </div>

            <div className="space-y-2">
              {agents.length === 0 ? (
                <div className="text-xs text-[#8E95A2] font-mono py-2">No agents registered</div>
              ) : (
                agents.map((agent) => (
                  <div
                    key={agent.id}
                    className="flex items-center justify-between p-2.5 border border-[#1E1E22] bg-[#000000]"
                  >
                    <div>
                      <div className="text-xs font-mono text-[#F4F6F8] font-medium">{agent.id}</div>
                      <div className="text-[10px] text-[#8E95A2] font-mono truncate max-w-[160px]">
                        {agent.name}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span
                        className={`text-[10px] font-mono px-1.5 py-0.5 border ${
                          agent.mode === 'enforce'
                            ? 'border-[#2563EB] text-[#4D8BFF] bg-[#2563EB]/10'
                            : 'border-[#F59E0B] text-[#F59E0B] bg-[#F59E0B]/10'
                        }`}
                      >
                        {agent.mode}
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Active Upstreams Section */}
          <div className="p-5 flex-1 min-h-0 overflow-auto">
            <div className="flex items-center justify-between mb-3">
              <div className="text-xs font-mono font-medium text-[#F4F6F8] flex items-center gap-1.5 uppercase">
                <Network className="w-3.5 h-3.5 text-[#4D8BFF]" />
                Active Upstreams
              </div>
              <button
                onClick={() => onNavigate('inventory')}
                className="text-[11px] text-[#8E95A2] hover:text-[#F4F6F8] font-mono"
              >
                Inspect
              </button>
            </div>

            <div className="space-y-2">
              {upstreams.length === 0 ? (
                <div className="text-xs text-[#8E95A2] font-mono py-2">No upstreams configured</div>
              ) : (
                upstreams.map((ups) => (
                  <div
                    key={ups.id}
                    className="p-2.5 border border-[#1E1E22] bg-[#000000] flex flex-col gap-1"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono text-[#F4F6F8] font-medium">{ups.name}</span>
                      <span
                        className={`text-[10px] font-mono px-1.5 py-0.5 border ${
                          ups.trust_tier === 'trusted'
                            ? 'border-[#1E1E22] text-[#8E95A2]'
                            : ups.trust_tier === 'egress'
                            ? 'border-[#F59E0B] text-[#F59E0B] bg-[#F59E0B]/10'
                            : 'border-[#EF4444] text-[#EF4444] bg-[#EF4444]/10'
                        }`}
                      >
                        {ups.trust_tier}
                      </span>
                    </div>
                    <div className="text-[10px] text-[#8E95A2] font-mono truncate" title={ups.command_or_url}>
                      {ups.transport.toUpperCase()}: {ups.command_or_url}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
