import React, { useState, useEffect } from 'react';
import { Agent, Upstream, SchemaPin } from '../types';
import { Cpu, Network, Key, Plus, Check, Copy, ArrowRight, X } from 'lucide-react';

interface InventoryViewProps {
  agents: Agent[];
  upstreams: Upstream[];
  onToggleAgentMode: (agentId: string, newMode: 'enforce' | 'shadow') => Promise<void>;
  onCreateAgent: (agent: { id: string; name: string; mode: 'enforce' | 'shadow'; allowedUpstreams: string[] }) => Promise<void>;
  onCreateUpstream: (upstream: { id: string; name: string; transport: 'stdio' | 'http'; commandOrUrl: string; trustTier: 'trusted' | 'untrusted' | 'egress' }) => Promise<void>;
}

export const InventoryView: React.FC<InventoryViewProps> = ({
  agents,
  upstreams,
  onToggleAgentMode,
  onCreateAgent,
  onCreateUpstream,
}) => {
  const [activeTab, setActiveTab] = useState<'agents' | 'upstreams'>('agents');

  // Token Minting Modal State
  const [mintModalAgent, setMintModalAgent] = useState<Agent | null>(null);
  const [mintedToken, setMintedToken] = useState<string | null>(null);
  const [mintExpiresAt, setMintExpiresAt] = useState<string | null>(null);
  const [copiedToken, setCopiedToken] = useState(false);
  const [isMinting, setIsMinting] = useState(false);

  // New Agent Drawer State
  const [showNewAgentDrawer, setShowNewAgentDrawer] = useState(false);
  const [newAgentId, setNewAgentId] = useState('');
  const [newAgentName, setNewAgentName] = useState('');
  const [newAgentMode, setNewAgentMode] = useState<'enforce' | 'shadow'>('enforce');
  const [newAgentUpstreams, setNewAgentUpstreams] = useState<string[]>(['*']);

  // New Upstream Drawer State
  const [showNewUpstreamDrawer, setShowNewUpstreamDrawer] = useState(false);
  const [newUpstreamId, setNewUpstreamId] = useState('');
  const [newUpstreamName, setNewUpstreamName] = useState('');
  const [newUpstreamTransport, setNewUpstreamTransport] = useState<'stdio' | 'http'>('stdio');
  const [newUpstreamCommand, setNewUpstreamCommand] = useState('');
  const [newUpstreamTrust, setNewUpstreamTrust] = useState<'trusted' | 'untrusted' | 'egress'>('trusted');

  // Pins state per upstream
  const [pinsMap, setPinsMap] = useState<Record<string, SchemaPin[]>>({});
  const [expandedUpstreamId, setExpandedUpstreamId] = useState<string | null>(null);

  // Load pins for expanded upstream
  useEffect(() => {
    if (expandedUpstreamId && !pinsMap[expandedUpstreamId]) {
      fetch(`http://localhost:3000/v1/upstreams/${expandedUpstreamId}/pins`)
        .then((res) => (res.ok ? res.json() : []))
        .then((pins) => {
          setPinsMap((prev) => ({ ...prev, [expandedUpstreamId]: pins }));
        })
        .catch(() => {});
    }
  }, [expandedUpstreamId, pinsMap]);

  const handleMintToken = async (agent: Agent) => {
    setIsMinting(true);
    try {
      const res = await fetch(`http://localhost:3000/v1/agents/${agent.id}/tokens`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ allowedScopes: ['*'], maxCalls: 100, ttlSec: 3600 }),
      });
      if (res.ok) {
        const data = await res.json();
        setMintedToken(data.token);
        setMintExpiresAt(data.expires_at);
      }
    } finally {
      setIsMinting(false);
    }
  };

  const handleApprovePin = async (upstreamId: string, pinId: string) => {
    const res = await fetch(`http://localhost:3000/v1/upstreams/${upstreamId}/pins/${pinId}/approve`, {
      method: 'POST',
    });
    if (res.ok) {
      // Reload pins
      const updated = await fetch(`http://localhost:3000/v1/upstreams/${upstreamId}/pins`).then((r) => r.json());
      setPinsMap((prev) => ({ ...prev, [upstreamId]: updated }));
    }
  };

  return (
    <div className="flex flex-col h-full bg-[#000000] text-[#F4F6F8]">
      {/* Sub-header Tab Bar */}
      <div className="h-11 border-b border-[#1E1E22] px-5 flex items-center justify-between bg-[#000000]">
        <div className="flex items-center gap-6 text-xs font-mono">
          <button
            onClick={() => setActiveTab('agents')}
            className={`h-11 flex items-center gap-2 border-b-2 font-medium transition-colors ${
              activeTab === 'agents'
                ? 'border-[#2563EB] text-[#F4F6F8]'
                : 'border-transparent text-[#8E95A2] hover:text-[#F4F6F8]'
            }`}
          >
            <Cpu className="w-3.5 h-3.5" />
            Registered Agents ({agents.length})
          </button>

          <button
            onClick={() => setActiveTab('upstreams')}
            className={`h-11 flex items-center gap-2 border-b-2 font-medium transition-colors ${
              activeTab === 'upstreams'
                ? 'border-[#2563EB] text-[#F4F6F8]'
                : 'border-transparent text-[#8E95A2] hover:text-[#F4F6F8]'
            }`}
          >
            <Network className="w-3.5 h-3.5" />
            Upstreams & Schema Pins ({upstreams.length})
          </button>
        </div>

        {activeTab === 'agents' ? (
          <button
            onClick={() => setShowNewAgentDrawer(true)}
            className="px-2.5 py-1 bg-[#2563EB] hover:bg-[#1D4ED8] text-[#F4F6F8] text-xs font-mono font-medium flex items-center gap-1.5 transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            Register Agent
          </button>
        ) : (
          <button
            onClick={() => setShowNewUpstreamDrawer(true)}
            className="px-2.5 py-1 bg-[#2563EB] hover:bg-[#1D4ED8] text-[#F4F6F8] text-xs font-mono font-medium flex items-center gap-1.5 transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            Register Upstream
          </button>
        )}
      </div>

      {/* Main Tab Content */}
      <div className="flex-1 overflow-auto bg-[#000000]">
        {activeTab === 'agents' ? (
          /* AGENTS TABLE */
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-[#1E1E22] text-[#8E95A2] font-mono text-[11px] bg-[#000000]">
                <th className="py-2.5 px-5 font-normal">Agent ID</th>
                <th className="py-2.5 px-5 font-normal">Display Name</th>
                <th className="py-2.5 px-5 font-normal">Enforcement Posture</th>
                <th className="py-2.5 px-5 font-normal">Allowed Upstreams</th>
                <th className="py-2.5 px-5 font-normal">Key Fingerprint</th>
                <th className="py-2.5 px-5 font-normal text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E1E22] font-mono">
              {agents.map((agent) => (
                <tr key={agent.id} className="hover:bg-[#09090B] transition-colors">
                  <td className="py-3 px-5 text-[#F4F6F8] font-medium">{agent.id}</td>
                  <td className="py-3 px-5 text-[#8E95A2]">{agent.name}</td>
                  <td className="py-3 px-5">
                    <div className="inline-flex border border-[#1E1E22] bg-[#09090B]">
                      <button
                        onClick={() => onToggleAgentMode(agent.id, 'enforce')}
                        className={`px-2 py-0.5 text-[10px] transition-colors ${
                          agent.mode === 'enforce'
                            ? 'bg-[#2563EB] text-[#F4F6F8] font-medium'
                            : 'text-[#8E95A2] hover:text-[#F4F6F8]'
                        }`}
                      >
                        Enforce
                      </button>
                      <button
                        onClick={() => onToggleAgentMode(agent.id, 'shadow')}
                        className={`px-2 py-0.5 text-[10px] transition-colors ${
                          agent.mode === 'shadow'
                            ? 'bg-[#F59E0B] text-[#000000] font-medium'
                            : 'text-[#8E95A2] hover:text-[#F4F6F8]'
                        }`}
                      >
                        Shadow
                      </button>
                    </div>
                  </td>
                  <td className="py-3 px-5 text-[#8E95A2]">
                    {Array.isArray(agent.allowed_upstreams)
                      ? agent.allowed_upstreams.join(', ')
                      : 'all (*)'}
                  </td>
                  <td className="py-3 px-5 text-[#8E95A2] tabular-nums">
                    {agent.key_fingerprint || 'ed25519-default'}
                  </td>
                  <td className="py-3 px-5 text-right">
                    <button
                      onClick={() => {
                        setMintModalAgent(agent);
                        setMintedToken(null);
                        handleMintToken(agent);
                      }}
                      className="px-2 py-1 border border-[#1E1E22] hover:border-[#4D8BFF] text-[#F4F6F8] text-[11px] inline-flex items-center gap-1.5 transition-colors"
                    >
                      <Key className="w-3 h-3 text-[#4D8BFF]" />
                      Mint Token
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          /* UPSTREAMS & SCHEMA PINS TABLE */
          <div className="divide-y divide-[#1E1E22]">
            {upstreams.map((ups) => {
              const isExpanded = expandedUpstreamId === ups.id;
              const pins = pinsMap[ups.id] || [];
              return (
                <div key={ups.id} className="bg-[#000000]">
                  <div
                    onClick={() => setExpandedUpstreamId(isExpanded ? null : ups.id)}
                    className="p-4 hover:bg-[#09090B] cursor-pointer flex items-center justify-between transition-colors"
                  >
                    <div className="flex items-center gap-4">
                      <div>
                        <div className="text-xs font-mono font-medium text-[#F4F6F8] flex items-center gap-2">
                          {ups.name}
                          <span
                            className={`text-[10px] px-1.5 py-0.2 border ${
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
                        <div className="text-[11px] font-mono text-[#8E95A2] mt-0.5">
                          ID: {ups.id} | {ups.transport.toUpperCase()}: {ups.command_or_url}
                        </div>
                      </div>
                    </div>

                    <div className="text-xs font-mono text-[#8E95A2] flex items-center gap-3">
                      <span>{pins.length > 0 ? `${pins.length} schema pins` : 'Expand pins'}</span>
                      <ArrowRight
                        className={`w-3.5 h-3.5 transform transition-transform ${
                          isExpanded ? 'rotate-90 text-[#4D8BFF]' : 'text-[#8E95A2]'
                        }`}
                      />
                    </div>
                  </div>

                  {/* Expanded Schema Pins */}
                  {isExpanded && (
                    <div className="bg-[#09090B] border-t border-[#1E1E22] p-4">
                      <div className="text-xs font-mono font-medium text-[#F4F6F8] mb-3 flex items-center justify-between">
                        <span>Pinned Tool Schemas (SHA-256)</span>
                        <span className="text-[11px] text-[#8E95A2]">Drift Protection Active</span>
                      </div>

                      {pins.length === 0 ? (
                        <div className="text-xs font-mono text-[#8E95A2] py-2">
                          No schemas pinned yet. Tools will be automatically pinned on first invocation.
                        </div>
                      ) : (
                        <div className="space-y-2 font-mono text-xs">
                          {pins.map((pin) => (
                            <div
                              key={pin.id}
                              className={`p-3 border bg-[#000000] flex flex-col gap-2 ${
                                pin.drift_detected ? 'border-[#EF4444]' : 'border-[#1E1E22]'
                              }`}
                            >
                              <div className="flex items-center justify-between">
                                <div className="font-medium text-[#F4F6F8]">{pin.tool_name}</div>
                                <div className="flex items-center gap-2">
                                  {pin.drift_detected ? (
                                    <span className="text-[10px] px-1.5 py-0.5 border border-[#EF4444] text-[#EF4444] bg-[#EF4444]/10">
                                      DRIFT DETECTED
                                    </span>
                                  ) : (
                                    <span className="text-[10px] px-1.5 py-0.5 border border-[#1E1E22] text-[#8E95A2]">
                                      PINNED
                                    </span>
                                  )}
                                  {pin.drift_detected ? (
                                    <button
                                      onClick={() => handleApprovePin(ups.id, pin.id)}
                                      className="px-2 py-0.5 bg-[#2563EB] hover:bg-[#1D4ED8] text-[#F4F6F8] text-[10px]"
                                    >
                                      Approve New Hash
                                    </button>
                                  ) : null}
                                </div>
                              </div>

                              <div className="text-[11px] text-[#8E95A2] truncate">
                                SHA-256: <span className="text-[#F4F6F8]">{pin.sha256_hash}</span>
                              </div>

                              {pin.drift_diff && (
                                <div className="p-2.5 border border-[#EF4444]/40 bg-[#EF4444]/5 text-xs font-mono space-y-1">
                                  <div className="text-[#EF4444] font-medium">
                                    {pin.drift_diff.diffSummary || 'Schema drift detected'}
                                  </div>
                                  <pre className="text-[10px] text-[#8E95A2] overflow-auto max-h-28 whitespace-pre-wrap">
                                    {JSON.stringify(pin.drift_diff, null, 2)}
                                  </pre>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Mint JWT Token Modal */}
      {mintModalAgent && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="w-full max-w-lg bg-[#09090B] border border-[#1E1E22] p-5 font-mono text-xs space-y-4">
            <div className="flex items-center justify-between border-b border-[#1E1E22] pb-3">
              <span className="font-medium text-[#F4F6F8] flex items-center gap-1.5">
                <Key className="w-4 h-4 text-[#4D8BFF]" />
                Mint Scoped JWT ({mintModalAgent.id})
              </span>
              <button
                onClick={() => setMintModalAgent(null)}
                className="text-[#8E95A2] hover:text-[#F4F6F8]"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div>
              <div className="text-[#8E95A2] mb-1">Generated Ed25519 Token:</div>
              <div className="p-3 bg-[#000000] border border-[#1E1E22] break-all text-[#F4F6F8] font-mono text-[11px] max-h-36 overflow-auto">
                {isMinting ? 'Minting cryptographic token...' : mintedToken || 'Error generating token'}
              </div>
            </div>

            {mintExpiresAt && (
              <div className="text-[#8E95A2] text-[11px]">
                Valid until: <span className="text-[#F4F6F8]">{new Date(mintExpiresAt).toLocaleString()}</span>
              </div>
            )}

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-[#1E1E22]">
              <button
                disabled={!mintedToken}
                onClick={() => {
                  if (mintedToken) {
                    navigator.clipboard.writeText(mintedToken);
                    setCopiedToken(true);
                    setTimeout(() => setCopiedToken(false), 2000);
                  }
                }}
                className="px-3 py-1.5 bg-[#2563EB] hover:bg-[#1D4ED8] text-[#F4F6F8] flex items-center gap-1.5"
              >
                {copiedToken ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                {copiedToken ? 'Copied' : 'Copy Token'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Register Agent Drawer */}
      {showNewAgentDrawer && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="w-full max-w-md bg-[#09090B] border border-[#1E1E22] p-5 font-mono text-xs space-y-4">
            <div className="flex items-center justify-between border-b border-[#1E1E22] pb-3">
              <span className="font-medium text-[#F4F6F8]">Register New Agent</span>
              <button onClick={() => setShowNewAgentDrawer(false)} className="text-[#8E95A2] hover:text-[#F4F6F8]">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div>
              <label className="text-[#8E95A2] block mb-1">Agent ID</label>
              <input
                type="text"
                placeholder="e.g. data-pipeline-agent"
                value={newAgentId}
                onChange={(e) => setNewAgentId(e.target.value)}
                className="w-full bg-[#000000] border border-[#1E1E22] px-3 py-1.5 text-xs text-[#F4F6F8] focus:outline-none focus:border-[#4D8BFF]"
              />
            </div>

            <div>
              <label className="text-[#8E95A2] block mb-1">Display Name</label>
              <input
                type="text"
                placeholder="e.g. Production Data Pipeline Worker"
                value={newAgentName}
                onChange={(e) => setNewAgentName(e.target.value)}
                className="w-full bg-[#000000] border border-[#1E1E22] px-3 py-1.5 text-xs text-[#F4F6F8] focus:outline-none focus:border-[#4D8BFF]"
              />
            </div>

            <div>
              <label className="text-[#8E95A2] block mb-1">Enforcement Posture</label>
              <select
                value={newAgentMode}
                onChange={(e) => setNewAgentMode(e.target.value as 'enforce' | 'shadow')}
                className="w-full bg-[#000000] border border-[#1E1E22] px-3 py-1.5 text-xs text-[#F4F6F8] focus:outline-none focus:border-[#4D8BFF]"
              >
                <option value="enforce">Enforce (Block & Quarantine)</option>
                <option value="shadow">Shadow (Log & Allow)</option>
              </select>
            </div>

            <div>
              <label className="text-[#8E95A2] block mb-1">Allowed Upstreams (comma-separated)</label>
              <input
                type="text"
                placeholder="*, local-filesystem, external-comms"
                value={newAgentUpstreams.join(', ')}
                onChange={(e) =>
                  setNewAgentUpstreams(
                    e.target.value
                      .split(',')
                      .map((s) => s.trim())
                      .filter(Boolean)
                  )
                }
                className="w-full bg-[#000000] border border-[#1E1E22] px-3 py-1.5 text-xs text-[#F4F6F8] focus:outline-none focus:border-[#4D8BFF]"
              />
            </div>

            <div className="flex items-center justify-end gap-2 pt-3 border-t border-[#1E1E22]">
              <button
                onClick={() => setShowNewAgentDrawer(false)}
                className="px-3 py-1.5 border border-[#1E1E22] text-[#8E95A2] hover:text-[#F4F6F8]"
              >
                Cancel
              </button>
              <button
                disabled={!newAgentId.trim()}
                onClick={async () => {
                  if (newAgentId.trim()) {
                    await onCreateAgent({
                      id: newAgentId.trim(),
                      name: newAgentName.trim() || newAgentId.trim(),
                      mode: newAgentMode,
                      allowedUpstreams: newAgentUpstreams,
                    });
                    setShowNewAgentDrawer(false);
                    setNewAgentId('');
                    setNewAgentName('');
                  }
                }}
                className="px-3 py-1.5 bg-[#2563EB] hover:bg-[#1D4ED8] text-[#F4F6F8] font-medium disabled:opacity-50"
              >
                Create Agent
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Register Upstream Drawer */}
      {showNewUpstreamDrawer && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="w-full max-w-md bg-[#09090B] border border-[#1E1E22] p-5 font-mono text-xs space-y-4">
            <div className="flex items-center justify-between border-b border-[#1E1E22] pb-3">
              <span className="font-medium text-[#F4F6F8]">Register New Upstream</span>
              <button onClick={() => setShowNewUpstreamDrawer(false)} className="text-[#8E95A2] hover:text-[#F4F6F8]">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div>
              <label className="text-[#8E95A2] block mb-1">Upstream ID</label>
              <input
                type="text"
                placeholder="e.g. git-mcp-server"
                value={newUpstreamId}
                onChange={(e) => setNewUpstreamId(e.target.value)}
                className="w-full bg-[#000000] border border-[#1E1E22] px-3 py-1.5 text-xs text-[#F4F6F8] focus:outline-none focus:border-[#4D8BFF]"
              />
            </div>

            <div>
              <label className="text-[#8E95A2] block mb-1">Display Name</label>
              <input
                type="text"
                placeholder="e.g. Git Operations Service"
                value={newUpstreamName}
                onChange={(e) => setNewUpstreamName(e.target.value)}
                className="w-full bg-[#000000] border border-[#1E1E22] px-3 py-1.5 text-xs text-[#F4F6F8] focus:outline-none focus:border-[#4D8BFF]"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-[#8E95A2] block mb-1">Transport</label>
                <select
                  value={newUpstreamTransport}
                  onChange={(e) => setNewUpstreamTransport(e.target.value as 'stdio' | 'http')}
                  className="w-full bg-[#000000] border border-[#1E1E22] px-3 py-1.5 text-xs text-[#F4F6F8] focus:outline-none focus:border-[#4D8BFF]"
                >
                  <option value="stdio">stdio (subprocess)</option>
                  <option value="http">http (remote)</option>
                </select>
              </div>

              <div>
                <label className="text-[#8E95A2] block mb-1">Trust Tier</label>
                <select
                  value={newUpstreamTrust}
                  onChange={(e) => setNewUpstreamTrust(e.target.value as 'trusted' | 'untrusted' | 'egress')}
                  className="w-full bg-[#000000] border border-[#1E1E22] px-3 py-1.5 text-xs text-[#F4F6F8] focus:outline-none focus:border-[#4D8BFF]"
                >
                  <option value="trusted">Trusted (Internal)</option>
                  <option value="untrusted">Untrusted (Taints Session)</option>
                  <option value="egress">Egress (Sink)</option>
                </select>
              </div>
            </div>

            <div>
              <label className="text-[#8E95A2] block mb-1">Command or URL</label>
              <input
                type="text"
                placeholder="npx -y @modelcontextprotocol/server-git"
                value={newUpstreamCommand}
                onChange={(e) => setNewUpstreamCommand(e.target.value)}
                className="w-full bg-[#000000] border border-[#1E1E22] px-3 py-1.5 text-xs text-[#F4F6F8] focus:outline-none focus:border-[#4D8BFF]"
              />
            </div>

            <div className="flex items-center justify-end gap-2 pt-3 border-t border-[#1E1E22]">
              <button
                onClick={() => setShowNewUpstreamDrawer(false)}
                className="px-3 py-1.5 border border-[#1E1E22] text-[#8E95A2] hover:text-[#F4F6F8]"
              >
                Cancel
              </button>
              <button
                disabled={!newUpstreamId.trim() || !newUpstreamCommand.trim()}
                onClick={async () => {
                  if (newUpstreamId.trim()) {
                    await onCreateUpstream({
                      id: newUpstreamId.trim(),
                      name: newUpstreamName.trim() || newUpstreamId.trim(),
                      transport: newUpstreamTransport,
                      commandOrUrl: newUpstreamCommand.trim(),
                      trustTier: newUpstreamTrust,
                    });
                    setShowNewUpstreamDrawer(false);
                    setNewUpstreamId('');
                    setNewUpstreamName('');
                    setNewUpstreamCommand('');
                  }
                }}
                className="px-3 py-1.5 bg-[#2563EB] hover:bg-[#1D4ED8] text-[#F4F6F8] font-medium disabled:opacity-50"
              >
                Create Upstream
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
