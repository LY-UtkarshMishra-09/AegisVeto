import React, { useState, useEffect, useCallback } from 'react';
import { Sidebar, NavTab } from './components/Sidebar';
import { OverviewView } from './views/OverviewView';
import { AuditStreamView } from './views/AuditStreamView';
import { ApprovalsView } from './views/ApprovalsView';
import { InventoryView } from './views/InventoryView';
import { PoliciesView } from './views/PoliciesView';
import { SettingsView } from './views/SettingsView';

import {
  AuditEvent,
  OverviewData,
  Agent,
  Upstream,
  QuarantineItem,
  PolicyVersion,
  ServiceSettings,
} from './types';

const API_BASE = 'http://localhost:3000';

function getInitialPage(): NavTab {
  const hash = window.location.hash.replace('#', '') as NavTab;
  if (['overview', 'logs', 'approvals', 'inventory', 'policies', 'settings'].includes(hash)) {
    return hash;
  }
  return 'overview';
}

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<NavTab>(getInitialPage());
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(true);

  // Global persistent data state
  const [overview, setOverview] = useState<OverviewData | null>(null);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [approvals, setApprovals] = useState<QuarantineItem[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [upstreams, setUpstreams] = useState<Upstream[]>([]);
  const [activePolicyYaml, setActivePolicyYaml] = useState<string>('');
  const [activePolicyVersion, setActivePolicyVersion] = useState<number>(1);
  const [policyVersions, setPolicyVersions] = useState<PolicyVersion[]>([]);
  const [settings, setSettings] = useState<ServiceSettings>({});
  const [insertedPolicySnippet, setInsertedPolicySnippet] = useState<string | undefined>(undefined);
  const [isLiveConnected, setIsLiveConnected] = useState<boolean>(false);

  // Hash-sync routing
  useEffect(() => {
    window.location.hash = activeTab;
  }, [activeTab]);

  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash.replace('#', '') as NavTab;
      if (['overview', 'logs', 'approvals', 'inventory', 'policies', 'settings'].includes(hash)) {
        setActiveTab(hash);
      }
    };
    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  // Fetch initial data
  const refreshOverview = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/v1/overview`);
      if (res.ok) setOverview(await res.json());
    } catch {}
  }, []);

  const refreshEvents = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/v1/events?limit=200`);
      if (res.ok) setEvents(await res.json());
    } catch {}
  }, []);

  const refreshApprovals = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/v1/approvals`);
      if (res.ok) setApprovals(await res.json());
    } catch {}
  }, []);

  const refreshAgents = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/v1/agents`);
      if (res.ok) setAgents(await res.json());
    } catch {}
  }, []);

  const refreshUpstreams = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/v1/upstreams`);
      if (res.ok) setUpstreams(await res.json());
    } catch {}
  }, []);

  const refreshPolicies = useCallback(async () => {
    try {
      const [activeRes, versionsRes] = await Promise.all([
        fetch(`${API_BASE}/v1/policies/active`),
        fetch(`${API_BASE}/v1/policies/versions`),
      ]);
      if (activeRes.ok) {
        const data = await activeRes.json();
        setActivePolicyYaml(data.yamlContent || '');
        setActivePolicyVersion(data.version || 1);
      }
      if (versionsRes.ok) {
        setPolicyVersions(await versionsRes.json());
      }
    } catch {}
  }, []);

  const refreshSettings = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/v1/settings`);
      if (res.ok) setSettings(await res.json());
    } catch {}
  }, []);

  useEffect(() => {
    refreshOverview();
    refreshEvents();
    refreshApprovals();
    refreshAgents();
    refreshUpstreams();
    refreshPolicies();
    refreshSettings();
  }, [
    refreshOverview,
    refreshEvents,
    refreshApprovals,
    refreshAgents,
    refreshUpstreams,
    refreshPolicies,
    refreshSettings,
  ]);

  // Persistent live SSE stream connection
  useEffect(() => {
    let es: EventSource | null = null;
    let reconnectTimeout: any = null;

    const connectSSE = () => {
      es = new EventSource(`${API_BASE}/v1/events/stream`);

      es.addEventListener('connected', () => {
        setIsLiveConnected(true);
      });

      es.addEventListener('evaluation', (e) => {
        try {
          const newEvent = JSON.parse(e.data);
          setEvents((prev) => [newEvent, ...prev.slice(0, 199)]);
          refreshOverview();
        } catch {}
      });

      es.addEventListener('quarantine', () => {
        try {
          refreshApprovals();
          refreshOverview();
        } catch {}
      });

      es.addEventListener('quarantine_resolved', () => {
        try {
          refreshApprovals();
          refreshOverview();
          refreshEvents();
        } catch {}
      });

      es.addEventListener('policy_updated', () => {
        refreshPolicies();
      });

      es.onerror = () => {
        setIsLiveConnected(false);
        es?.close();
        reconnectTimeout = setTimeout(connectSSE, 4000);
      };
    };

    connectSSE();

    return () => {
      es?.close();
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
    };
  }, [refreshApprovals, refreshEvents, refreshOverview, refreshPolicies]);

  // Handlers for Views
  const handleResolveApproval = async (id: string, action: 'approve' | 'veto') => {
    const res = await fetch(`${API_BASE}/v1/approvals/${id}/resolve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action }),
    });
    if (res.ok) {
      setApprovals((prev) => prev.filter((a) => a.id !== id));
      refreshOverview();
      refreshEvents();
    }
  };

  const handleToggleAgentMode = async (agentId: string, newMode: 'enforce' | 'shadow') => {
    const res = await fetch(`${API_BASE}/v1/agents/${agentId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: newMode }),
    });
    if (res.ok) {
      refreshAgents();
    }
  };

  const handleCreateAgent = async (agent: {
    id: string;
    name: string;
    mode: 'enforce' | 'shadow';
    allowedUpstreams: string[];
  }) => {
    const res = await fetch(`${API_BASE}/v1/agents`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(agent),
    });
    if (res.ok) {
      refreshAgents();
      refreshOverview();
    }
  };

  const handleCreateUpstream = async (upstream: {
    id: string;
    name: string;
    transport: 'stdio' | 'http';
    commandOrUrl: string;
    trustTier: 'trusted' | 'untrusted' | 'egress';
  }) => {
    const res = await fetch(`${API_BASE}/v1/upstreams`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(upstream),
    });
    if (res.ok) {
      refreshUpstreams();
    }
  };

  const handleSavePolicy = async (yamlContent: string): Promise<boolean> => {
    const res = await fetch(`${API_BASE}/v1/policies/active`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ yamlContent, author: 'operator' }),
    });
    if (res.ok) {
      refreshPolicies();
      return true;
    }
    return false;
  };

  const handleSaveSettings = async (newSettings: Partial<ServiceSettings>): Promise<boolean> => {
    const res = await fetch(`${API_BASE}/v1/settings`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(newSettings),
    });
    if (res.ok) {
      refreshSettings();
      return true;
    }
    return false;
  };

  const pageTitles: Record<NavTab, string> = {
    overview: 'Overview',
    logs: 'Audit Stream',
    approvals: 'Pending Approvals',
    inventory: 'Inventory & Schema Pins',
    policies: 'Security Policies',
    settings: 'Service Settings',
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#000000] text-[#F4F6F8]">
      {/* Collapsible Left Rail (64px collapsed / 220px expanded) */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        pendingApprovalsCount={approvals.length}
        isCollapsed={isSidebarCollapsed}
        onToggleCollapse={() => setIsSidebarCollapsed(!isSidebarCollapsed)}
      />

      {/* Main Container */}
      <div className="flex-1 flex flex-col min-w-0 h-screen overflow-hidden bg-[#000000]">
        {/* Sticky Top Utility Bar (h-12 border-b border-[#1E1E22] px-5) */}
        <header className="h-12 border-b border-[#1E1E22] px-5 flex items-center justify-between bg-[#000000] shrink-0 z-20">
          {/* Left Breadcrumb */}
          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="text-[#8E95A2]">AegisVeto</span>
            <span className="text-[#1E1E22]">/</span>
            <span className="text-[#F4F6F8] font-medium">{pageTitles[activeTab]}</span>
          </div>

          {/* Center Inline Hairline Telemetry */}
          <div className="hidden md:flex items-center gap-4 text-xs font-mono text-[#8E95A2]">
            <div>
              24h Calls: <span className="text-[#F4F6F8] tabular-nums">{overview?.total ?? 0}</span>
            </div>
            <div className="text-[#1E1E22]">|</div>
            <div>
              Vetoed: <span className="text-[#EF4444] tabular-nums">{overview?.vetoed ?? 0}</span>
            </div>
            <div className="text-[#1E1E22]">|</div>
            <div>
              Pending: <span className="text-[#F59E0B] tabular-nums">{approvals.length}</span>
            </div>
            <div className="text-[#1E1E22]">|</div>
            <div>
              p95 Latency:{' '}
              <span className="text-[#4D8BFF] tabular-nums">
                {(overview?.p95LatencyMs ?? 0).toFixed(2)}ms
              </span>
            </div>
          </div>

          {/* Right Live Proxy Indicator */}
          <div className="flex items-center gap-2">
            <div
              className={`w-2 h-2 rounded-full ${
                isLiveConnected ? 'bg-[#4D8BFF] animate-pulse' : 'bg-[#EF4444]'
              }`}
            />
            <span className="text-xs font-mono text-[#8E95A2] hidden sm:inline">
              {isLiveConnected ? 'Proxy Active' : 'Disconnected'}
            </span>
          </div>
        </header>

        {/* Dynamic Route View */}
        <main className="flex-1 min-h-0 overflow-hidden bg-[#000000]">
          {activeTab === 'overview' && (
            <OverviewView
              overview={overview}
              agents={agents}
              upstreams={upstreams}
              onNavigate={(tab) => setActiveTab(tab as NavTab)}
            />
          )}

          {activeTab === 'logs' && <AuditStreamView events={events} />}

          {activeTab === 'approvals' && (
            <ApprovalsView
              approvals={approvals}
              onResolve={handleResolveApproval}
              onNavigateToPolicy={(snippet) => {
                setInsertedPolicySnippet(snippet);
                setActiveTab('policies');
              }}
            />
          )}

          {activeTab === 'inventory' && (
            <InventoryView
              agents={agents}
              upstreams={upstreams}
              onToggleAgentMode={handleToggleAgentMode}
              onCreateAgent={handleCreateAgent}
              onCreateUpstream={handleCreateUpstream}
            />
          )}

          {activeTab === 'policies' && (
            <PoliciesView
              initialYaml={activePolicyYaml}
              initialVersion={activePolicyVersion}
              versions={policyVersions}
              agents={agents}
              onSavePolicy={handleSavePolicy}
              insertedSnippet={insertedPolicySnippet}
            />
          )}

          {activeTab === 'settings' && (
            <SettingsView initialSettings={settings} onSaveSettings={handleSaveSettings} />
          )}
        </main>
      </div>
    </div>
  );
};

export default App;
