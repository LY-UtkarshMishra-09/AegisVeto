import React, { useState, useEffect } from 'react';
import { Sidebar, NavTab } from './components/Sidebar';
import { LiveConsoleView } from './views/LiveConsoleView';
import { QuarantineView } from './views/QuarantineView';
import { BenchmarkView } from './views/BenchmarkView';
import { PolicyRulesView } from './views/PolicyRulesView';
import {
  initialPipelineStatus,
  mockBenchmarkMetrics,
} from './mockData';
import { ToolCall, QuarantineItem, LLMProvider } from './types';

const API_BASE = 'http://localhost:3000';

interface AuditLogResponseItem {
  id: string;
  timestamp: string;
  session_id: string;
  provider: LLMProvider;
  tool_name: string;
  payload_json: string;
  taint_state: 'CLEAN' | 'TAINTED';
  decision: 'ALLOW' | 'DENY' | 'QUARANTINE';
  latency_ms: number;
  reason: string;
}

interface QuarantineResponseItem {
  id: string;
  quarantine_id?: string;
  session_id: string;
  timestamp: string;
  tool: string;
  args?: Record<string, unknown>;
  taint: 'CLEAN' | 'TAINTED';
  reason: string;
  rule_matched?: string;
  ai_assessment?: {
    risk_score: number;
    hijacked: boolean;
    summary: string;
  };
}

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<NavTab>('console');
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);
  const [provider, setProvider] = useState<LLMProvider>('ollama');
  const [isProtected, setIsProtected] = useState(true);
  const [toolCalls, setToolCalls] = useState<ToolCall[]>([]);
  const [quarantineQueue, setQuarantineQueue] = useState<QuarantineItem[]>([]);
  const [pipelineStatus, setPipelineStatus] = useState(initialPipelineStatus);
  const [stats, setStats] = useState({ totalCalls: 0, attacksVetoed: 0, avgLatencyMs: 0 });
  const [policyYaml, setPolicyYaml] = useState<string>('');
  const [isRunningScenario, setIsRunningScenario] = useState(false);

  const currentModel = provider === 'ollama' ? 'qwen3:8b' : 'llama-3.3-70b-versatile';

  const handleProviderChange = (p: LLMProvider) => {
    setProvider(p);
    setPipelineStatus((prev) => ({
      ...prev,
      provider: p,
      model: p === 'ollama' ? 'qwen3:8b' : 'llama-3.3-70b-versatile',
    }));
  };

  // Smooth scroll handler when clicking sidebar nav item
  const handleNavClick = (tab: NavTab) => {
    setActiveTab(tab);
    const section = document.getElementById(tab);
    if (section) {
      section.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  // Scroll-spy with IntersectionObserver
  useEffect(() => {
    const sectionIds: NavTab[] = ['console', 'quarantine', 'benchmark', 'policy'];
    const elements = sectionIds
      .map((id) => document.getElementById(id))
      .filter((el): el is HTMLElement => el !== null);

    if (elements.length === 0) return;

    const observer = new IntersectionObserver(
      (entries) => {
        // Find visible section with highest intersection ratio
        const visible = entries.filter((entry) => entry.isIntersecting);
        if (visible.length > 0) {
          // Sort by intersection ratio or top position
          visible.sort((a, b) => b.intersectionRatio - a.intersectionRatio);
          const topEntry = visible[0];
          if (topEntry?.target?.id) {
            setActiveTab(topEntry.target.id as NavTab);
          }
        }
      },
      {
        root: null,
        rootMargin: '-20% 0px -60% 0px',
        threshold: [0, 0.2, 0.5, 0.8],
      }
    );

    elements.forEach((el) => observer.observe(el));
    return () => observer.disconnect();
  }, []);

  // Hydrate on mount from SQLite backend and subscribe to SSE
  useEffect(() => {
    // 1. Fetch Audit Logs & KPI metrics
    fetch(`${API_BASE}/audit`)
      .then((r) => r.json())
      .then((data) => {
        if (data.logs && Array.isArray(data.logs)) {
          const mapped: ToolCall[] = data.logs.map((l: AuditLogResponseItem) => {
            let parsedArgs: Record<string, unknown> = {};
            try {
              parsedArgs = JSON.parse(l.payload_json || '{}');
            } catch {
              parsedArgs = { raw: l.payload_json };
            }

            return {
              id: l.id,
              timestamp: l.timestamp.includes('T') ? l.timestamp.split('T')[1].slice(0, 12) : l.timestamp,
              session: l.session_id,
              provider: l.provider || 'ollama',
              tool: l.tool_name,
              args: parsedArgs,
              taint: l.taint_state,
              verdict: l.decision,
              latencyMs: l.latency_ms,
              reason: l.reason || '',
              responsePayload: parsedArgs,
            };
          });
          setToolCalls(mapped);
        }

        if (data.metrics) {
          setStats({
            totalCalls: data.metrics.totalCalls,
            attacksVetoed: data.metrics.blockedCount,
            avgLatencyMs: data.metrics.avgLatencyMs,
          });
        }
      })
      .catch((err) => console.warn('Could not connect to /audit (backend starting up?):', err));

    // 2. Fetch pending Quarantines
    fetch(`${API_BASE}/quarantine`)
      .then((r) => r.json())
      .then((items: QuarantineResponseItem[]) => {
        if (Array.isArray(items)) {
          setQuarantineQueue(
            items.map((it) => ({
              id: it.quarantine_id || it.id,
              session: it.session_id,
              timestamp: it.timestamp,
              tool: it.tool,
              args: it.args || {},
              taint: it.taint,
              riskSummary: it.reason,
              ruleMatched: it.rule_matched || 'QUARANTINE_RULE',
              status: 'PENDING',
              ai_assessment: it.ai_assessment,
            }))
          );
        }
      })
      .catch((err) => console.warn('Could not load /quarantine:', err));

    // 3. Fetch active policy.yaml
    fetch(`${API_BASE}/policy`)
      .then((r) => r.text())
      .then((text) => setPolicyYaml(text))
      .catch((err) => console.warn('Could not load /policy:', err));

    // 4. Subscribe to Live SSE Events
    const eventSource = new EventSource(`${API_BASE}/events`);

    eventSource.addEventListener('evaluation', (event) => {
      try {
        const data = JSON.parse(event.data);
        const newCall: ToolCall = {
          id: data.id,
          timestamp: (data.timestamp || new Date().toISOString()).split('T')[1]?.slice(0, 12) || data.timestamp,
          session: data.session_id,
          provider: data.provider || provider,
          tool: data.tool || data.tool_name,
          args: data.args || {},
          taint: data.taint || data.taint_state,
          verdict: data.verdict || data.decision,
          latencyMs: data.latency_ms || data.latencyMs || 0,
          reason: data.reason || '',
        };

        setToolCalls((prev) => [newCall, ...prev]);

        setPipelineStatus({
          agentStatus: 'active',
          provider: data.provider || provider,
          model: data.model || currentModel,
          jwtVerified: true,
          taintState: data.taint || data.taint_state || 'CLEAN',
          policyGateVerdict: data.verdict || data.decision || 'ALLOW',
          targetTool: data.tool || data.tool_name || 'unknown',
          latencyMs: data.latency_ms || 0,
        });

        setStats((prev) => {
          const isVeto = (data.verdict || data.decision) === 'DENY' || (data.verdict || data.decision) === 'VETO';
          const nextTotal = prev.totalCalls + 1;
          const nextLat = Number(((prev.avgLatencyMs * prev.totalCalls + (data.latency_ms || 0)) / nextTotal).toFixed(2));
          return {
            totalCalls: nextTotal,
            attacksVetoed: isVeto ? prev.attacksVetoed + 1 : prev.attacksVetoed,
            avgLatencyMs: nextLat,
          };
        });
      } catch (err) {
        console.error('SSE evaluation parse error:', err);
      }
    });

    eventSource.addEventListener('quarantine', (event) => {
      try {
        const data = JSON.parse(event.data);
        setQuarantineQueue((prev) => [
          {
            id: data.id,
            session: data.session_id,
            timestamp: data.timestamp,
            tool: data.tool,
            args: data.args || {},
            taint: data.taint,
            riskSummary: data.reason,
            ruleMatched: data.rule_matched,
            status: 'PENDING',
          },
          ...prev,
        ]);
      } catch (err) {
        console.error('SSE quarantine parse error:', err);
      }
    });

    eventSource.addEventListener('quarantine_resolved', (event) => {
      try {
        const data = JSON.parse(event.data);
        setQuarantineQueue((prev) =>
          prev.map((item) =>
            item.id === data.id
              ? { ...item, status: data.action === 'APPROVE' ? 'APPROVED' : 'VETOED' }
              : item
          )
        );
      } catch (err) {
        console.error('SSE quarantine_resolved parse error:', err);
      }
    });

    eventSource.addEventListener('quarantine_analyzed', (event) => {
      try {
        const data = JSON.parse(event.data);
        setQuarantineQueue((prev) =>
          prev.map((item) =>
            item.id === data.id ? { ...item, ai_assessment: data.ai_assessment } : item
          )
        );
      } catch (err) {
        console.error('SSE quarantine_analyzed parse error:', err);
      }
    });

    eventSource.addEventListener('policy_updated', () => {
      fetch(`${API_BASE}/policy`)
        .then((r) => r.text())
        .then((text) => setPolicyYaml(text))
        .catch((err) => console.warn('Could not reload /policy:', err));
    });

    return () => {
      eventSource.close();
    };
  }, [provider, currentModel]);

  // Scenario A: Benign Task via backend POST /demo/run
  const handleRunBenign = async () => {
    setIsRunningScenario(true);
    try {
      await fetch(`${API_BASE}/demo/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenario: 'benign',
          protected: isProtected,
          provider,
        }),
      });
    } catch (err) {
      console.error('Error running benign scenario:', err);
    } finally {
      setIsRunningScenario(false);
    }
  };

  // Scenario B: Attack Task via backend POST /demo/run
  const handleRunAttack = async () => {
    setIsRunningScenario(true);
    try {
      await fetch(`${API_BASE}/demo/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenario: 'attack',
          protected: isProtected,
          provider,
        }),
      });
    } catch (err) {
      console.error('Error running attack scenario:', err);
    } finally {
      setIsRunningScenario(false);
    }
  };

  // Quarantine Actions via backend POST /quarantine/:id/resolve
  const handleApproveQuarantine = async (id: string) => {
    try {
      await fetch(`${API_BASE}/quarantine/${id}/resolve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'APPROVE' }),
      });
      setQuarantineQueue((prev) =>
        prev.map((item) => (item.id === id ? { ...item, status: 'APPROVED' } : item))
      );
    } catch (err) {
      console.error('Error approving quarantine:', err);
    }
  };

  const handleVetoQuarantine = async (id: string) => {
    try {
      await fetch(`${API_BASE}/quarantine/${id}/resolve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'VETO' }),
      });
      setQuarantineQueue((prev) =>
        prev.map((item) => (item.id === id ? { ...item, status: 'VETOED' } : item))
      );
      setStats((prev) => ({ ...prev, attacksVetoed: prev.attacksVetoed + 1 }));
    } catch (err) {
      console.error('Error vetoing quarantine:', err);
    }
  };

  const handlePolicyPatched = () => {
    fetch(`${API_BASE}/policy`)
      .then((r) => r.text())
      .then((text) => setPolicyYaml(text))
      .catch((err) => console.warn('Could not reload /policy:', err));
  };

  const pendingCount = quarantineQueue.filter((item) => item.status === 'PENDING').length;

  return (
    <div className="flex min-h-screen bg-[#080B0E] text-[#ECF2EE] font-sans">
      {/* Sticky Collapsible Left Sidebar */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={handleNavClick}
        pendingQuarantineCount={pendingCount}
        isCollapsed={isSidebarCollapsed}
        onToggleCollapse={() => setIsSidebarCollapsed((prev) => !prev)}
      />

      {/* Main Single-Page Stacked Container */}
      <main className="flex-1 h-screen overflow-y-auto">
        <div className="max-w-6xl mx-auto space-y-10 p-6">
          {/* Section 1: Live Console */}
          <section id="console" className="scroll-mt-6">
            <LiveConsoleView
              toolCalls={toolCalls}
              pipelineStatus={pipelineStatus}
              stats={stats}
              provider={provider}
              setProvider={handleProviderChange}
              isProtected={isProtected}
              setIsProtected={setIsProtected}
              onRunBenign={handleRunBenign}
              onRunAttack={handleRunAttack}
              isRunningScenario={isRunningScenario}
            />
          </section>

          {/* Section 2: Quarantine Queue */}
          <section id="quarantine" className="scroll-mt-6">
            <QuarantineView
              queue={quarantineQueue}
              onApprove={handleApproveQuarantine}
              onVeto={handleVetoQuarantine}
              onPolicyPatched={handlePolicyPatched}
            />
          </section>

          {/* Section 3: VS Benchmark */}
          <section id="benchmark" className="scroll-mt-6">
            <BenchmarkView metrics={mockBenchmarkMetrics} />
          </section>

          {/* Section 4: Policy Rules */}
          <section id="policy" className="scroll-mt-6">
            <PolicyRulesView policyYaml={policyYaml} />
          </section>
        </div>
      </main>
    </div>
  );
};

export default App;
