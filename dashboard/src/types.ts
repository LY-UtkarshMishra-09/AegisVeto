export type Verdict =
  | 'ALLOW'
  | 'DENY'
  | 'QUARANTINE'
  | 'SHADOW_DENY'
  | 'SCHEMA_DRIFT'
  | 'CRITICAL_TRIPWIRE';

export type TaintState = 'CLEAN' | 'TAINTED' | 'TERMINATED';
export type AgentMode = 'enforce' | 'shadow';
export type TrustTier = 'trusted' | 'untrusted' | 'egress';

export interface AuditEvent {
  id: string;
  timestamp: string;
  session_id: string;
  agent_id: string;
  upstream_id: string | null;
  tool_name: string;
  taint_state: TaintState;
  verdict: Verdict;
  latency_ms: number;
  rule_matched: string;
  payload_json: string | null;
}

export interface OverviewData {
  total: number;
  allowed: number;
  quarantined: number;
  vetoed: number;
  shadowDenied: number;
  p95LatencyMs: number;
  activeAgents: number;
  activeIncidents: number;
  recentBlocked: Array<{
    id: string;
    timestamp: string;
    agentId: string;
    toolName: string;
    verdict: Verdict;
    ruleMatched: string;
    latencyMs: number;
  }>;
}

export interface Agent {
  id: string;
  name: string;
  mode: AgentMode;
  allowed_upstreams: string[];
  key_fingerprint: string | null;
  status: 'active' | 'revoked';
  created_at: string;
}

export interface Upstream {
  id: string;
  name: string;
  transport: 'stdio' | 'http';
  command_or_url: string;
  trust_tier: TrustTier;
  vault_secret_ref: string | null;
  status: string;
  created_at: string;
}

export interface SchemaPin {
  id: string;
  upstream_id: string;
  tool_name: string;
  sha256_hash: string;
  canonical_schema: Record<string, unknown>;
  approved_at: string;
  drift_detected: number;
  drift_diff: {
    field?: string;
    oldValue?: unknown;
    newValue?: unknown;
    diffSummary?: string;
  } | null;
}

export interface QuarantineItem {
  id: string;
  eventId: string;
  agentId: string;
  sessionId: string;
  toolName: string;
  payload: Record<string, unknown>;
  status: 'pending' | 'approved' | 'vetoed' | 'expired';
  aiRiskScore: number | null;
  aiHijacked: number | null;
  aiSummary: string | null;
  createdAt: string;
  expiresAt: string;
  ruleMatched: string;
}

export interface PolicyVersion {
  id: string;
  version: number;
  author: string;
  is_active: number;
  created_at: string;
}

export interface ActivePolicyResponse {
  version: number;
  yamlContent: string;
  author: string;
  createdAt: string;
  parsed: Record<string, unknown>;
}

export interface ServiceSettings {
  layer2_provider?: {
    provider: 'ollama' | 'groq';
    ollamaUrl: string;
    ollamaModel: string;
    groqModel: string;
    apiKey?: string;
  };
  approval_sla_seconds?: number;
  webhook_url?: string;
  canary_tokens?: string[];
  decoy_tool_name?: string;
}
