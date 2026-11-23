export type Verdict = 'ALLOW' | 'DENY' | 'QUARANTINE';
export type TaintState = 'CLEAN' | 'TAINTED';

export interface ToolCall {
  id: string;
  timestamp: string;
  session: string;
  tool: string;
  args: Record<string, unknown>;
  taint: TaintState;
  verdict: Verdict;
  latencyMs: number;
  reason: string;
  responsePayload?: Record<string, unknown> | string;
}

export interface QuarantineItem {
  id: string;
  session: string;
  timestamp: string;
  tool: string;
  args: Record<string, unknown>;
  taint: TaintState;
  riskSummary: string;
  ruleMatched: string;
  status: 'PENDING' | 'APPROVED' | 'VETOED';
}

export interface BenchmarkMetric {
  id: string;
  category: string;
  rawAgent: string;
  llmJudge: string;
  aegisVeto: string;
  aegisVetoHighlight?: boolean;
}

export interface PipelineStatus {
  agentStatus: 'active' | 'idle';
  jwtVerified: boolean;
  taintState: TaintState;
  policyGateVerdict: Verdict;
  targetTool: string;
  latencyMs: number;
}
