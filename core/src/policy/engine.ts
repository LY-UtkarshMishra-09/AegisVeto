import { z } from 'zod';
import {
  evaluateDeterministic,
  getActivePolicy,
  loadActivePolicy,
  EvaluateRequest,
  EvaluateResponse,
  EngineVerdict,
} from '../engine/evaluate.js';

export type Verdict = 'ALLOW' | 'DENY' | 'QUARANTINE';

export interface EvaluationRequest {
  session_id: string;
  tool: string;
  args: Record<string, unknown>;
  max_calls?: number;
}

export interface EvaluationResult {
  id: string;
  verdict: Verdict;
  taint: 'CLEAN' | 'TAINTED';
  latency_ms: number;
  reason: string;
  rule_matched: string;
  session_id: string;
  tool: string;
  args: Record<string, unknown>;
  timestamp: string;
}

export const EvaluateRequestSchema = z.object({
  token: z.string().optional(),
  tool: z.string(),
  args: z.record(z.unknown()).default({}),
});

export function loadPolicy(policyPath: string): void {
  loadActivePolicy();
}

export function getRawPolicy(): string {
  return getActivePolicy().raw;
}

export function evaluate(req: EvaluationRequest): EvaluationResult {
  const result = evaluateDeterministic({
    sessionId: req.session_id,
    toolName: req.tool,
    args: req.args,
  });

  const verdict: Verdict =
    result.verdict === 'ALLOW' ? 'ALLOW' : result.verdict === 'QUARANTINE' ? 'QUARANTINE' : 'DENY';
  const taint: 'CLEAN' | 'TAINTED' = result.taintState === 'CLEAN' ? 'CLEAN' : 'TAINTED';

  return {
    id: result.id,
    verdict,
    taint,
    latency_ms: result.latencyMs,
    reason: result.reason || result.ruleMatched,
    rule_matched: result.ruleMatched,
    session_id: req.session_id,
    tool: req.tool,
    args: req.args,
    timestamp: result.trace.timestamp,
  };
}
