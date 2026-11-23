import fs from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';
import { z } from 'zod';
import { getTaint, markTainted, getOrCreateSession, incrementCallCount } from '../state/taint.js';

// ─── Types ───────────────────────────────────────────────────────
export type Verdict = 'ALLOW' | 'DENY' | 'QUARANTINE';

export interface EvaluationRequest {
  session_id: string;
  tool: string;
  args: Record<string, unknown>;
  max_calls: number;
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
  token: z.string(),
  tool: z.string(),
  args: z.record(z.unknown()).default({}),
});

// ─── Policy Loading ──────────────────────────────────────────────
interface PolicyConfig {
  path_protection: {
    deny_patterns: string[];
    sandbox_root: string;
  };
  tools: Record<string, {
    action: string;
    trust?: string;
    class?: string;
    deny_paths?: string[];
    quarantine_patterns?: string[];
  }>;
  taint_engine: {
    egress_tools: string[];
    sink_action_when_tainted: string;
  };
}

let policyConfig: PolicyConfig;
let policyRaw: string;

export function loadPolicy(policyPath: string): void {
  policyRaw = fs.readFileSync(policyPath, 'utf-8');
  policyConfig = yaml.load(policyRaw) as PolicyConfig;
}

export function getRawPolicy(): string {
  return policyRaw;
}

// ─── Path Security ───────────────────────────────────────────────
function findRepoRoot(): string {
  let curr = process.cwd();
  while (curr !== path.dirname(curr)) {
    if (fs.existsSync(path.join(curr, 'policy.yaml'))) return curr;
    curr = path.dirname(curr);
  }
  return process.cwd();
}

const SANDBOX_ROOT = path.join(findRepoRoot(), 'sandbox');

function isPathDenied(filePath: string): { denied: boolean; rule: string } {
  // Convert all slashes to forward slashes and trim relative prefixes
  const normalized = filePath.replace(/\\/g, '/').replace(/^\.\//, '');
  const baseName = path.basename(filePath);

  // Check path traversal: does resolved path escape sandbox?
  const resolved = path.resolve(SANDBOX_ROOT, filePath.replace(/^sandbox[/\\]?/, ''));
  if (filePath.includes('..') || (!resolved.startsWith(SANDBOX_ROOT) && !filePath.startsWith('sandbox'))) {
    return { denied: true, rule: 'PATH_TRAVERSAL_ESCAPE' };
  }

  // Hard deny on secret file patterns
  if (
    baseName.startsWith('.env') ||
    normalized.includes('.env') ||
    normalized.includes('.ssh') ||
    normalized.includes('.git/config')
  ) {
    return { denied: true, rule: 'SECRET_PROTECTION_ENV' };
  }

  // Check explicit deny patterns
  const denyPatterns = policyConfig.path_protection.deny_patterns;
  for (const pattern of denyPatterns) {
    const cleanPattern = pattern.replace(/\\/g, '/');
    if (cleanPattern === '../' && filePath.includes('..')) {
      return { denied: true, rule: 'PATH_TRAVERSAL_DOTDOT' };
    }

    const regexStr = cleanPattern
      .replace(/\*\*/g, '.*')
      .replace(/\*/g, '[^/]*')
      .replace(/\./g, '\\.');
    if (new RegExp(regexStr).test(normalized) || new RegExp(regexStr).test(baseName)) {
      return { denied: true, rule: `DENY_PATTERN:${pattern}` };
    }
  }

  return { denied: false, rule: '' };
}

// ─── Core Deterministic Engine ───────────────────────────────────
let evalCounter = 0;

export function evaluate(req: EvaluationRequest): EvaluationResult {
  const start = performance.now();
  const id = `eval-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
  const timestamp = new Date().toISOString();

  // Ensure session state exists
  getOrCreateSession(req.session_id, req.max_calls);

  // Check call count limit
  const callInfo = incrementCallCount(req.session_id);
  if (callInfo.exceeded) {
    const elapsed = performance.now() - start;
    return {
      id, verdict: 'DENY', taint: getTaint(req.session_id), latency_ms: +elapsed.toFixed(3),
      reason: `Call limit exceeded (${callInfo.current}/${callInfo.max})`,
      rule_matched: 'CALL_LIMIT_EXCEEDED', session_id: req.session_id,
      tool: req.tool, args: req.args, timestamp,
    };
  }

  const toolConfig = policyConfig.tools[req.tool];

  // 1. Path security check for file-access tools
  if ((req.tool === 'read_file' || req.tool === 'write_file') && typeof req.args['path'] === 'string') {
    const pathCheck = isPathDenied(req.args['path'] as string);
    if (pathCheck.denied) {
      const elapsed = performance.now() - start;
      return {
        id, verdict: 'DENY', taint: getTaint(req.session_id), latency_ms: +elapsed.toFixed(3),
        reason: `Secret/path protection: access denied by ${pathCheck.rule}`,
        rule_matched: pathCheck.rule, session_id: req.session_id,
        tool: req.tool, args: req.args, timestamp,
      };
    }
  }

  // 2. Taint propagation: untrusted tools flip session taint
  if (toolConfig?.trust === 'untrusted') {
    markTainted(req.session_id, `Tool '${req.tool}' is classified as untrusted input source`);
  }

  const currentTaint = getTaint(req.session_id);

  // 3. Egress blocking when tainted
  const egressTools = policyConfig.taint_engine.egress_tools;
  const isEgress = toolConfig?.class === 'egress' || egressTools.includes(req.tool);

  if (isEgress && currentTaint === 'TAINTED') {
    const elapsed = performance.now() - start;
    return {
      id, verdict: 'DENY', taint: currentTaint, latency_ms: +elapsed.toFixed(3),
      reason: 'Taint Lock: session is TAINTED, egress tool deterministically blocked',
      rule_matched: 'TAINT_EGRESS_DENY', session_id: req.session_id,
      tool: req.tool, args: req.args, timestamp,
    };
  }

  // 4. Quarantine check: explicit quarantine action or pattern match
  if (toolConfig?.action === 'quarantine') {
    const elapsed = performance.now() - start;
    return {
      id, verdict: 'QUARANTINE', taint: currentTaint, latency_ms: +elapsed.toFixed(3),
      reason: `Tool '${req.tool}' requires human-in-the-loop approval`,
      rule_matched: 'TOOL_ACTION_QUARANTINE', session_id: req.session_id,
      tool: req.tool, args: req.args, timestamp,
    };
  }

  if (toolConfig?.quarantine_patterns && typeof req.args['command'] === 'string') {
    for (const pattern of toolConfig.quarantine_patterns) {
      if (new RegExp(pattern).test(req.args['command'] as string)) {
        const elapsed = performance.now() - start;
        return {
          id, verdict: 'QUARANTINE', taint: currentTaint, latency_ms: +elapsed.toFixed(3),
          reason: `Destructive shell pattern matched: ${pattern}`,
          rule_matched: `QUARANTINE_PATTERN:${pattern}`, session_id: req.session_id,
          tool: req.tool, args: req.args, timestamp,
        };
      }
    }
  }

  // 5. Egress tools when CLEAN require approval
  if (isEgress && toolConfig?.action === 'require_approval') {
    const elapsed = performance.now() - start;
    return {
      id, verdict: 'QUARANTINE', taint: currentTaint, latency_ms: +elapsed.toFixed(3),
      reason: `Egress tool '${req.tool}' requires operator approval`,
      rule_matched: 'EGRESS_REQUIRE_APPROVAL', session_id: req.session_id,
      tool: req.tool, args: req.args, timestamp,
    };
  }

  // 6. Default ALLOW
  const elapsed = performance.now() - start;
  return {
    id, verdict: 'ALLOW', taint: currentTaint, latency_ms: +elapsed.toFixed(3),
    reason: `Tool '${req.tool}' allowed by policy`,
    rule_matched: 'DEFAULT_ALLOW', session_id: req.session_id,
    tool: req.tool, args: req.args, timestamp,
  };
}
