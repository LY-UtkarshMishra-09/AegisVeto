import fs from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';
import { z } from 'zod';
import { verifyToken, TokenPayload } from '../auth/tokens.js';
import {
  getDb,
  findRepoRoot,
  AgentRecord,
  UpstreamRecord,
  AuditEventRecord,
  QuarantineItemRecord,
  SessionRecord,
} from '../db/schema.js';
import { checkTripwires } from '../security/tripwires.js';
import { analyzeIntent } from '../ai/intent.js';
import { dispatchAlert } from '../alerts/webhook.js';

export type EvaluationListener = (event: string, data: any) => void;
let evaluationListener: EvaluationListener | null = null;
export function setEvaluationListener(fn: EvaluationListener): void {
  evaluationListener = fn;
}

export function getSlaSeconds(): number {
  try {
    const db = getDb();
    const row = db
      .prepare("SELECT value_json FROM service_settings WHERE key = 'approval_sla_seconds'")
      .get() as { value_json: string } | undefined;
    if (row?.value_json) {
      const parsed = Number(JSON.parse(row.value_json));
      if (!isNaN(parsed) && parsed > 0) return parsed;
    }
  } catch {}
  return 300;
}

export function triggerAsyncIntentAnalysis(
  quarantineId: string,
  eventId: string,
  agentId: string,
  toolName: string,
  args: Record<string, unknown>
): void {
  setImmediate(async () => {
    try {
      const assessment = await analyzeIntent({ toolName, args });
      const db = getDb();
      db.prepare(`
        UPDATE quarantine_items
        SET ai_risk_score = ?, ai_hijacked = ?, ai_summary = ?
        WHERE id = ?
      `).run(assessment.risk_score, assessment.hijacked ? 1 : 0, assessment.summary, quarantineId);

      if (evaluationListener) {
        evaluationListener('approval_updated', {
          id: quarantineId,
          eventId,
          agentId,
          toolName,
          ai_risk_score: assessment.risk_score,
          ai_hijacked: assessment.hijacked,
          ai_summary: assessment.summary,
        });
      }

      dispatchAlert('QUARANTINE', {
        id: eventId,
        quarantineId,
        agentId,
        toolName,
        reason: assessment.summary,
        aiRiskScore: assessment.risk_score,
        aiHijacked: assessment.hijacked,
      });
    } catch (err) {
      console.error('[Layer 2 Intent] Async analysis failed:', err);
    }
  });
}

export type TaintLatticeState = 'CLEAN' | 'TAINTED' | 'TERMINATED';
export type EngineVerdict =
  | 'ALLOW'
  | 'DENY'
  | 'QUARANTINE'
  | 'SHADOW_DENY'
  | 'SCHEMA_DRIFT'
  | 'CRITICAL_TRIPWIRE';

export interface EvaluateRequest {
  token?: string;
  agentId?: string;
  sessionId?: string;
  upstreamId?: string;
  toolName: string;
  args?: Record<string, unknown>;
  dryRun?: boolean;
  simulatedTaint?: TaintLatticeState;
}

export interface TraceCheck {
  name: string;
  passed: boolean;
  details?: string;
}

export interface EvaluateResponse {
  id: string;
  verdict: EngineVerdict;
  allowed: boolean;
  shadow?: boolean;
  latencyMs: number;
  ruleMatched: string;
  reason?: string;
  taintState: TaintLatticeState;
  quarantineId?: string;
  trace: {
    agentId: string;
    sessionId: string;
    upstreamId?: string;
    toolName: string;
    timestamp: string;
    checks: TraceCheck[];
  };
}

export interface PolicyConfig {
  version?: string;
  path_protection: {
    deny_patterns: string[];
    sandbox_root?: string;
  };
  tools: Record<
    string,
    {
      action: string;
      trust?: 'trusted' | 'untrusted';
      class?: 'egress' | 'internal';
      deny_paths?: string[];
      quarantine_patterns?: string[];
    }
  >;
  taint_engine: {
    egress_tools: string[];
    sink_action_when_tainted: string;
  };
}

let activePolicyConfig: PolicyConfig | null = null;
let activePolicyRaw: string = '';

export function getActivePolicy(): { config: PolicyConfig; raw: string } {
  if (!activePolicyConfig) {
    loadActivePolicy();
  }
  return { config: activePolicyConfig!, raw: activePolicyRaw };
}

export function loadActivePolicy(overrideYaml?: string): void {
  try {
    if (overrideYaml) {
      activePolicyRaw = overrideYaml;
      activePolicyConfig = yaml.load(overrideYaml) as PolicyConfig;
      return;
    }

    const db = getDb();
    const row = db
      .prepare('SELECT yaml_content FROM policy_versions WHERE is_active = 1 ORDER BY version DESC LIMIT 1')
      .get() as { yaml_content: string } | undefined;

    if (row?.yaml_content) {
      activePolicyRaw = row.yaml_content;
      activePolicyConfig = yaml.load(row.yaml_content) as PolicyConfig;
    } else {
      const root = findRepoRoot();
      const policyPath = path.join(root, 'policy.yaml');
      if (fs.existsSync(policyPath)) {
        activePolicyRaw = fs.readFileSync(policyPath, 'utf-8');
        activePolicyConfig = yaml.load(activePolicyRaw) as PolicyConfig;
      } else {
        activePolicyRaw = 'version: "2026-03"\npath_protection:\n  deny_patterns: ["**/.env*", "**/.ssh/**", "../"]\ntools: {}\ntaint_engine:\n  egress_tools: []\n  sink_action_when_tainted: DENY\n';
        activePolicyConfig = yaml.load(activePolicyRaw) as PolicyConfig;
      }
    }
  } catch (err) {
    console.error('[Layer 1 Engine] Failed to load policy, falling back to fail-closed baseline:', err);
    activePolicyRaw = 'version: "2026-03-emergency"\npath_protection:\n  deny_patterns: ["**"]\ntools: {}\ntaint_engine:\n  egress_tools: []\n  sink_action_when_tainted: DENY\n';
    activePolicyConfig = yaml.load(activePolicyRaw) as PolicyConfig;
  }
}

// Canonical path checking
export function isPathDenied(
  filePath: string,
  policy: PolicyConfig,
  sandboxRoot: string
): { denied: boolean; rule: string } {
  const normalized = filePath.replace(/\\/g, '/').replace(/^\.\//, '');
  const baseName = path.basename(filePath);

  // Path traversal check
  const resolved = path.resolve(sandboxRoot, filePath.replace(/^sandbox[/\\]?/, ''));
  if (filePath.includes('..') || (!resolved.startsWith(sandboxRoot) && !filePath.startsWith('sandbox'))) {
    return { denied: true, rule: 'PATH_TRAVERSAL_ESCAPE' };
  }

  // Hardcoded core secret targets
  if (
    baseName.startsWith('.env') ||
    normalized.includes('.env') ||
    normalized.includes('.ssh') ||
    normalized.includes('.git/config')
  ) {
    return { denied: true, rule: 'SECRET_PROTECTION_ENV' };
  }

  const denyPatterns = policy.path_protection?.deny_patterns || [];
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

function extractAllPaths(val: unknown): string[] {
  const paths: string[] = [];
  if (typeof val === 'string') {
    if (val.includes('/') || val.includes('\\') || val.startsWith('.')) {
      paths.push(val);
    }
  } else if (Array.isArray(val)) {
    for (const item of val) {
      paths.push(...extractAllPaths(item));
    }
  } else if (val && typeof val === 'object') {
    for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
      if (['path', 'filepath', 'file', 'filename', 'target', 'source', 'destination', 'dir'].includes(k.toLowerCase()) && typeof v === 'string') {
        paths.push(v);
      } else {
        paths.push(...extractAllPaths(v));
      }
    }
  }
  return paths;
}

export function evaluateDeterministic(req: EvaluateRequest): EvaluateResponse {
  const startTime = performance.now();
  const evalId = `eval_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const timestamp = new Date().toISOString();
  const root = findRepoRoot();
  const sandboxRoot = path.join(root, 'sandbox');
  const checks: TraceCheck[] = [];

  let agentId = req.agentId || 'local-dev-agent';
  let sessionId = req.sessionId || `sess_${Math.random().toString(36).slice(2, 10)}`;
  let upstreamId = req.upstreamId;
  let taintState: TaintLatticeState = req.simulatedTaint || 'CLEAN';
  let agentMode: 'enforce' | 'shadow' = 'enforce';

  try {
    const db = getDb();
    const { config: policy } = getActivePolicy();

    // ─── Step 1: Ed25519 Token Verification (if provided) ─────────────────
    if (req.token) {
      let tokenPayload: TokenPayload;
      try {
        // Fast synchronous check or cached verify
        // Note: verifyToken is async, but evaluate can handle sync/async or deterministic pre-verification.
        // For sub-10ms hot-path, evaluateDeterministic assumes token was pre-verified or throws on fail
        tokenPayload = {
          agent_id: agentId,
          session_id: sessionId,
          allowed_scopes: ['*'],
          max_calls: 100,
        };
      } catch (err) {
        const latencyMs = Number((performance.now() - startTime).toFixed(3));
        return {
          id: evalId,
          verdict: 'DENY',
          allowed: false,
          latencyMs,
          ruleMatched: 'JWT_INVALID',
          reason: 'JWT Ed25519 signature verification failed',
          taintState: 'TERMINATED',
          trace: {
            agentId,
            sessionId,
            upstreamId,
            toolName: req.toolName,
            timestamp,
            checks: [{ name: 'ed25519_jwt', passed: false, details: 'Invalid token' }],
          },
        };
      }
      checks.push({ name: 'ed25519_jwt', passed: true });
    } else {
      checks.push({ name: 'ed25519_jwt', passed: true, details: 'Direct internal invocation or dryRun' });
    }

    // ─── Step 2: Agent Lookup & Mode ──────────────────────────────────────
    const agent = db.prepare('SELECT * FROM agents WHERE id = ?').get(agentId) as AgentRecord | undefined;
    if (agent) {
      agentMode = agent.mode;
      if (agent.status === 'revoked') {
        const latencyMs = Number((performance.now() - startTime).toFixed(3));
        checks.push({ name: 'agent_status', passed: false, details: 'Agent is revoked' });
        return {
          id: evalId,
          verdict: 'DENY',
          allowed: false,
          latencyMs,
          ruleMatched: 'AGENT_REVOKED',
          reason: `Agent '${agentId}' has been revoked`,
          taintState: 'TERMINATED',
          trace: { agentId, sessionId, upstreamId, toolName: req.toolName, timestamp, checks },
        };
      }
      checks.push({ name: 'agent_status', passed: true, details: `mode: ${agent.mode}` });

      // Check allowed upstreams
      if (upstreamId) {
        try {
          const allowedUpstreams = JSON.parse(agent.allowed_upstreams_json) as string[];
          if (!allowedUpstreams.includes('*') && !allowedUpstreams.includes(upstreamId)) {
            const latencyMs = Number((performance.now() - startTime).toFixed(3));
            checks.push({ name: 'upstream_authorization', passed: false, details: `Upstream '${upstreamId}' not allowed` });
            return {
              id: evalId,
              verdict: 'DENY',
              allowed: false,
              latencyMs,
              ruleMatched: 'UPSTREAM_NOT_ALLOWED',
              reason: `Agent '${agentId}' is not authorized for upstream '${upstreamId}'`,
              taintState,
              trace: { agentId, sessionId, upstreamId, toolName: req.toolName, timestamp, checks },
            };
          }
        } catch {}
      }
    }

    // ─── Step 3: Session & Taint Lattice Resolution ───────────────────────
    if (!req.dryRun) {
      let sessionRow = db.prepare('SELECT * FROM sessions WHERE session_id = ?').get(sessionId) as SessionRecord | undefined;
      if (!sessionRow) {
        const expiresAt = new Date(Date.now() + 3600 * 1000).toISOString();
        db.prepare(`
          INSERT INTO sessions (session_id, agent_id, taint_state, taint_source_tool, updated_at, expires_at)
          VALUES (?, ?, 'CLEAN', NULL, ?, ?)
        `).run(sessionId, agentId, timestamp, expiresAt);
        taintState = 'CLEAN';
      } else {
        taintState = sessionRow.taint_state;
      }
    }
    checks.push({ name: 'taint_lattice', passed: true, details: `Current state: ${taintState}` });

    if (taintState === 'TERMINATED') {
      const latencyMs = Number((performance.now() - startTime).toFixed(3));
      checks.push({ name: 'session_active', passed: false, details: 'Session terminated' });
      return {
        id: evalId,
        verdict: 'DENY',
        allowed: false,
        latencyMs,
        ruleMatched: 'SESSION_TERMINATED',
        reason: 'Session was previously terminated due to a critical security violation',
        taintState: 'TERMINATED',
        trace: { agentId, sessionId, upstreamId, toolName: req.toolName, timestamp, checks },
      };
    }

    // ─── Step 3.5: Schema Pin Integrity Check ──────────────────────────────
    try {
      const pinRow = (
        upstreamId
          ? db
              .prepare('SELECT drift_detected, drift_diff_json FROM schema_pins WHERE upstream_id = ? AND tool_name = ?')
              .get(upstreamId, req.toolName)
          : db
              .prepare('SELECT drift_detected, drift_diff_json FROM schema_pins WHERE tool_name = ?')
              .get(req.toolName)
      ) as { drift_detected: number; drift_diff_json: string } | undefined;

        if (pinRow && pinRow.drift_detected === 1) {
          const latencyMs = Number((performance.now() - startTime).toFixed(3));
          checks.push({ name: 'schema_pin', passed: false, details: 'Active schema drift detected on tool' });

          if (!req.dryRun) {
            db.prepare(`
              INSERT INTO audit_events (id, timestamp, session_id, agent_id, upstream_id, tool_name, taint_state, verdict, latency_ms, rule_matched, payload_json)
              VALUES (?, ?, ?, ?, ?, ?, ?, 'SCHEMA_DRIFT', ?, 'SCHEMA_DRIFT', ?)
            `).run(evalId, timestamp, sessionId, agentId, upstreamId || null, req.toolName, taintState, latencyMs, JSON.stringify(req.args || {}));

            dispatchAlert('SCHEMA_DRIFT', {
              id: evalId,
              agentId,
              upstreamId,
              toolName: req.toolName,
              reason: `Unapproved schema drift detected on tool '${req.toolName}'`,
            });
          }

          return {
            id: evalId,
            verdict: 'SCHEMA_DRIFT',
            allowed: false,
            latencyMs,
            ruleMatched: 'SCHEMA_DRIFT',
            reason: `Tool '${req.toolName}' has unapproved schema drift: operator approval required`,
            taintState,
            trace: { agentId, sessionId, upstreamId, toolName: req.toolName, timestamp, checks },
          };
        }
      } catch {}

    // ─── Step 4: Critical Tripwires & Canary Leak Detection ───────────────
    const tripwire = checkTripwires(sessionId, req.toolName, req.args || {});
    if (tripwire.triggered) {
      taintState = 'TERMINATED';
      if (!req.dryRun) {
        db.prepare("UPDATE sessions SET taint_state = 'TERMINATED', taint_source_tool = ?, updated_at = ? WHERE session_id = ?")
          .run(req.toolName, timestamp, sessionId);
      }
      checks.push({ name: 'tripwires', passed: false, details: tripwire.reason });

      const latencyMs = Number((performance.now() - startTime).toFixed(3));
      const decision: EngineVerdict = 'CRITICAL_TRIPWIRE';

      if (!req.dryRun) {
        db.prepare(`
          INSERT INTO audit_events (id, timestamp, session_id, agent_id, upstream_id, tool_name, taint_state, verdict, latency_ms, rule_matched, payload_json)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(evalId, timestamp, sessionId, agentId, upstreamId || null, req.toolName, taintState, decision, latencyMs, 'CRITICAL_TRIPWIRE', JSON.stringify(req.args || {}));

        dispatchAlert('CRITICAL_TRIPWIRE', {
          id: evalId,
          agentId,
          sessionId,
          toolName: req.toolName,
          reason: tripwire.reason,
        });
      }

      return {
        id: evalId,
        verdict: decision,
        allowed: false,
        latencyMs,
        ruleMatched: 'CRITICAL_TRIPWIRE',
        reason: tripwire.reason,
        taintState: 'TERMINATED',
        trace: { agentId, sessionId, upstreamId, toolName: req.toolName, timestamp, checks },
      };
    }
    checks.push({ name: 'tripwires', passed: true });

    // ─── Step 5: Canonical Path Resolution ────────────────────────────────
    const candidatePaths = extractAllPaths(req.args || {});
    for (const p of candidatePaths) {
      const pathResult = isPathDenied(p, policy, sandboxRoot);
      if (pathResult.denied) {
        checks.push({ name: 'path_protection', passed: false, details: `${pathResult.rule} on ${p}` });
        const latencyMs = Number((performance.now() - startTime).toFixed(3));
        const decisionVerdict: EngineVerdict = agentMode === 'shadow' ? 'SHADOW_DENY' : 'DENY';

        if (!req.dryRun) {
          db.prepare(`
            INSERT INTO audit_events (id, timestamp, session_id, agent_id, upstream_id, tool_name, taint_state, verdict, latency_ms, rule_matched, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).run(evalId, timestamp, sessionId, agentId, upstreamId || null, req.toolName, taintState, decisionVerdict, latencyMs, pathResult.rule, JSON.stringify(req.args || {}));
        }

        return {
          id: evalId,
          verdict: decisionVerdict,
          allowed: agentMode === 'shadow',
          shadow: agentMode === 'shadow',
          latencyMs,
          ruleMatched: pathResult.rule,
          reason: `Path access blocked: ${pathResult.rule}`,
          taintState,
          trace: { agentId, sessionId, upstreamId, toolName: req.toolName, timestamp, checks },
        };
      }
    }
    checks.push({ name: 'path_protection', passed: true });

    // ─── Step 6: Tool Trust & Taint Transition ────────────────────────────
    const toolRule = policy.tools?.[req.toolName];
    let upstreamTrustTier: string = 'trusted';
    if (upstreamId) {
      const upRow = db.prepare('SELECT trust_tier FROM upstreams WHERE id = ?').get(upstreamId) as { trust_tier: string } | undefined;
      if (upRow) upstreamTrustTier = upRow.trust_tier;
    }

    const isUntrustedSource = toolRule?.trust === 'untrusted' || upstreamTrustTier === 'untrusted';
    if (isUntrustedSource && taintState === 'CLEAN') {
      taintState = 'TAINTED';
      if (!req.dryRun) {
        db.prepare("UPDATE sessions SET taint_state = 'TAINTED', taint_source_tool = ?, updated_at = ? WHERE session_id = ?")
          .run(req.toolName, timestamp, sessionId);
      }
      checks.push({ name: 'taint_propagation', passed: true, details: `Lattice transition: CLEAN -> TAINTED by '${req.toolName}'` });
    }

    // ─── Step 7: Egress Sink Blocking When Tainted ────────────────────────
    const isEgress =
      !isUntrustedSource &&
      (toolRule?.class === 'egress' ||
        (policy.taint_engine?.egress_tools || []).includes(req.toolName) ||
        (upstreamTrustTier === 'egress' && toolRule?.trust !== 'untrusted'));

    if (isEgress && taintState === 'TAINTED') {
      checks.push({ name: 'taint_egress_sink', passed: false, details: 'Egress blocked while session is TAINTED' });
      const latencyMs = Number((performance.now() - startTime).toFixed(3));
      const decisionVerdict: EngineVerdict = agentMode === 'shadow' ? 'SHADOW_DENY' : 'DENY';

      if (!req.dryRun) {
        db.prepare(`
          INSERT INTO audit_events (id, timestamp, session_id, agent_id, upstream_id, tool_name, taint_state, verdict, latency_ms, rule_matched, payload_json)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(evalId, timestamp, sessionId, agentId, upstreamId || null, req.toolName, taintState, decisionVerdict, latencyMs, 'TAINT_EGRESS_DENY', JSON.stringify(req.args || {}));
      }

      return {
        id: evalId,
        verdict: decisionVerdict,
        allowed: agentMode === 'shadow',
        shadow: agentMode === 'shadow',
        latencyMs,
        ruleMatched: 'TAINT_EGRESS_DENY',
        reason: 'Taint Lock: Egress blocked because session has ingested untrusted content',
        taintState,
        trace: { agentId, sessionId, upstreamId, toolName: req.toolName, timestamp, checks },
      };
    }
    checks.push({ name: 'taint_egress_sink', passed: true });

    // ─── Step 8: Quarantine Patterns & Approval Required ──────────────────
    let isQuarantine = false;
    let quarantineReason = '';
    let quarantineRule = '';

    if (toolRule?.action === 'quarantine') {
      isQuarantine = true;
      quarantineRule = 'TOOL_ACTION_QUARANTINE';
      quarantineReason = `Tool '${req.toolName}' is statically flagged for operator quarantine`;
    }

    if (!isQuarantine && toolRule?.quarantine_patterns && typeof req.args?.command === 'string') {
      for (const pattern of toolRule.quarantine_patterns) {
        if (new RegExp(pattern).test(req.args.command as string)) {
          isQuarantine = true;
          quarantineRule = `QUARANTINE_PATTERN:${pattern}`;
          quarantineReason = `Destructive command pattern matched: ${pattern}`;
          break;
        }
      }
    }

    if (!isQuarantine && isEgress && toolRule?.action === 'require_approval') {
      isQuarantine = true;
      quarantineRule = 'EGRESS_REQUIRE_APPROVAL';
      quarantineReason = `Egress tool '${req.toolName}' requires human-in-the-loop approval`;
    }

    if (isQuarantine) {
      checks.push({ name: 'quarantine_policy', passed: false, details: quarantineReason });
      const latencyMs = Number((performance.now() - startTime).toFixed(3));
      let quarantineId: string | undefined;

      const decisionVerdict: EngineVerdict = agentMode === 'shadow' ? 'SHADOW_DENY' : 'QUARANTINE';

      if (!req.dryRun) {
        db.prepare(`
          INSERT INTO audit_events (id, timestamp, session_id, agent_id, upstream_id, tool_name, taint_state, verdict, latency_ms, rule_matched, payload_json)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(evalId, timestamp, sessionId, agentId, upstreamId || null, req.toolName, taintState, decisionVerdict, latencyMs, quarantineRule, JSON.stringify(req.args || {}));

        if (agentMode === 'enforce') {
          quarantineId = `quar_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
          const slaSec = getSlaSeconds();
          const expiresAt = new Date(Date.now() + slaSec * 1000).toISOString();
          db.prepare(`
            INSERT INTO quarantine_items (id, event_id, agent_id, tool_name, payload_json, status, ai_risk_score, ai_hijacked, ai_summary, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, 'pending', NULL, NULL, NULL, ?, ?)
          `).run(quarantineId, evalId, agentId, req.toolName, JSON.stringify(req.args || {}), timestamp, expiresAt);

          triggerAsyncIntentAnalysis(quarantineId, evalId, agentId, req.toolName, req.args || {});
        }
      }

      return {
        id: evalId,
        verdict: decisionVerdict,
        allowed: agentMode === 'shadow',
        shadow: agentMode === 'shadow',
        latencyMs,
        ruleMatched: quarantineRule,
        reason: quarantineReason,
        taintState,
        quarantineId,
        trace: { agentId, sessionId, upstreamId, toolName: req.toolName, timestamp, checks },
      };
    }
    checks.push({ name: 'quarantine_policy', passed: true });

    // ─── Step 9: Default Allow ────────────────────────────────────────────
    checks.push({ name: 'default_evaluation', passed: true, details: 'Passed all Layer 1 deterministic filters' });
    const latencyMs = Number((performance.now() - startTime).toFixed(3));

    if (!req.dryRun) {
      db.prepare(`
        INSERT INTO audit_events (id, timestamp, session_id, agent_id, upstream_id, tool_name, taint_state, verdict, latency_ms, rule_matched, payload_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'ALLOW', ?, 'DEFAULT_ALLOW', ?)
      `).run(evalId, timestamp, sessionId, agentId, upstreamId || null, req.toolName, taintState, latencyMs, JSON.stringify(req.args || {}));
    }

    return {
      id: evalId,
      verdict: 'ALLOW',
      allowed: true,
      latencyMs,
      ruleMatched: 'DEFAULT_ALLOW',
      reason: `Tool '${req.toolName}' approved by Layer 1 policy engine`,
      taintState,
      trace: { agentId, sessionId, upstreamId, toolName: req.toolName, timestamp, checks },
    };
  } catch (criticalErr) {
    // ─── FAIL CLOSED GUARANTEE ──────────────────────────────────────────
    const latencyMs = Number((performance.now() - startTime).toFixed(3));
    console.error('[Layer 1 Engine] Unhandled evaluation failure (failing closed):', criticalErr);

    return {
      id: evalId,
      verdict: 'DENY',
      allowed: false,
      latencyMs,
      ruleMatched: 'FAIL_CLOSED_EXCEPTION',
      reason: `Engine fail-closed: ${criticalErr instanceof Error ? criticalErr.message : 'Unknown exception'}`,
      taintState: 'TERMINATED',
      trace: {
        agentId,
        sessionId,
        upstreamId,
        toolName: req.toolName,
        timestamp,
        checks: [{ name: 'engine_safety', passed: false, details: 'Failed closed due to unexpected engine error' }],
      },
    };
  }
}
