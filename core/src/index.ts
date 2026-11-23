import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { streamSSE } from 'hono/streaming';
import { serve } from '@hono/node-server';
import path from 'node:path';
import fs from 'node:fs';

import { initKeys, issueToken, verifyToken, TokenRequestSchema } from './auth/tokens.js';
import { evaluate, loadPolicy, getRawPolicy, EvaluateRequestSchema, EvaluationResult } from './policy/engine.js';
import { runAgentScenario, RunnerOptions } from './agent/runner.js';
import { initDb, insertAuditLog, getAuditLogs, getAuditMetrics } from './db/audit.js';
import { analyzeIntent, AIAssessment } from './ai/intent.js';
import { suggestPolicyRule, validateAndApplyPolicy } from './ai/patcher.js';

const app = new Hono();

// ─── CORS ────────────────────────────────────────────────────────
app.use('*', cors({
  origin: ['http://localhost:5173', 'http://127.0.0.1:5173'],
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
}));

// ─── In-Memory Log & SSE ─────────────────────────────────────────
const auditLog: EvaluationResult[] = [];
type SSEClient = { send: (data: string) => void };
const sseClients: Set<SSEClient> = new Set();

function broadcast(event: string, data: unknown): void {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const client of sseClients) {
    try { client.send(payload); } catch { sseClients.delete(client); }
  }
}

// ─── Quarantine Pending Map ──────────────────────────────────────
interface PendingQuarantine {
  result: EvaluationResult;
  resolve: (action: 'APPROVE' | 'VETO') => void;
  ai_assessment?: AIAssessment;
}
const pendingQuarantines = new Map<string, PendingQuarantine>();

// ─── Routes ──────────────────────────────────────────────────────

// POST /tokens — Issue JWT
app.post('/tokens', async (c) => {
  const body = await c.req.json();
  const parsed = TokenRequestSchema.safeParse(body);
  if (!parsed.success) {
    return c.json({ error: 'Invalid request', details: parsed.error.flatten() }, 400);
  }
  const result = await issueToken(parsed.data);
  return c.json(result, 201);
});

// POST /evaluate — Verify JWT, run policy engine
app.post('/evaluate', async (c) => {
  const body = await c.req.json();
  const parsed = EvaluateRequestSchema.safeParse(body);
  if (!parsed.success) {
    return c.json({ error: 'Invalid request', details: parsed.error.flatten() }, 400);
  }

  // Verify JWT
  let tokenPayload;
  try {
    tokenPayload = await verifyToken(parsed.data.token);
  } catch (err) {
    return c.json({ error: 'JWT verification failed', message: err instanceof Error ? err.message : 'Unknown' }, 401);
  }

  // Check tool is in allowed scopes
  if (!tokenPayload.allowed_scopes.includes(parsed.data.tool) && !tokenPayload.allowed_scopes.includes('*')) {
    return c.json({
      verdict: 'DENY',
      reason: `Tool '${parsed.data.tool}' is not in allowed scopes`,
      rule_matched: 'JWT_SCOPE_VIOLATION',
    }, 403);
  }

  // Run deterministic policy engine
  const result = evaluate({
    session_id: tokenPayload.session_id,
    tool: parsed.data.tool,
    args: parsed.data.args,
    max_calls: tokenPayload.max_calls,
  });

  // Record to SQLite audit database
  insertAuditLog({
    id: result.id,
    timestamp: result.timestamp,
    session_id: result.session_id,
    provider: 'direct',
    model: 'deterministic',
    tool_name: result.tool,
    taint_state: result.taint,
    decision: result.verdict,
    latency_ms: result.latency_ms,
    reason: result.reason,
    payload_json: JSON.stringify(result.args),
    mode: 'protected',
  });

  broadcast('evaluation', {
    ...result,
    provider: 'direct',
    model: 'deterministic',
  });

  // If QUARANTINE, hold the response until resolved
  if (result.verdict === 'QUARANTINE') {
    broadcast('quarantine', result);

    // Layer 2 AI Security Brain: Run semantic intent verifier asynchronously
    analyzeIntent({
      toolName: result.tool,
      args: result.args,
      recentContext: result.reason,
    })
      .then((assessment) => {
        const pending = pendingQuarantines.get(result.id);
        if (pending) {
          pending.ai_assessment = assessment;
        }
        broadcast('quarantine_analyzed', {
          id: result.id,
          ai_assessment: assessment,
        });
      })
      .catch((err) => {
        console.warn('[L2 Security Brain] Intent analysis warning:', err);
      });

    const resolution = await new Promise<'APPROVE' | 'VETO'>((resolve) => {
      pendingQuarantines.set(result.id, { result, resolve });
    });

    pendingQuarantines.delete(result.id);

    const finalVerdict = resolution === 'APPROVE' ? 'ALLOW' : 'DENY';
    const resolved = { ...result, verdict: finalVerdict, reason: `${result.reason} [Operator: ${resolution}]` };
    broadcast('quarantine_resolved', { id: result.id, action: resolution, result: resolved });
    return c.json(resolved);
  }

  return c.json(result);
});

// POST /quarantine/:id/resolve — Resolve pending quarantine
app.post('/quarantine/:id/resolve', async (c) => {
  const { id } = c.req.param();
  const body = await c.req.json();
  const action = body.action as 'APPROVE' | 'VETO';

  if (action !== 'APPROVE' && action !== 'VETO') {
    return c.json({ error: 'action must be APPROVE or VETO' }, 400);
  }

  const pending = pendingQuarantines.get(id);
  if (!pending) {
    return c.json({ error: 'No pending quarantine with that id' }, 404);
  }

  pending.resolve(action);

  // Record quarantine resolution in SQLite
  insertAuditLog({
    id: `res-${id}-${Date.now()}`,
    timestamp: new Date().toISOString(),
    session_id: pending.result.session_id,
    provider: 'operator',
    model: 'human-in-the-loop',
    tool_name: pending.result.tool,
    taint_state: pending.result.taint,
    decision: action === 'APPROVE' ? 'ALLOW' : 'DENY',
    latency_ms: 0,
    reason: `Quarantine manually ${action === 'APPROVE' ? 'Approved' : 'Vetoed'} by operator`,
    payload_json: JSON.stringify(pending.result.args),
    mode: 'quarantine_resolution',
  });

  return c.json({ status: 'resolved', id, action });
});

// GET /quarantine — List pending quarantines
app.get('/quarantine', (c) => {
  const items = Array.from(pendingQuarantines.entries()).map(([quarantineId, pq]) => ({
    quarantine_id: quarantineId,
    ...pq.result,
    ai_assessment: pq.ai_assessment,
  }));
  return c.json(items);
});

// POST /policy/suggest — AI Policy Auto-Patcher ("Learn Once, Enforce Forever")
app.post('/policy/suggest', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const toolName = body.toolName || body.tool || 'unknown_tool';
  const args = body.args || {};
  const reason = body.reason || '';
  const provider = body.provider;

  const suggestion = await suggestPolicyRule({
    toolName,
    args,
    reason,
    currentPolicyYaml: getRawPolicy(),
    provider,
  });

  return c.json(suggestion);
});

// POST /policy/apply — Validate and apply auto-patched rule
app.post('/policy/apply', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  let yamlToApply = body.policyYaml;

  if (!yamlToApply && body.suggestedYaml) {
    yamlToApply = body.suggestedYaml;
  }

  // If snippet provided, merge/append into policy.yaml
  if (!yamlToApply && body.snippet) {
    const current = getRawPolicy();
    yamlToApply = `${current.trim()}\n\n# Auto-patched rule\n${body.snippet.trim()}\n`;
  }

  if (!yamlToApply) {
    return c.json({ error: 'policyYaml, suggestedYaml, or snippet is required' }, 400);
  }

  const result = validateAndApplyPolicy(yamlToApply);
  if (!result.success) {
    return c.json({ error: result.error }, 400);
  }

  // Hot-reload Layer 1 policy in memory
  let curr = process.cwd();
  let policyPath = path.join(curr, 'policy.yaml');
  while (!fs.existsSync(policyPath) && curr !== path.dirname(curr)) {
    curr = path.dirname(curr);
    policyPath = path.join(curr, 'policy.yaml');
  }
  loadPolicy(policyPath);
  broadcast('policy_updated', { timestamp: new Date().toISOString() });

  return c.json({ status: 'applied', policy: getRawPolicy() });
});

// GET /policy — Raw policy.yaml
app.get('/policy', (c) => {
  return c.text(getRawPolicy());
});

// GET /audit — SQLite logs + KPI metrics
app.get('/audit', (c) => {
  const logs = getAuditLogs(100);
  const metrics = getAuditMetrics(pendingQuarantines.size);
  return c.json({ logs, metrics });
});

// GET /logs — Backward-compatible endpoint returning raw SQLite logs
app.get('/logs', (c) => {
  return c.json(getAuditLogs(100));
});

// GET /events — SSE stream
app.get('/events', (c) => {
  return streamSSE(c, async (stream) => {
    const client: SSEClient = {
      send: (data: string) => { stream.write(data); },
    };
    sseClients.add(client);

    // Send initial connection event
    await stream.writeSSE({ event: 'connected', data: JSON.stringify({ status: 'ok', timestamp: new Date().toISOString() }) });

    // Keep alive until client disconnects
    while (true) {
      await stream.sleep(30000);
      await stream.writeSSE({ event: 'ping', data: '{}' });
    }
  });
});

// POST /demo/run — Run scenario through agent runner
app.post('/demo/run', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const scenario = body.scenario === 'attack' ? 'attack' : 'benign';
  const isProtected = body.protected !== false;
  const provider = (body.provider as RunnerOptions['provider']) || 'ollama';

  const result = await runAgentScenario({
    scenario,
    protected: isProtected,
    provider,
  });

  // Persist execution steps in SQLite and broadcast evaluation events
  for (const step of result.trace) {
    if (step.evaluation) {
      insertAuditLog({
        id: step.evaluation.id,
        timestamp: step.evaluation.timestamp,
        session_id: result.session_id,
        provider: result.provider,
        model: result.model,
        tool_name: step.evaluation.tool,
        taint_state: step.evaluation.taint,
        decision: step.evaluation.verdict,
        latency_ms: step.evaluation.latency_ms,
        reason: step.evaluation.reason,
        payload_json: JSON.stringify(step.evaluation.args),
        mode: isProtected ? 'protected' : 'raw',
      });

      broadcast('evaluation', {
        ...step.evaluation,
        provider: result.provider,
        model: result.model,
      });
    } else if (step.type === 'tool_call' && !isProtected) {
      const toolName = step.tool || 'unknown';
      const syntheticId = `raw-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
      const timestamp = new Date().toISOString();

      insertAuditLog({
        id: syntheticId,
        timestamp,
        session_id: result.session_id,
        provider: result.provider,
        model: result.model,
        tool_name: toolName,
        taint_state: 'TAINTED',
        decision: 'ALLOW',
        latency_ms: 0.05,
        reason: 'RAW_UNPROTECTED: AegisVeto bypassed by test configuration',
        payload_json: JSON.stringify(step.args || {}),
        mode: 'raw',
      });

      broadcast('evaluation', {
        id: syntheticId,
        timestamp,
        session_id: result.session_id,
        provider: result.provider,
        model: result.model,
        tool: toolName,
        args: step.args || {},
        taint: 'TAINTED',
        verdict: 'ALLOW',
        latency_ms: 0.05,
        reason: 'RAW_UNPROTECTED: AegisVeto bypassed by test configuration',
      });
    }
  }

  broadcast('demo_run', result);
  return c.json(result);
});

// Health check
app.get('/', (c) => {
  return c.json({ service: 'aegisveto-core', status: 'active', engine: 'deterministic', llm_in_guard: false });
});

// ─── Start ───────────────────────────────────────────────────────
async function main(): Promise<void> {
  // Initialize SQLite database
  initDb();
  console.log('[AegisVeto] SQLite audit database initialized');

  // Load policy from project root
  let curr = process.cwd();
  let policyPath = path.join(curr, 'policy.yaml');
  while (!fs.existsSync(policyPath) && curr !== path.dirname(curr)) {
    curr = path.dirname(curr);
    policyPath = path.join(curr, 'policy.yaml');
  }
  loadPolicy(policyPath);
  console.log('[AegisVeto] Policy loaded from', policyPath);

  // Generate EdDSA key pair
  await initKeys();
  console.log('[AegisVeto] EdDSA key pair initialized');

  // Start server
  serve({ fetch: app.fetch, port: 3000 }, (info) => {
    console.log(`[AegisVeto] Core proxy listening on http://localhost:${info.port}`);
  });
}

main().catch(console.error);

export { app };
