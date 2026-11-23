import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { streamSSE } from 'hono/streaming';
import { serve } from '@hono/node-server';
import path from 'node:path';

import { initKeys, issueToken, verifyToken, TokenRequestSchema } from './auth/tokens.js';
import { evaluate, loadPolicy, getRawPolicy, EvaluateRequestSchema, EvaluationResult } from './policy/engine.js';

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

  auditLog.push(result);
  broadcast('evaluation', result);

  // If QUARANTINE, hold the response until resolved
  if (result.verdict === 'QUARANTINE') {
    broadcast('quarantine', result);

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
  return c.json({ status: 'resolved', id, action });
});

// GET /quarantine — List pending quarantines
app.get('/quarantine', (c) => {
  const items = Array.from(pendingQuarantines.entries()).map(([quarantineId, pq]) => ({
    quarantine_id: quarantineId,
    ...pq.result,
  }));
  return c.json(items);
});

// GET /policy — Raw policy.yaml
app.get('/policy', (c) => {
  return c.text(getRawPolicy());
});

// GET /logs — Audit log
app.get('/logs', (c) => {
  return c.json(auditLog);
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

// Health check
app.get('/', (c) => {
  return c.json({ service: 'aegisveto-core', status: 'active', engine: 'deterministic', llm_in_guard: false });
});

// ─── Start ───────────────────────────────────────────────────────
async function main(): Promise<void> {
  // Load policy from project root
  const policyPath = path.resolve(process.cwd(), 'policy.yaml');
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
