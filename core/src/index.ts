import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { streamSSE } from 'hono/streaming';
import { serve } from '@hono/node-server';
import path from 'node:path';
import fs from 'node:fs';
import yaml from 'js-yaml';
import { z } from 'zod';

import { initKeys, issueToken, verifyToken, getKeyFingerprint, TokenRequestSchema } from './auth/tokens.js';
import {
  getDb,
  findRepoRoot,
  AgentRecord,
  UpstreamRecord,
  SchemaPinRecord,
  PolicyVersionRecord,
  AuditEventRecord,
  QuarantineItemRecord,
  ServiceSettingRecord,
} from './db/schema.js';
import {
  evaluateDeterministic,
  getActivePolicy,
  loadActivePolicy,
  EvaluateRequest,
  EvaluateResponse,
  setEvaluationListener,
} from './engine/evaluate.js';
import { approvePin } from './security/schemaPinning.js';
import { httpMcpGateway } from './mcp/httpGateway.js';
import { suggestPolicyRule } from './ai/patcher.js';
import { dispatchAlert } from './alerts/webhook.js';
import { serveStatic } from '@hono/node-server/serve-static';

const app = new Hono();

// Mount Streamable HTTP MCP Reverse Proxy
app.route('/v1/mcp', httpMcpGateway);

// ─── CORS ────────────────────────────────────────────────────────
app.use(
  '*',
  cors({
    origin: ['http://localhost:5173', 'http://127.0.0.1:5173', 'http://localhost:3000'],
    allowMethods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization'],
  })
);

// ─── SSE Broadcast Bus ───────────────────────────────────────────
type SSEClient = { send: (data: string) => void };
const sseClients: Set<SSEClient> = new Set();

export function broadcastSSE(event: string, data: unknown): void {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const client of sseClients) {
    try {
      client.send(payload);
    } catch {
      sseClients.delete(client);
    }
  }
}

setEvaluationListener(broadcastSSE);

// ─── SLA Auto-Deny Sweeper: Lightweight interval (every 5s) ────────
export function sweepExpiredApprovals(): void {
  try {
    const db = getDb();
    const now = new Date().toISOString();
    const expiredRows = db.prepare(`
      SELECT * FROM quarantine_items
      WHERE status = 'pending' AND expires_at <= ?
    `).all(now) as QuarantineItemRecord[];

    if (expiredRows.length > 0) {
      db.prepare(`
        UPDATE quarantine_items
        SET status = 'expired'
        WHERE status = 'pending' AND expires_at <= ?
      `).run(now);

      for (const item of expiredRows) {
        broadcastSSE('approval_expired', {
          id: item.id,
          eventId: item.event_id,
          agentId: item.agent_id,
          toolName: item.tool_name,
          expiredAt: now,
        });

        // Fail-closed audit event
        const evalId = `eval_exp_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
        db.prepare(`
          INSERT INTO audit_events (id, timestamp, session_id, agent_id, upstream_id, tool_name, taint_state, verdict, latency_ms, rule_matched, payload_json)
          VALUES (?, ?, ?, ?, NULL, ?, 'CLEAN', 'DENY', 0.0, 'SLA_TIMEOUT_EXPIRED', ?)
        `).run(evalId, now, `sess_quar_${item.id}`, item.agent_id, item.tool_name, item.payload_json);
      }
    }
  } catch (err) {
    console.error('[SLA Sweeper] Failed to expire overdue items:', err);
  }
}

function expireOverdueApprovals(): void {
  sweepExpiredApprovals();
}

// ─────────────────────────────────────────────────────────────────
// 1. OVERVIEW: GET /v1/overview
// ─────────────────────────────────────────────────────────────────
app.get('/v1/overview', (c) => {
  const db = getDb();
  expireOverdueApprovals();

  const now = Date.now();
  const oneDayAgo = new Date(now - 24 * 60 * 60 * 1000).toISOString();

  // Aggregate counts
  const totalRow = db.prepare('SELECT COUNT(*) as c FROM audit_events WHERE timestamp >= ?').get(oneDayAgo) as { c: number };
  const allowedRow = db.prepare("SELECT COUNT(*) as c FROM audit_events WHERE verdict = 'ALLOW' AND timestamp >= ?").get(oneDayAgo) as { c: number };
  const quarantinedRow = db.prepare("SELECT COUNT(*) as c FROM audit_events WHERE verdict = 'QUARANTINE' AND timestamp >= ?").get(oneDayAgo) as { c: number };
  const shadowDeniedRow = db.prepare("SELECT COUNT(*) as c FROM audit_events WHERE verdict = 'SHADOW_DENY' AND timestamp >= ?").get(oneDayAgo) as { c: number };
  const vetoedRow = db.prepare("SELECT COUNT(*) as c FROM quarantine_items WHERE status = 'vetoed' AND created_at >= ?").get(oneDayAgo) as { c: number };

  // Calculate p95 latency
  const latencies = db.prepare('SELECT latency_ms FROM audit_events WHERE timestamp >= ? ORDER BY latency_ms ASC').all(oneDayAgo) as { latency_ms: number }[];
  let p95LatencyMs = 0;
  if (latencies.length > 0) {
    const idx = Math.min(Math.floor(latencies.length * 0.95), latencies.length - 1);
    p95LatencyMs = Number(latencies[idx].latency_ms.toFixed(2));
  } else {
    // Check all-time fallback
    const allLats = db.prepare('SELECT latency_ms FROM audit_events ORDER BY latency_ms ASC LIMIT 500').all() as { latency_ms: number }[];
    if (allLats.length > 0) {
      const idx = Math.min(Math.floor(allLats.length * 0.95), allLats.length - 1);
      p95LatencyMs = Number(allLats[idx].latency_ms.toFixed(2));
    }
  }

  // Active agents count
  const agentsRow = db.prepare("SELECT COUNT(*) as c FROM agents WHERE status = 'active'").get() as { c: number };

  // Active incidents (blocked/tripwire/drift events in 24h + pending quarantines)
  const incidentsRow = db.prepare(`
    SELECT COUNT(*) as c FROM audit_events
    WHERE verdict IN ('DENY', 'CRITICAL_TRIPWIRE', 'SCHEMA_DRIFT') AND timestamp >= ?
  `).get(oneDayAgo) as { c: number };

  const pendingQuarRow = db.prepare("SELECT COUNT(*) as c FROM quarantine_items WHERE status = 'pending'").get() as { c: number };
  const activeIncidents = incidentsRow.c + pendingQuarRow.c;

  // Recent blocked events
  const recentBlocked = db.prepare(`
    SELECT id, timestamp, agent_id as agentId, tool_name as toolName, verdict, rule_matched as ruleMatched, latency_ms as latencyMs
    FROM audit_events
    WHERE verdict IN ('DENY', 'CRITICAL_TRIPWIRE', 'SCHEMA_DRIFT', 'SHADOW_DENY')
    ORDER BY timestamp DESC
    LIMIT 5
  `).all();

  return c.json({
    total: totalRow.c,
    allowed: allowedRow.c,
    quarantined: quarantinedRow.c,
    vetoed: vetoedRow.c,
    shadowDenied: shadowDeniedRow.c,
    p95LatencyMs,
    activeAgents: agentsRow.c,
    activeIncidents,
    recentBlocked,
  });
});

// ─────────────────────────────────────────────────────────────────
// 2. AUDIT LOG & SSE: GET /v1/events, GET /v1/events/stream
// ─────────────────────────────────────────────────────────────────
app.get('/v1/events', (c) => {
  const db = getDb();
  const agentId = c.req.query('agentId');
  const verdict = c.req.query('verdict');
  const taint = c.req.query('taint');
  const search = c.req.query('search');
  const limit = Math.min(Number(c.req.query('limit')) || 100, 500);

  let query = 'SELECT * FROM audit_events WHERE 1=1';
  const params: unknown[] = [];

  if (agentId) {
    query += ' AND agent_id = ?';
    params.push(agentId);
  }
  if (verdict) {
    query += ' AND verdict = ?';
    params.push(verdict);
  }
  if (taint) {
    query += ' AND taint_state = ?';
    params.push(taint);
  }
  if (search) {
    query += ' AND (tool_name LIKE ? OR rule_matched LIKE ? OR payload_json LIKE ?)';
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }

  query += ' ORDER BY timestamp DESC LIMIT ?';
  params.push(limit);

  const rows = db.prepare(query).all(...params) as AuditEventRecord[];
  return c.json(rows);
});

app.get('/v1/events/stream', (c) => {
  return streamSSE(c, async (stream) => {
    const client: SSEClient = {
      send: (data: string) => {
        stream.write(data);
      },
    };
    sseClients.add(client);

    await stream.writeSSE({
      event: 'connected',
      data: JSON.stringify({ status: 'ok', timestamp: new Date().toISOString() }),
    });

    while (true) {
      await stream.sleep(25000);
      await stream.writeSSE({ event: 'ping', data: '{}' });
    }
  });
});

// ─────────────────────────────────────────────────────────────────
// 3. ENFORCEMENT: POST /v1/evaluate
// ─────────────────────────────────────────────────────────────────
app.post('/v1/evaluate', async (c) => {
  const body = await c.req.json().catch(() => ({}));

  // Extract auth header token if present
  const authHeader = c.req.header('Authorization');
  let token = body.token;
  if (!token && authHeader?.startsWith('Bearer ')) {
    token = authHeader.slice(7);
  }

  const toolName = body.toolName || body.tool;
  if (!toolName || typeof toolName !== 'string') {
    return c.json({ error: 'toolName is required' }, 400);
  }

  let agentId = body.agentId;
  let sessionId = body.sessionId;

  // If Ed25519 token passed, verify it
  if (token) {
    try {
      const payload = await verifyToken(token);
      agentId = payload.agent_id;
      sessionId = payload.session_id || sessionId;

      // Check scope
      if (!payload.allowed_scopes.includes('*') && !payload.allowed_scopes.includes(toolName)) {
        return c.json(
          {
            verdict: 'DENY',
            allowed: false,
            latencyMs: 0.1,
            ruleMatched: 'JWT_SCOPE_VIOLATION',
            reason: `Tool '${toolName}' not in token allowed_scopes`,
            taintState: 'CLEAN',
          },
          403
        );
      }
    } catch (err) {
      return c.json(
        {
          verdict: 'DENY',
          allowed: false,
          latencyMs: 0.1,
          ruleMatched: 'JWT_INVALID',
          reason: err instanceof Error ? err.message : 'Invalid token',
          taintState: 'TERMINATED',
        },
        401
      );
    }
  }

  const evalReq: EvaluateRequest = {
    token,
    agentId,
    sessionId,
    upstreamId: body.upstreamId,
    toolName,
    args: body.args || {},
    dryRun: body.dryRun === true,
    simulatedTaint: body.simulatedTaint,
  };

  const response: EvaluateResponse = evaluateDeterministic(evalReq);

  // Broadcast live evaluation if not dryRun
  if (!body.dryRun) {
    broadcastSSE('evaluation', {
      id: response.id,
      timestamp: response.trace.timestamp,
      sessionId: response.trace.sessionId,
      agentId: response.trace.agentId,
      toolName: response.trace.toolName,
      verdict: response.verdict,
      allowed: response.allowed,
      shadow: response.shadow,
      latencyMs: response.latencyMs,
      ruleMatched: response.ruleMatched,
      taintState: response.taintState,
    });

    if (response.verdict === 'QUARANTINE') {
      broadcastSSE('quarantine', {
        id: response.quarantineId,
        eventId: response.id,
        agentId: response.trace.agentId,
        toolName: response.trace.toolName,
        args: body.args || {},
      });
    }
  }

  return c.json(response);
});

// ─────────────────────────────────────────────────────────────────
// 4. AGENTS: GET/POST /v1/agents, PATCH /v1/agents/:id, POST /v1/agents/:id/tokens
// ─────────────────────────────────────────────────────────────────
app.get('/v1/agents', (c) => {
  const db = getDb();
  const rows = db.prepare('SELECT * FROM agents ORDER BY created_at DESC').all() as AgentRecord[];
  return c.json(
    rows.map((r) => ({
      ...r,
      allowed_upstreams: JSON.parse(r.allowed_upstreams_json),
    }))
  );
});

app.post('/v1/agents', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const id = body.id || `agent_${Math.random().toString(36).slice(2, 8)}`;
  const name = body.name || id;
  const mode = body.mode === 'shadow' ? 'shadow' : 'enforce';
  const allowedUpstreams = Array.isArray(body.allowedUpstreams) ? body.allowedUpstreams : ['*'];
  const status = body.status === 'revoked' ? 'revoked' : 'active';
  const now = new Date().toISOString();

  const db = getDb();
  db.prepare(`
    INSERT INTO agents (id, name, mode, allowed_upstreams_json, key_fingerprint, status, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(id, name, mode, JSON.stringify(allowedUpstreams), getKeyFingerprint(), status, now);

  return c.json(
    {
      id,
      name,
      mode,
      allowed_upstreams: allowedUpstreams,
      status,
      created_at: now,
    },
    201
  );
});

app.patch('/v1/agents/:id', async (c) => {
  const { id } = c.req.param();
  const body = await c.req.json().catch(() => ({}));
  const db = getDb();

  const existing = db.prepare('SELECT * FROM agents WHERE id = ?').get(id) as AgentRecord | undefined;
  if (!existing) {
    return c.json({ error: `Agent '${id}' not found` }, 404);
  }

  const newMode = body.mode ? (body.mode === 'shadow' ? 'shadow' : 'enforce') : existing.mode;
  const newStatus = body.status ? (body.status === 'revoked' ? 'revoked' : 'active') : existing.status;
  const newUpstreams = body.allowedUpstreams ? JSON.stringify(body.allowedUpstreams) : existing.allowed_upstreams_json;
  const newName = body.name || existing.name;

  db.prepare(`
    UPDATE agents
    SET name = ?, mode = ?, status = ?, allowed_upstreams_json = ?
    WHERE id = ?
  `).run(newName, newMode, newStatus, newUpstreams, id);

  const updated = db.prepare('SELECT * FROM agents WHERE id = ?').get(id) as AgentRecord;
  return c.json({
    ...updated,
    allowed_upstreams: JSON.parse(updated.allowed_upstreams_json),
  });
});

app.post('/v1/agents/:id/tokens', async (c) => {
  const { id } = c.req.param();
  const body = await c.req.json().catch(() => ({}));
  const db = getDb();

  const agent = db.prepare('SELECT * FROM agents WHERE id = ?').get(id) as AgentRecord | undefined;
  if (!agent) {
    return c.json({ error: `Agent '${id}' not found` }, 404);
  }

  const tokenData = await issueToken({
    agent_id: id,
    session_id: body.sessionId,
    allowed_scopes: Array.isArray(body.allowedScopes) ? body.allowedScopes : ['*'],
    max_calls: Number(body.maxCalls) || 100,
    ttl_sec: Number(body.ttlSec) || 900,
  });

  // Update agent key fingerprint
  db.prepare('UPDATE agents SET key_fingerprint = ? WHERE id = ?').run(tokenData.key_fingerprint, id);

  return c.json(tokenData, 201);
});

// ─────────────────────────────────────────────────────────────────
// 5. UPSTREAMS & SCHEMA PINS: GET/POST/DELETE /v1/upstreams, GET/POST pins
// ─────────────────────────────────────────────────────────────────
app.get('/v1/upstreams', (c) => {
  const db = getDb();
  const rows = db.prepare('SELECT * FROM upstreams ORDER BY created_at DESC').all() as UpstreamRecord[];
  return c.json(rows);
});

app.post('/v1/upstreams', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const id = body.id || `ups_${Math.random().toString(36).slice(2, 8)}`;
  const name = body.name || id;
  const transport = body.transport === 'http' ? 'http' : 'stdio';
  const commandOrUrl = body.commandOrUrl || body.command_or_url || '';
  const trustTier = ['trusted', 'untrusted', 'egress'].includes(body.trustTier) ? body.trustTier : 'trusted';
  const vaultSecretRef = body.vaultSecretRef || null;
  const status = body.status || 'active';
  const now = new Date().toISOString();

  const db = getDb();
  db.prepare(`
    INSERT INTO upstreams (id, name, transport, command_or_url, trust_tier, vault_secret_ref, status, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, name, transport, commandOrUrl, trustTier, vaultSecretRef, status, now);

  return c.json(
    {
      id,
      name,
      transport,
      command_or_url: commandOrUrl,
      trust_tier: trustTier,
      vault_secret_ref: vaultSecretRef,
      status,
      created_at: now,
    },
    201
  );
});

app.delete('/v1/upstreams/:id', (c) => {
  const { id } = c.req.param();
  const db = getDb();
  db.prepare('DELETE FROM upstreams WHERE id = ?').run(id);
  db.prepare('DELETE FROM schema_pins WHERE upstream_id = ?').run(id);
  return c.json({ status: 'deleted', id });
});

app.get('/v1/upstreams/:id/pins', (c) => {
  const { id } = c.req.param();
  const db = getDb();
  const rows = db.prepare('SELECT * FROM schema_pins WHERE upstream_id = ? ORDER BY approved_at DESC').all(id) as SchemaPinRecord[];
  return c.json(
    rows.map((r) => ({
      ...r,
      canonical_schema: JSON.parse(r.canonical_schema_json || '{}'),
      drift_diff: r.drift_diff_json ? JSON.parse(r.drift_diff_json) : null,
    }))
  );
});

app.post('/v1/upstreams/:id/pins/:pinId/approve', (c) => {
  const { id, pinId } = c.req.param();
  const ok = approvePin(id, pinId);

  if (!ok) {
    return c.json({ error: 'Pin not found for upstream' }, 404);
  }

  return c.json({ status: 'approved', pinId, approved_at: new Date().toISOString() });
});

// ─────────────────────────────────────────────────────────────────
// 6. POLICIES: GET active, GET versions, PUT active, POST simulate
// ─────────────────────────────────────────────────────────────────
app.get('/v1/policies/active', (c) => {
  const { config, raw } = getActivePolicy();
  const db = getDb();
  const activeVersion = db.prepare('SELECT * FROM policy_versions WHERE is_active = 1 LIMIT 1').get() as PolicyVersionRecord | undefined;

  return c.json({
    version: activeVersion?.version || 1,
    yamlContent: raw,
    author: activeVersion?.author || 'system',
    createdAt: activeVersion?.created_at || new Date().toISOString(),
    parsed: config,
  });
});

app.get('/v1/policies/versions', (c) => {
  const db = getDb();
  const rows = db.prepare('SELECT id, version, author, is_active, created_at FROM policy_versions ORDER BY version DESC').all() as PolicyVersionRecord[];
  return c.json(rows);
});

app.put('/v1/policies/active', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const yamlContent = body.yamlContent || body.yaml;
  const author = body.author || 'operator';

  if (!yamlContent || typeof yamlContent !== 'string') {
    return c.json({ error: 'yamlContent string is required' }, 400);
  }

  // Validate with js-yaml and schema
  let parsed: unknown;
  try {
    parsed = yaml.load(yamlContent);
    if (!parsed || typeof parsed !== 'object') {
      throw new Error('YAML must evaluate to a valid object');
    }
  } catch (err) {
    return c.json({ error: 'Invalid YAML format', details: err instanceof Error ? err.message : String(err) }, 400);
  }

  const db = getDb();
  const maxRow = db.prepare('SELECT MAX(version) as max_v FROM policy_versions').get() as { max_v: number | null };
  const nextVersion = (maxRow?.max_v || 0) + 1;
  const id = `pol-v${nextVersion}`;
  const now = new Date().toISOString();

  // Deactivate old active version
  db.prepare('UPDATE policy_versions SET is_active = 0 WHERE is_active = 1').run();

  // Insert new active version
  db.prepare(`
    INSERT INTO policy_versions (id, version, yaml_content, author, is_active, created_at)
    VALUES (?, ?, ?, ?, 1, ?)
  `).run(id, nextVersion, yamlContent, author, now);

  // Write root policy.yaml
  try {
    const root = findRepoRoot();
    const policyPath = path.join(root, 'policy.yaml');
    fs.writeFileSync(policyPath, yamlContent, 'utf-8');
  } catch (err) {
    console.warn('[Policy] Failed to write root policy.yaml:', err);
  }

  // Hot reload Layer 1 engine
  loadActivePolicy(yamlContent);
  broadcastSSE('policy_updated', { version: nextVersion, timestamp: now, author });

  return c.json({
    status: 'applied',
    version: nextVersion,
    active: true,
    yamlContent,
  });
});

app.post('/v1/policies/simulate', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const toolName = body.toolName || body.tool;
  if (!toolName) {
    return c.json({ error: 'toolName is required' }, 400);
  }

  // Optional ephemeral policy override for simulation
  if (body.policyYaml) {
    loadActivePolicy(body.policyYaml);
  }

  const simResult = evaluateDeterministic({
    agentId: body.agentId || 'local-dev-agent',
    toolName,
    args: body.args || {},
    dryRun: true,
    simulatedTaint: body.simulatedTaint || 'CLEAN',
  });

  // Reset to DB active policy if overridden
  if (body.policyYaml) {
    loadActivePolicy();
  }

  return c.json({
    simulation: true,
    ...simResult,
  });
});

app.post('/v1/policies/suggest', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const toolName = body.toolName || body.tool;
  if (!toolName) {
    return c.json({ error: 'toolName is required' }, 400);
  }

  const suggestion = await suggestPolicyRule({
    toolName,
    args: body.args || {},
    reason: body.reason,
  });

  return c.json(suggestion);
});

// ─────────────────────────────────────────────────────────────────
// 7. APPROVALS: GET /v1/approvals, POST /v1/approvals/:id/resolve
// ─────────────────────────────────────────────────────────────────
app.get('/v1/approvals', (c) => {
  const db = getDb();
  expireOverdueApprovals();

  const rows = db.prepare(`
    SELECT q.*, a.rule_matched, a.latency_ms, a.session_id
    FROM quarantine_items q
    LEFT JOIN audit_events a ON q.event_id = a.id
    WHERE q.status = 'pending'
    ORDER BY q.created_at DESC
  `).all();

  return c.json(
    rows.map((r: any) => ({
      id: r.id,
      eventId: r.event_id,
      agentId: r.agent_id,
      sessionId: r.session_id,
      toolName: r.tool_name,
      payload: JSON.parse(r.payload_json || '{}'),
      status: r.status,
      aiRiskScore: r.ai_risk_score,
      aiHijacked: r.ai_hijacked,
      aiSummary: r.ai_summary,
      createdAt: r.created_at,
      expiresAt: r.expires_at,
      ruleMatched: r.rule_matched,
    }))
  );
});

app.post('/v1/approvals/:id/resolve', async (c) => {
  const { id } = c.req.param();
  const body = await c.req.json().catch(() => ({}));
  const action = body.action as 'approve' | 'veto';

  if (action !== 'approve' && action !== 'veto') {
    return c.json({ error: "action must be 'approve' or 'veto'" }, 400);
  }

  const db = getDb();
  const item = db.prepare('SELECT * FROM quarantine_items WHERE id = ?').get(id) as QuarantineItemRecord | undefined;
  if (!item) {
    return c.json({ error: `Quarantine item '${id}' not found` }, 404);
  }

  const newStatus = action === 'approve' ? 'approved' : 'vetoed';
  db.prepare('UPDATE quarantine_items SET status = ? WHERE id = ?').run(newStatus, id);

  const finalVerdict = action === 'approve' ? 'ALLOW' : 'DENY';
  const now = new Date().toISOString();

  // Log resolution event in audit log
  const resEventId = `eval_res_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
  db.prepare(`
    INSERT INTO audit_events (id, timestamp, session_id, agent_id, upstream_id, tool_name, taint_state, verdict, latency_ms, rule_matched, payload_json)
    VALUES (?, ?, ?, ?, NULL, ?, 'CLEAN', ?, 0.0, ?, ?)
  `).run(
    resEventId,
    now,
    `sess_quar_${id}`,
    item.agent_id,
    item.tool_name,
    finalVerdict,
    `OPERATOR_${action.toUpperCase()}`,
    item.payload_json
  );

  broadcastSSE('quarantine_resolved', {
    id,
    action,
    status: newStatus,
    verdict: finalVerdict,
    timestamp: now,
  });

  return c.json({
    status: 'resolved',
    id,
    action,
    verdict: finalVerdict,
  });
});

// ─────────────────────────────────────────────────────────────────
// 8. SETTINGS: GET /v1/settings, PUT /v1/settings
// ─────────────────────────────────────────────────────────────────
app.get('/v1/settings', (c) => {
  const db = getDb();
  const rows = db.prepare('SELECT * FROM service_settings').all() as ServiceSettingRecord[];
  const settings: Record<string, unknown> = {};
  for (const row of rows) {
    try {
      settings[row.key] = JSON.parse(row.value_json);
    } catch {
      settings[row.key] = row.value_json;
    }
  }
  return c.json(settings);
});

app.put('/v1/settings', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const db = getDb();
  const upsert = db.prepare('INSERT OR REPLACE INTO service_settings (key, value_json) VALUES (?, ?)');

  for (const [k, v] of Object.entries(body)) {
    upsert.run(k, JSON.stringify(v));
  }

  // Return full refreshed settings
  const rows = db.prepare('SELECT * FROM service_settings').all() as ServiceSettingRecord[];
  const settings: Record<string, unknown> = {};
  for (const row of rows) {
    try {
      settings[row.key] = JSON.parse(row.value_json);
    } catch {
      settings[row.key] = row.value_json;
    }
  }
  return c.json(settings);
});

app.post('/v1/settings/test-webhook', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const targetUrl = body.webhookUrl || body.url;

  const delivered = await dispatchAlert(
    'TEST',
    {
      toolName: 'test_connection',
      agentId: 'local-operator',
      reason: 'Manual test ping from AegisVeto settings console',
    },
    targetUrl
  );

  return c.json({ status: delivered ? 'delivered' : 'queued_or_failed', targetUrl: targetUrl || 'configured_default' });
});

// ─────────────────────────────────────────────────────────────────
// Compatibility, Health & Static UI
// ─────────────────────────────────────────────────────────────────
app.get('/health', (c) => {
  return c.json({
    service: 'aegisveto-core',
    status: 'active',
    engine: 'deterministic-layer-1',
    plane: 'control-and-data',
  });
});

app.get('/policy', (c) => {
  return c.text(getActivePolicy().raw);
});

// Serve Dashboard static frontend in production
const distPath = path.join(findRepoRoot(), 'dashboard', 'dist');
if (fs.existsSync(distPath)) {
  const relDist = path.relative(process.cwd(), distPath);
  app.use('/assets/*', serveStatic({ root: relDist }));
  app.get('*', (c) => {
    if (c.req.path.startsWith('/v1')) {
      return c.json({ error: 'Not found' }, 404);
    }
    const indexPath = path.join(distPath, 'index.html');
    if (fs.existsSync(indexPath)) {
      return c.html(fs.readFileSync(indexPath, 'utf-8'));
    }
    return c.text('Not found', 404);
  });
} else {
  app.get('/', (c) => {
    return c.json({
      service: 'aegisveto-core',
      status: 'active',
      engine: 'deterministic-layer-1',
      plane: 'control-and-data',
    });
  });
}

// ─────────────────────────────────────────────────────────────────
// Start Server
// ─────────────────────────────────────────────────────────────────
export async function startServer(port = 3000) {
  getDb();
  console.log('[AegisVeto] Control Plane SQLite initialized (WAL mode)');

  loadActivePolicy();
  console.log('[AegisVeto] Layer 1 Deterministic Policy Engine initialized');

  await initKeys();
  console.log('[AegisVeto] Ed25519 cryptographic tokens ready');

  // Start active 5s SLA Auto-Deny Sweeper
  const sweeperInterval = setInterval(sweepExpiredApprovals, 5000);
  if (sweeperInterval.unref) sweeperInterval.unref();

  return serve({ fetch: app.fetch, port }, (info) => {
    console.log(`[AegisVeto] Production Control & Data Plane listening on http://localhost:${info.port}`);
  });
}

const isDirectRun =
  process.argv[1] &&
  (process.argv[1].endsWith('index.ts') || process.argv[1].endsWith('index.js'));

if (isDirectRun) {
  startServer(3000).catch(console.error);
}

export { app };
