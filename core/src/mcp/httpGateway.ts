import { Context, Hono } from 'hono';
import { verifyToken } from '../auth/tokens.js';
import { getDb, UpstreamRecord, AgentRecord } from '../db/schema.js';
import { evaluateDeterministic, getActivePolicy } from '../engine/evaluate.js';
import { resolveUpstreamSecret } from '../vault/secrets.js';
import { verifyToolSchema, pinTools, ToolSchemaObject } from '../security/schemaPinning.js';
import { getDecoyToolDefinition } from '../security/tripwires.js';

export const httpMcpGateway = new Hono();

// Mount on ALL /v1/mcp/:upstreamId
httpMcpGateway.all('/:upstreamId/*', handleMcpRequest);
httpMcpGateway.all('/:upstreamId', handleMcpRequest);

async function handleMcpRequest(c: Context) {
  const upstreamId = c.req.param('upstreamId');
  const authHeader = c.req.header('Authorization');

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json(
      {
        jsonrpc: '2.0',
        id: null,
        error: {
          code: -32001,
          message: 'Unauthorized: Missing or invalid Authorization Bearer JWT',
        },
      },
      401
    );
  }

  const token = authHeader.slice(7).trim();
  let agentId = 'local-dev-agent';
  let sessionId = `sess_${Date.now()}`;
  let allowedScopes = ['*'];

  try {
    const payload = await verifyToken(token);
    agentId = payload.agent_id;
    sessionId = payload.session_id || sessionId;
    allowedScopes = payload.allowed_scopes;
  } catch (err) {
    return c.json(
      {
        jsonrpc: '2.0',
        id: null,
        error: {
          code: -32001,
          message: `JWT verification failed: ${err instanceof Error ? err.message : 'Invalid token'}`,
        },
      },
      401
    );
  }

  const db = getDb();
  const upstream = db
    ?.prepare('SELECT * FROM upstreams WHERE id = ?')
    .get(upstreamId) as UpstreamRecord | undefined;

  if (!upstream) {
    return c.json(
      {
        jsonrpc: '2.0',
        id: null,
        error: {
          code: -32602,
          message: `Upstream '${upstreamId}' not found in registry`,
        },
      },
      404
    );
  }

  // Parse JSON-RPC body if POST/PUT
  let body: any = null;
  if (['POST', 'PUT', 'PATCH'].includes(c.req.method)) {
    try {
      body = await c.req.json();
    } catch {
      return c.json(
        {
          jsonrpc: '2.0',
          id: null,
          error: { code: -32700, message: 'Parse error: Invalid JSON' },
        },
        400
      );
    }
  }

  const rpcId = body?.id ?? 1;
  const method = body?.method;

  // ─── tools/call Interception ──────────────────────────────────────
  if (method === 'tools/call') {
    const toolName = body.params?.name;
    const toolArgs = body.params?.arguments || {};

    // Check JWT scopes
    if (!allowedScopes.includes('*') && !allowedScopes.includes(toolName)) {
      return c.json(
        {
          jsonrpc: '2.0',
          id: rpcId,
          error: {
            code: -32001,
            message: `[AegisVeto JWT_SCOPE_VIOLATION] Tool '${toolName}' not permitted in agent token scopes`,
          },
        },
        403
      );
    }

    // Run Layer 1 Deterministic Evaluation
    const decision = evaluateDeterministic({
      token,
      agentId,
      sessionId,
      upstreamId,
      toolName,
      args: toolArgs,
      dryRun: false,
    });

    if (!decision.allowed) {
      return c.json(
        {
          jsonrpc: '2.0',
          id: rpcId,
          error: {
            code: -32001,
            message: `[AegisVeto ${decision.verdict}] ${decision.reason || decision.ruleMatched}`,
            data: {
              verdict: decision.verdict,
              ruleMatched: decision.ruleMatched,
              taintState: decision.taintState,
              latencyMs: decision.latencyMs,
            },
          },
        },
        403
      );
    }

    // Decision ALLOWED: Resolve Upstream Vault Secrets
    const { headers: vaultHeaders } = resolveUpstreamSecret(upstream.vault_secret_ref);

    // Forward to upstream HTTP target
    if (upstream.transport === 'http' && upstream.command_or_url.startsWith('http')) {
      try {
        const forwardRes = await fetch(upstream.command_or_url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...vaultHeaders,
          },
          body: JSON.stringify(body),
        });

        const forwardJson = await forwardRes.json();
        return c.json(forwardJson, forwardRes.status as any);
      } catch (fwdErr) {
        return c.json(
          {
            jsonrpc: '2.0',
            id: rpcId,
            error: {
              code: -32000,
              message: `Upstream HTTP dispatch error: ${fwdErr instanceof Error ? fwdErr.message : String(fwdErr)}`,
            },
          },
          502
        );
      }
    }

    // Direct mock response if internal/local
    return c.json({
      jsonrpc: '2.0',
      id: rpcId,
      result: {
        content: [
          {
            type: 'text',
            text: `[AegisVeto Gateway] Call to '${toolName}' allowed and dispatched.`,
          },
        ],
      },
    });
  }

  // ─── tools/list Interception ──────────────────────────────────────
  if (method === 'tools/list') {
    // Check session taint
    let sessionTaint = 'CLEAN';
    try {
      const sessRow = db
        ?.prepare('SELECT taint_state FROM sessions WHERE session_id = ?')
        .get(sessionId) as { taint_state: string } | undefined;
      if (sessRow) sessionTaint = sessRow.taint_state;
    } catch {}

    const { config: policy } = getActivePolicy();
    const egressToolsList = policy?.taint_engine?.egress_tools || [
      'send_external_email',
      'http_post_webhook',
      'curl_upload',
    ];

    if (upstream.transport === 'http' && upstream.command_or_url.startsWith('http')) {
      try {
        const { headers: vaultHeaders } = resolveUpstreamSecret(upstream.vault_secret_ref);
        const forwardRes = await fetch(upstream.command_or_url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...vaultHeaders },
          body: JSON.stringify(body),
        });
        const forwardJson = (await forwardRes.json()) as any;

        if (forwardJson.result?.tools && Array.isArray(forwardJson.result.tools)) {
          // Verify and enforce tool schema pins
          for (const t of forwardJson.result.tools) {
            const verif = verifyToolSchema(t as ToolSchemaObject, upstreamId);
            if (!verif.valid) {
              const diffJson = JSON.stringify(verif.diff);
              const reason = `Tool schema mutation detected for '${t.name}': ${verif.diff?.diffSummary}`;
              try {
                db?.prepare(`
                  INSERT INTO audit_events (id, timestamp, session_id, agent_id, upstream_id, tool_name, taint_state, verdict, latency_ms, rule_matched, payload_json)
                  VALUES (?, ?, ?, ?, ?, ?, 'TAINTED', 'SCHEMA_DRIFT', 0.1, ?, ?)
                `).run(`drift_${Date.now()}`, new Date().toISOString(), sessionId, agentId, upstreamId, t.name, reason, diffJson);
              } catch {}
              return c.json({
                jsonrpc: '2.0',
                id: rpcId,
                error: {
                  code: -32001,
                  message: `[AegisVeto SCHEMA_DRIFT] ${reason}`,
                  data: { verdict: 'SCHEMA_DRIFT', diff: verif.diff },
                },
              }, 403);
            }
          }

          pinTools(forwardJson.result.tools, upstreamId);

          if (sessionTaint === 'TAINTED') {
            forwardJson.result.tools = forwardJson.result.tools.filter(
              (t: any) => !egressToolsList.includes(t.name)
            );
          }

          const decoy = getDecoyToolDefinition();
          forwardJson.result.tools = [...forwardJson.result.tools, decoy];
        }
        return c.json(forwardJson);
      } catch {}
    }

    // Default list response
    const decoy = getDecoyToolDefinition();
    return c.json({
      jsonrpc: '2.0',
      id: rpcId,
      result: {
        tools: [decoy],
      },
    });
  }

  // Forward generic methods
  return c.json({
    jsonrpc: '2.0',
    id: rpcId,
    result: { status: 'acknowledged', upstreamId },
  });
}
