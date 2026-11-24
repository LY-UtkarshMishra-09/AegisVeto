import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';
import { Server } from '@modelcontextprotocol/server';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import {
  evaluateDeterministic,
  getActivePolicy,
  loadActivePolicy,
  isPathDenied,
} from '../engine/evaluate.js';
import { getDb, findRepoRoot, UpstreamRecord, AgentRecord } from '../db/schema.js';
import { resolveUpstreamSecret } from '../vault/secrets.js';
import {
  initSchemaPins,
  pinTools,
  verifyToolSchema,
  ToolSchemaObject,
} from '../security/schemaPinning.js';
import {
  DECOY_TOOL_NAME,
  DECOY_TOOL_DEFINITION,
  getDecoyToolDefinition,
  checkTripwires,
} from '../security/tripwires.js';

interface CliArgs {
  agentId: string;
  upstreamId: string;
  token?: string;
  upstreamCmd: string[];
}

function parseCliArgs(): CliArgs {
  const args = process.argv.slice(2);
  let agentId = 'local-dev-agent';
  let upstreamId = 'local-filesystem';
  let token: string | undefined = undefined;

  const sepIdx = args.indexOf('--');
  let flags = sepIdx !== -1 ? args.slice(0, sepIdx) : args;
  const upstreamCmd = sepIdx !== -1 ? args.slice(sepIdx + 1) : [];

  for (let i = 0; i < flags.length; i++) {
    if (flags[i] === '--agent' && flags[i + 1]) {
      agentId = flags[++i];
    } else if (flags[i] === '--upstream' && flags[i + 1]) {
      upstreamId = flags[++i];
    } else if (flags[i] === '--token' && flags[i + 1]) {
      token = flags[++i];
    }
  }

  if (upstreamCmd.length === 0) {
    console.error(
      'Usage: proxy.ts [--agent <agent-id>] [--upstream <upstream-id>] [--token <jwt>] -- <upstream-cmd> [args...]'
    );
    process.exit(1);
  }

  return { agentId, upstreamId, token, upstreamCmd };
}

async function notifyControlPlane(event: string, data: unknown): Promise<void> {
  try {
    await fetch('http://localhost:3000/v1/events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event, data }),
      signal: AbortSignal.timeout(200),
    });
  } catch {
    // Control Plane HTTP server might be offline or running standalone; ignore silently
  }
}

async function main() {
  const { agentId, upstreamId, token, upstreamCmd } = parseCliArgs();
  const repoRoot = findRepoRoot();

  // Initialize DB and Layer 1 Policy
  let db: Database.Database | null = null;
  try {
    db = getDb();
    initSchemaPins();
    loadActivePolicy();
  } catch (err) {
    console.error('[AegisVeto MCP Proxy] Initialization warning:', err);
  }

  // Lookup Upstream in DB for Vault secrets
  let vaultSecretRef: string | null = null;
  let trustTier: string = 'trusted';
  try {
    const upRow = db
      ?.prepare('SELECT * FROM upstreams WHERE id = ?')
      .get(upstreamId) as UpstreamRecord | undefined;
    if (upRow) {
      vaultSecretRef = upRow.vault_secret_ref;
      trustTier = upRow.trust_tier;
    }
  } catch {}

  // Resolve secrets via Vault resolver
  const { env: vaultEnv } = resolveUpstreamSecret(vaultSecretRef);

  const sessionId = `mcp_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;

  // 1. Upstream Stdio Client Transport
  const [command, ...cmdArgs] = upstreamCmd;
  const mergedEnv: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined) mergedEnv[k] = v;
  }
  for (const [k, v] of Object.entries(vaultEnv)) {
    if (v !== undefined) mergedEnv[k] = v;
  }

  const upstreamTransport = new StdioClientTransport({
    command,
    args: cmdArgs,
    env: mergedEnv,
  });

  const upstreamClient = new Client(
    { name: `aegisveto-client-${agentId}`, version: '1.0.0' },
    { capabilities: {} }
  );

  // 2. Downstream Server
  const downstreamServer = new Server(
    { name: 'aegisveto-proxy', version: '1.0.0' },
    { capabilities: { tools: { listChanged: true } } }
  );
  downstreamServer.registerCapabilities({ tools: { listChanged: true } });

  // Propagate upstream tool changes downstream
  upstreamClient.setNotificationHandler('notifications/tools/list_changed', async () => {
    try {
      await downstreamServer.sendToolListChanged();
    } catch {}
  });

  // ─── Intercept tools/list ───────────────────────────────────────────
  downstreamServer.setRequestHandler('tools/list', async (request: any) => {
    let upstreamRes: any = { tools: [] };
    try {
      upstreamRes = await upstreamClient.listTools(request?.params);
    } catch (err) {
      console.error('[AegisVeto Proxy] Failed to list tools from upstream:', err);
      return { tools: [] };
    }

    let upstreamTools: ToolSchemaObject[] = (upstreamRes.tools || []) as ToolSchemaObject[];

    // Verify and enforce tool schema pins
    for (const tool of upstreamTools) {
      const verif = verifyToolSchema(tool, upstreamId);
      if (!verif.valid) {
        const diffJson = JSON.stringify(verif.diff);
        const reason = `Tool schema mutation detected for '${tool.name}': ${verif.diff?.diffSummary}`;
        const timestamp = new Date().toISOString();

        try {
          db?.prepare(`
            INSERT INTO audit_events (id, timestamp, session_id, agent_id, upstream_id, tool_name, taint_state, verdict, latency_ms, rule_matched, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, 'TAINTED', 'SCHEMA_DRIFT', 0.1, ?, ?)
          `).run(
            `drift_${Date.now()}`,
            timestamp,
            sessionId,
            agentId,
            upstreamId,
            tool.name,
            reason,
            diffJson
          );
        } catch {}

        const err = new Error(`[AegisVeto SCHEMA_DRIFT] ${reason}`);
        (err as any).code = -32001;
        throw err;
      }
    }

    pinTools(upstreamTools, upstreamId);

    // Dynamic Capability Revocation: Check session taint state
    let sessionTaint = 'CLEAN';
    try {
      const sessRow = db
        ?.prepare('SELECT taint_state FROM sessions WHERE session_id = ?')
        .get(sessionId) as { taint_state: string } | undefined;
      if (sessRow) {
        sessionTaint = sessRow.taint_state;
      }
    } catch {}

    // When TAINTED or TERMINATED, strip all egress tools
    const { config: policy } = getActivePolicy();
    const egressToolsList = policy?.taint_engine?.egress_tools || [
      'send_external_email',
      'http_post_webhook',
      'curl_upload',
    ];

    if (sessionTaint === 'TAINTED' || sessionTaint === 'TERMINATED') {
      upstreamTools = upstreamTools.filter((t) => {
        const isEgress =
          egressToolsList.includes(t.name) ||
          policy?.tools?.[t.name]?.class === 'egress' ||
          trustTier === 'egress';
        return !isEgress;
      });
    }

    // Append Decoy Tool honeypot (dynamically configured from settings)
    const decoy = getDecoyToolDefinition();
    const finalTools = [...upstreamTools, decoy as unknown as ToolSchemaObject];

    return {
      ...upstreamRes,
      tools: finalTools,
    };
  });

  // ─── Intercept tools/call ───────────────────────────────────────────
  downstreamServer.setRequestHandler('tools/call', async (request: any) => {
    const { name, arguments: args = {} } = request.params || {};

    // Map common tool aliases
    let targetTool = name;
    const mappedArgs: Record<string, unknown> = { ...(args || {}) };
    if (name === 'read_text_file' || name === 'read_file') {
      targetTool = 'read_file';
      if (!mappedArgs['path'] && typeof mappedArgs['uri'] === 'string') {
        mappedArgs['path'] = mappedArgs['uri'];
      }
    }

    // Verify upstream tool schema integrity before invocation (Anti-Rug-Pull)
    try {
      const currentToolsRes = await upstreamClient.listTools();
      const currentToolObj = (currentToolsRes.tools || []).find((t: any) => t.name === name);
      if (currentToolObj) {
        const verif = verifyToolSchema(currentToolObj as ToolSchemaObject, upstreamId);
        if (!verif.valid) {
          const diffJson = JSON.stringify(verif.diff);
          const reason = `Tool schema mutation detected for '${name}': ${verif.diff?.diffSummary}`;
          const driftId = `drift_${Date.now()}`;
          const timestamp = new Date().toISOString();

          try {
            db?.prepare(`
              INSERT INTO audit_events (id, timestamp, session_id, agent_id, upstream_id, tool_name, taint_state, verdict, latency_ms, rule_matched, payload_json)
              VALUES (?, ?, ?, ?, ?, ?, 'TAINTED', 'SCHEMA_DRIFT', 0.1, ?, ?)
            `).run(driftId, timestamp, sessionId, agentId, upstreamId, name, reason, diffJson);
          } catch {}

          notifyControlPlane('schema_drift', {
            id: driftId,
            session_id: sessionId,
            tool: name,
            diff: verif.diff,
            reason,
          });

          const err = new Error(`[AegisVeto SCHEMA_DRIFT] ${reason}`);
          (err as any).code = -32001;
          throw err;
        }
      }
    } catch (e: any) {
      if (e.message?.includes('SCHEMA_DRIFT')) throw e;
    }

    // Query session taint prior to call
    let priorTaint = 'CLEAN';
    try {
      const sRow = db
        ?.prepare('SELECT taint_state FROM sessions WHERE session_id = ?')
        .get(sessionId) as { taint_state: string } | undefined;
      if (sRow) priorTaint = sRow.taint_state;
    } catch {}

    // Evaluate call through Layer 1 Deterministic Engine
    const decision = evaluateDeterministic({
      token,
      agentId,
      sessionId,
      upstreamId,
      toolName: targetTool,
      args: mappedArgs,
      dryRun: false,
    });

    notifyControlPlane('tool_evaluation', decision);

    // If decision transitioned from CLEAN to TAINTED, revoke capabilities downstream!
    if (priorTaint === 'CLEAN' && decision.taintState === 'TAINTED') {
      try {
        await downstreamServer.sendToolListChanged();
      } catch (e) {
        console.warn('[AegisVeto Proxy] Failed to notify downstream tool list change:', e);
      }
    }

    // Fail-Closed Gate: Block DENY, QUARANTINE, CRITICAL_TRIPWIRE, SCHEMA_DRIFT
    if (!decision.allowed) {
      const err = new Error(
        `[AegisVeto ${decision.verdict}] ${decision.reason || decision.ruleMatched}`
      );
      (err as any).code = -32001;
      (err as any).data = {
        verdict: decision.verdict,
        ruleMatched: decision.ruleMatched,
        latencyMs: decision.latencyMs,
        taintState: decision.taintState,
      };
      throw err;
    }

    // Call allowed: forward to upstream MCP server
    const result = await upstreamClient.callTool({
      name,
      arguments: args,
    });

    return result;
  });

  // Connect transports
  await upstreamClient.connect(upstreamTransport);
  const downstreamTransport = new StdioServerTransport();
  await downstreamServer.connect(downstreamTransport);
}

main().catch((err) => {
  console.error('[AegisVeto MCP Proxy] Fatal execution error:', err);
  process.exit(1);
});
