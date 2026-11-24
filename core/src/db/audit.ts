import { getDb, AuditEventRecord } from './schema.js';

export interface AuditRecord {
  id: string;
  timestamp: string;
  session_id: string;
  provider: string;
  model: string;
  tool_name: string;
  taint_state: string;
  decision: string;
  latency_ms: number;
  reason: string;
  payload_json: string;
  mode: string;
}

export interface AuditMetrics {
  totalCalls: number;
  blockedCount: number;
  avgLatencyMs: number;
  pendingQuarantine: number;
}

export function initDb(): void {
  getDb();
}

export function insertAuditLog(log: AuditRecord): void {
  const db = getDb();
  // Map legacy decision to audit_events verdict
  let verdict: 'ALLOW' | 'DENY' | 'QUARANTINE' | 'SHADOW_DENY' | 'SCHEMA_DRIFT' | 'CRITICAL_TRIPWIRE' = 'ALLOW';
  const dec = log.decision.toUpperCase();
  if (dec === 'DENY' || dec === 'VETO') verdict = 'DENY';
  else if (dec === 'QUARANTINE') verdict = 'QUARANTINE';
  else if (dec === 'SHADOW_DENY') verdict = 'SHADOW_DENY';
  else if (dec === 'SCHEMA_DRIFT') verdict = 'SCHEMA_DRIFT';
  else if (dec === 'CRITICAL_TRIPWIRE') verdict = 'CRITICAL_TRIPWIRE';

  const stmt = db.prepare(`
    INSERT OR REPLACE INTO audit_events (
      id, timestamp, session_id, agent_id, upstream_id, tool_name,
      taint_state, verdict, latency_ms, rule_matched, payload_json
    ) VALUES (
      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
    )
  `);

  stmt.run(
    log.id,
    log.timestamp,
    log.session_id,
    'local-dev-agent',
    null,
    log.tool_name,
    log.taint_state,
    verdict,
    log.latency_ms,
    log.reason || 'LEGACY_LOG',
    log.payload_json
  );
}

export function getAuditLogs(limit = 100): AuditRecord[] {
  const db = getDb();
  const rows = db.prepare(`
    SELECT id, timestamp, session_id, tool_name, taint_state, verdict as decision, latency_ms, rule_matched as reason, payload_json
    FROM audit_events
    ORDER BY timestamp DESC
    LIMIT ?
  `).all(limit) as Array<{
    id: string;
    timestamp: string;
    session_id: string;
    tool_name: string;
    taint_state: string;
    decision: string;
    latency_ms: number;
    reason: string;
    payload_json: string | null;
  }>;

  return rows.map((r) => ({
    id: r.id,
    timestamp: r.timestamp,
    session_id: r.session_id,
    provider: 'aegisveto',
    model: 'l1-deterministic',
    tool_name: r.tool_name,
    taint_state: r.taint_state,
    decision: r.decision,
    latency_ms: r.latency_ms,
    reason: r.reason,
    payload_json: r.payload_json || '{}',
    mode: 'enforce',
  }));
}

export function getAuditMetrics(pendingQuarantineCount = 0): AuditMetrics {
  const db = getDb();
  const countRow = db.prepare(`SELECT COUNT(*) as count FROM audit_events`).get() as { count: number };
  const blockedRow = db.prepare(`SELECT COUNT(*) as count FROM audit_events WHERE verdict IN ('DENY', 'CRITICAL_TRIPWIRE', 'SCHEMA_DRIFT')`).get() as { count: number };
  const avgRow = db.prepare(`SELECT AVG(latency_ms) as avg_lat FROM audit_events`).get() as { avg_lat: number | null };

  return {
    totalCalls: countRow.count,
    blockedCount: blockedRow.count,
    avgLatencyMs: avgRow.avg_lat ? Number(avgRow.avg_lat.toFixed(2)) : 0,
    pendingQuarantine: pendingQuarantineCount,
  };
}
