import Database from 'better-sqlite3';
import path from 'node:path';
import fs from 'node:fs';

function findRepoRoot(): string {
  let curr = process.cwd();
  while (curr !== path.dirname(curr)) {
    if (fs.existsSync(path.join(curr, 'policy.yaml'))) return curr;
    curr = path.dirname(curr);
  }
  return process.cwd();
}

const DB_PATH = path.join(findRepoRoot(), 'aegisveto_audit.db');

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

let db: Database.Database;

export function initDb(): void {
  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');

  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      session_id TEXT NOT NULL,
      provider TEXT NOT NULL,
      model TEXT NOT NULL,
      tool_name TEXT NOT NULL,
      taint_state TEXT NOT NULL,
      decision TEXT NOT NULL,
      latency_ms REAL NOT NULL,
      reason TEXT,
      payload_json TEXT,
      mode TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_logs(session_id);
    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp DESC);
  `);
}

export function insertAuditLog(log: AuditRecord): void {
  if (!db) initDb();
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO audit_logs (
      id, timestamp, session_id, provider, model, tool_name,
      taint_state, decision, latency_ms, reason, payload_json, mode
    ) VALUES (
      @id, @timestamp, @session_id, @provider, @model, @tool_name,
      @taint_state, @decision, @latency_ms, @reason, @payload_json, @mode
    )
  `);
  stmt.run(log);
}

export function getAuditLogs(limit = 100): AuditRecord[] {
  if (!db) initDb();
  const stmt = db.prepare(`SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?`);
  return stmt.all(limit) as AuditRecord[];
}

export function getAuditMetrics(pendingQuarantineCount = 0): AuditMetrics {
  if (!db) initDb();
  const countRow = db.prepare(`SELECT COUNT(*) as count FROM audit_logs`).get() as { count: number };
  const blockedRow = db.prepare(`SELECT COUNT(*) as count FROM audit_logs WHERE decision IN ('DENY', 'VETO')`).get() as { count: number };
  const avgRow = db.prepare(`SELECT AVG(latency_ms) as avg_lat FROM audit_logs`).get() as { avg_lat: number | null };

  return {
    totalCalls: countRow.count,
    blockedCount: blockedRow.count,
    avgLatencyMs: avgRow.avg_lat ? Number(avgRow.avg_lat.toFixed(2)) : 0,
    pendingQuarantine: pendingQuarantineCount,
  };
}
