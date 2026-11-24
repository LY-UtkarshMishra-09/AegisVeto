import Database from 'better-sqlite3';
import path from 'node:path';
import fs from 'node:fs';

export interface AgentRecord {
  id: string;
  name: string;
  mode: 'enforce' | 'shadow';
  allowed_upstreams_json: string;
  key_fingerprint: string | null;
  status: 'active' | 'revoked';
  created_at: string;
}

export interface UpstreamRecord {
  id: string;
  name: string;
  transport: 'stdio' | 'http';
  command_or_url: string;
  trust_tier: 'trusted' | 'untrusted' | 'egress';
  vault_secret_ref: string | null;
  status: string;
  created_at: string;
}

export interface SchemaPinRecord {
  id: string;
  upstream_id: string;
  tool_name: string;
  sha256_hash: string;
  canonical_schema_json: string;
  approved_at: string;
  drift_detected: number; // 0 or 1
  drift_diff_json: string | null;
}

export interface PolicyVersionRecord {
  id: string;
  version: number;
  yaml_content: string;
  author: string;
  is_active: number; // 0 or 1
  created_at: string;
}

export interface SessionRecord {
  session_id: string;
  agent_id: string;
  taint_state: 'CLEAN' | 'TAINTED' | 'TERMINATED';
  taint_source_tool: string | null;
  updated_at: string;
  expires_at: string;
}

export interface AuditEventRecord {
  id: string;
  timestamp: string;
  session_id: string;
  agent_id: string;
  upstream_id: string | null;
  tool_name: string;
  taint_state: string;
  verdict: 'ALLOW' | 'DENY' | 'QUARANTINE' | 'SHADOW_DENY' | 'SCHEMA_DRIFT' | 'CRITICAL_TRIPWIRE';
  latency_ms: number;
  rule_matched: string;
  payload_json: string | null;
}

export interface QuarantineItemRecord {
  id: string;
  event_id: string;
  agent_id: string;
  tool_name: string;
  payload_json: string;
  status: 'pending' | 'approved' | 'vetoed' | 'expired';
  ai_risk_score: number | null;
  ai_hijacked: number | null;
  ai_summary: string | null;
  created_at: string;
  expires_at: string;
}

export interface ServiceSettingRecord {
  key: string;
  value_json: string;
}

export function findRepoRoot(): string {
  let curr = process.cwd();
  while (curr !== path.dirname(curr)) {
    if (fs.existsSync(path.join(curr, 'policy.yaml'))) return curr;
    curr = path.dirname(curr);
  }
  return process.cwd();
}

let dbInstance: Database.Database | null = null;

export function getDb(): Database.Database {
  if (!dbInstance) {
    const root = findRepoRoot();
    const dbPath = path.join(root, 'aegisveto_audit.db');
    dbInstance = new Database(dbPath);
    dbInstance.pragma('journal_mode = WAL');
    dbInstance.pragma('synchronous = NORMAL');
    initDatabase(dbInstance);
  }
  return dbInstance;
}

export function initDatabase(db: Database.Database): void {
  // Check if legacy schema_pins exists with incompatible columns
  try {
    const pinCols = db.prepare("PRAGMA table_info(schema_pins)").all() as { name: string }[];
    if (pinCols.length > 0 && !pinCols.some((c) => c.name === 'upstream_id')) {
      db.exec("DROP TABLE schema_pins;");
    }
  } catch {}

  // 1. agents
  db.exec(`
    CREATE TABLE IF NOT EXISTS agents (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      mode TEXT NOT NULL CHECK(mode IN ('enforce', 'shadow')),
      allowed_upstreams_json TEXT NOT NULL,
      key_fingerprint TEXT,
      status TEXT NOT NULL CHECK(status IN ('active', 'revoked')),
      created_at TEXT NOT NULL
    );
  `);

  // 2. upstreams
  db.exec(`
    CREATE TABLE IF NOT EXISTS upstreams (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      transport TEXT NOT NULL CHECK(transport IN ('stdio', 'http')),
      command_or_url TEXT NOT NULL,
      trust_tier TEXT NOT NULL CHECK(trust_tier IN ('trusted', 'untrusted', 'egress')),
      vault_secret_ref TEXT,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `);

  // 3. schema_pins
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_pins (
      id TEXT PRIMARY KEY,
      upstream_id TEXT NOT NULL,
      tool_name TEXT NOT NULL,
      sha256_hash TEXT NOT NULL,
      canonical_schema_json TEXT NOT NULL,
      approved_at TEXT NOT NULL,
      drift_detected INTEGER NOT NULL DEFAULT 0,
      drift_diff_json TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_schema_pins_upstream ON schema_pins(upstream_id);
    CREATE INDEX IF NOT EXISTS idx_schema_pins_tool ON schema_pins(tool_name);
  `);

  // 4. policy_versions
  db.exec(`
    CREATE TABLE IF NOT EXISTS policy_versions (
      id TEXT PRIMARY KEY,
      version INTEGER NOT NULL,
      yaml_content TEXT NOT NULL,
      author TEXT NOT NULL,
      is_active INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_policy_versions_active ON policy_versions(is_active);
  `);

  // 5. sessions
  db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      session_id TEXT PRIMARY KEY,
      agent_id TEXT NOT NULL,
      taint_state TEXT NOT NULL CHECK(taint_state IN ('CLEAN', 'TAINTED', 'TERMINATED')),
      taint_source_tool TEXT,
      updated_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_sessions_agent ON sessions(agent_id);
  `);

  // 6. audit_events
  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_events (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      session_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      upstream_id TEXT,
      tool_name TEXT NOT NULL,
      taint_state TEXT NOT NULL,
      verdict TEXT NOT NULL CHECK(verdict IN ('ALLOW', 'DENY', 'QUARANTINE', 'SHADOW_DENY', 'SCHEMA_DRIFT', 'CRITICAL_TRIPWIRE')),
      latency_ms REAL NOT NULL,
      rule_matched TEXT NOT NULL,
      payload_json TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_audit_events_session ON audit_events(session_id);
    CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_events_agent ON audit_events(agent_id);
    CREATE INDEX IF NOT EXISTS idx_audit_events_verdict ON audit_events(verdict);
  `);

  // 7. quarantine_items
  db.exec(`
    CREATE TABLE IF NOT EXISTS quarantine_items (
      id TEXT PRIMARY KEY,
      event_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      tool_name TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'vetoed', 'expired')),
      ai_risk_score REAL,
      ai_hijacked INTEGER,
      ai_summary TEXT,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine_items(status);
    CREATE INDEX IF NOT EXISTS idx_quarantine_expires ON quarantine_items(expires_at);
  `);

  // 8. service_settings
  db.exec(`
    CREATE TABLE IF NOT EXISTS service_settings (
      key TEXT PRIMARY KEY,
      value_json TEXT NOT NULL
    );
  `);

  seedDefaultsIfEmpty(db);
}

function seedDefaultsIfEmpty(db: Database.Database): void {
  const root = findRepoRoot();
  const now = new Date().toISOString();

  // 1. Agent seed
  const agentCount = (db.prepare('SELECT COUNT(*) as c FROM agents').get() as { c: number }).c;
  if (agentCount === 0) {
    db.prepare(`
      INSERT INTO agents (id, name, mode, allowed_upstreams_json, key_fingerprint, status, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      'local-dev-agent',
      'Local Development Agent',
      'enforce',
      JSON.stringify(['local-filesystem', 'external-comms']),
      'ed25519-builtin-local-agent',
      'active',
      now
    );
  }

  // 2. Upstream seeds
  const upstreamCount = (db.prepare('SELECT COUNT(*) as c FROM upstreams').get() as { c: number }).c;
  if (upstreamCount === 0) {
    const insertUpstream = db.prepare(`
      INSERT INTO upstreams (id, name, transport, command_or_url, trust_tier, vault_secret_ref, status, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertUpstream.run(
      'local-filesystem',
      'Local Filesystem',
      'stdio',
      'npx @modelcontextprotocol/server-filesystem ./sandbox',
      'trusted',
      null,
      'active',
      now
    );

    insertUpstream.run(
      'external-comms',
      'External Communications',
      'stdio',
      'node ./mcp/mock-comms-server.js',
      'egress',
      null,
      'active',
      now
    );
  }

  // 3. Policy versions seed from root policy.yaml
  const policyCount = (db.prepare('SELECT COUNT(*) as c FROM policy_versions').get() as { c: number }).c;
  if (policyCount === 0) {
    let yamlContent = '';
    const rootPolicyPath = path.join(root, 'policy.yaml');
    if (fs.existsSync(rootPolicyPath)) {
      yamlContent = fs.readFileSync(rootPolicyPath, 'utf-8');
    } else {
      yamlContent = `# AegisVeto Zero-Trust Security Policy\nversion: "2026-03"\n`;
    }

    db.prepare(`
      INSERT INTO policy_versions (id, version, yaml_content, author, is_active, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run('pol-v1', 1, yamlContent, 'system', 1, now);
  }

  // 4. Service settings seed
  const settingsCount = (db.prepare('SELECT COUNT(*) as c FROM service_settings').get() as { c: number }).c;
  if (settingsCount === 0) {
    const insertSetting = db.prepare(`
      INSERT INTO service_settings (key, value_json) VALUES (?, ?)
    `);

    insertSetting.run(
      'layer2_provider',
      JSON.stringify({
        provider: 'ollama',
        ollamaUrl: process.env.OLLAMA_BASE_URL || 'http://localhost:11434',
        ollamaModel: process.env.OLLAMA_MODEL || 'qwen2.5:7b',
        groqModel: process.env.GROQ_MODEL || 'llama-3.3-70b-versatile',
        apiKey: process.env.GROQ_API_KEY || '',
      })
    );

    insertSetting.run('approval_sla_seconds', JSON.stringify(300));
    insertSetting.run('webhook_url', JSON.stringify(''));
    insertSetting.run('canary_tokens', JSON.stringify(['aegis_canary_9921', 'ak_live_sec_tripwire_7701']));
  }
}
