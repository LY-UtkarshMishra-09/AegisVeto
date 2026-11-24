import fs from 'node:fs';
import path from 'node:path';
import { markTerminated, isTerminated } from '../state/taint.js';
import { getDb } from '../db/schema.js';

function findRepoRoot(): string {
  let curr = process.cwd();
  while (curr !== path.dirname(curr)) {
    if (fs.existsSync(path.join(curr, 'policy.yaml'))) return curr;
    curr = path.dirname(curr);
  }
  return process.cwd();
}

export function getDecoyToolName(): string {
  try {
    const db = getDb();
    const row = db
      .prepare("SELECT value_json FROM service_settings WHERE key = 'decoy_tool_name'")
      .get() as { value_json: string } | undefined;
    if (row?.value_json) {
      const parsed = JSON.parse(row.value_json);
      if (typeof parsed === 'string' && parsed.trim()) return parsed.trim();
    }
  } catch {}
  return 'export_admin_secrets';
}

export function getDecoyToolDefinition() {
  const name = getDecoyToolName();
  return {
    name,
    description: 'Internal admin utility. Never invoke in normal workflows.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Export destination' },
      },
    },
  };
}

export const DECOY_TOOL_NAME = 'export_admin_secrets';
export const DECOY_TOOL_DEFINITION = {
  name: DECOY_TOOL_NAME,
  description: 'Internal admin utility. Never invoke in normal workflows.',
  inputSchema: {
    type: 'object',
    properties: {
      target: { type: 'string', description: 'Export destination' },
    },
  },
};

export function isDecoyTool(toolName: string): boolean {
  return toolName === getDecoyToolName() || toolName === 'export_admin_secrets';
}

export function loadCanaryTokens(): string[] {
  const tokens: Set<string> = new Set(['aegis_canary_9921']);

  // 1. Load active canary tokens from SQLite service_settings
  try {
    const db = getDb();
    const row = db
      .prepare("SELECT value_json FROM service_settings WHERE key = 'canary_tokens'")
      .get() as { value_json: string } | undefined;
    if (row?.value_json) {
      const parsed = JSON.parse(row.value_json);
      if (Array.isArray(parsed)) {
        for (const t of parsed) {
          if (typeof t === 'string' && t.trim()) tokens.add(t.trim());
        }
      }
    }
  } catch {}

  // 2. Load from sandbox/.env if present
  try {
    const repoRoot = findRepoRoot();
    const envPath = path.join(repoRoot, 'sandbox', '.env');
    if (fs.existsSync(envPath)) {
      const lines = fs.readFileSync(envPath, 'utf-8').split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const parts = trimmed.split('=');
        if (parts.length >= 2) {
          const val = parts.slice(1).join('=').trim().replace(/^['"]|['"]$/g, '');
          if (val) tokens.add(val);
        }
      }
    }
  } catch {}

  return Array.from(tokens);
}

// Generate raw, url-encoded, and base64 forms of a canary string
function getCanaryVariants(token: string): string[] {
  const variants = [token];

  // URL encoded variant
  try {
    const urlEnc = encodeURIComponent(token);
    if (urlEnc !== token) variants.push(urlEnc);
  } catch {}

  // Base64 encoded variant (with and without padding)
  try {
    const b64 = Buffer.from(token, 'utf-8').toString('base64');
    variants.push(b64);
    const unpadded = b64.replace(/=+$/, '');
    if (unpadded !== b64) variants.push(unpadded);
  } catch {}

  return variants;
}

// Recursively inspect all string values in arguments
function extractStringValues(val: unknown): string[] {
  const strings: string[] = [];
  if (typeof val === 'string') {
    strings.push(val);
    // Also try base64 decode if the string looks like base64
    if (/^[A-Za-z0-9+/=]{8,}$/.test(val.trim())) {
      try {
        const decoded = Buffer.from(val.trim(), 'base64').toString('utf-8');
        if (decoded && !/[\x00-\x08\x0E-\x1F]/.test(decoded)) {
          strings.push(decoded);
        }
      } catch {}
    }
  } else if (Array.isArray(val)) {
    for (const item of val) {
      strings.push(...extractStringValues(item));
    }
  } else if (val && typeof val === 'object') {
    for (const key of Object.keys(val)) {
      strings.push(...extractStringValues((val as Record<string, unknown>)[key]));
    }
  }
  return strings;
}

export interface CanaryDetectionResult {
  detected: boolean;
  canary?: string;
  variantMatched?: string;
  location?: string;
}

export function scanForCanaries(args: Record<string, unknown>): CanaryDetectionResult {
  const canaries = loadCanaryTokens();
  const stringValues = extractStringValues(args);

  for (const canary of canaries) {
    const variants = getCanaryVariants(canary);
    for (const str of stringValues) {
      for (const variant of variants) {
        if (str.includes(variant)) {
          return {
            detected: true,
            canary,
            variantMatched: variant,
            location: str.slice(0, 80),
          };
        }
      }
    }
  }

  return { detected: false };
}

export function checkTripwires(
  sessionId: string,
  toolName: string,
  args: Record<string, unknown>
): { triggered: boolean; reason: string; tripwireType: string } {
  // Check if session is already terminated in memory
  if (isTerminated(sessionId)) {
    return {
      triggered: true,
      reason: 'Session has been TERMINATED due to security tripwire violation',
      tripwireType: 'CRITICAL_TRIPWIRE',
    };
  }

  // Check if session is terminated in SQLite
  try {
    const db = getDb();
    const row = db
      .prepare('SELECT taint_state FROM sessions WHERE session_id = ?')
      .get(sessionId) as { taint_state: string } | undefined;
    if (row?.taint_state === 'TERMINATED') {
      markTerminated(sessionId, 'Session terminated in database');
      return {
        triggered: true,
        reason: 'Session has been TERMINATED due to security tripwire violation',
        tripwireType: 'CRITICAL_TRIPWIRE',
      };
    }
  } catch {}

  // 1. Check Decoy Tool invocation
  if (isDecoyTool(toolName)) {
    markTerminated(sessionId, `Decoy tool '${toolName}' invoked`);
    try {
      const db = getDb();
      db.prepare(
        "UPDATE sessions SET taint_state = 'TERMINATED', taint_source_tool = ? WHERE session_id = ?"
      ).run(toolName, sessionId);
    } catch {}
    return {
      triggered: true,
      reason: `Decoy trap triggered: unauthorized invocation of honeypot tool '${toolName}'`,
      tripwireType: 'CRITICAL_TRIPWIRE',
    };
  }

  // 2. Check Canary token leak in arguments (raw, URL-encoded, or Base64)
  const canaryCheck = scanForCanaries(args);
  if (canaryCheck.detected) {
    markTerminated(sessionId, `Canary token leak detected: ${canaryCheck.canary}`);
    try {
      const db = getDb();
      db.prepare(
        "UPDATE sessions SET taint_state = 'TERMINATED', taint_source_tool = ? WHERE session_id = ?"
      ).run(`canary:${canaryCheck.canary}`, sessionId);
    } catch {}
    return {
      triggered: true,
      reason: `Canary exfiltration trap triggered: secret canary match detected in outbound arguments (${canaryCheck.canary})`,
      tripwireType: 'CRITICAL_TRIPWIRE',
    };
  }

  return { triggered: false, reason: '', tripwireType: '' };
}
