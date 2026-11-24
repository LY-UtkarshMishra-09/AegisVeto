import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import { getDb as getSharedDb } from '../db/schema.js';

export interface ToolSchemaObject {
  name: string;
  description?: string;
  inputSchema: {
    type: 'object';
    properties?: Record<string, unknown>;
    [key: string]: unknown;
  };
  annotations?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface SchemaPin {
  id: string;
  upstream_id: string;
  tool_name: string;
  hash: string;
  canonical_json: string;
  first_seen: string;
  drift_detected?: number;
}

export interface SchemaVerificationResult {
  valid: boolean;
  tool_name: string;
  driftType?: 'DESCRIPTION_MUTATION' | 'INPUT_SCHEMA_MUTATION' | 'GENERAL_DRIFT';
  expectedHash?: string;
  actualHash?: string;
  diff?: {
    field: string;
    oldSchema: unknown;
    newSchema: unknown;
    oldValue: unknown;
    newValue: unknown;
    diffSummary: string;
  };
}

// Canonical JSON serialization with sorted keys
export function canonicalStringify(obj: unknown): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return `[${obj.map((item) => canonicalStringify(item)).join(',')}]`;
  }
  const keys = Object.keys(obj as Record<string, unknown>).sort();
  const entries = keys.map(
    (k) => `${JSON.stringify(k)}:${canonicalStringify((obj as Record<string, unknown>)[k])}`
  );
  return `{${entries.join(',')}}`;
}

// Compute SHA-256 hash of canonical tool schema
export function computeToolHash(tool: ToolSchemaObject): { hash: string; canonical: string } {
  const norm: Record<string, unknown> = {
    name: tool.name,
    description: tool.description ?? '',
    inputSchema: tool.inputSchema ?? {},
  };
  if (tool.annotations !== undefined) {
    norm.annotations = tool.annotations;
  }
  const canonical = canonicalStringify(norm);
  const hash = crypto.createHash('sha256').update(canonical).digest('hex');
  return { hash, canonical };
}

// In-memory cache for ultra-fast verification: key is `${upstreamId}:${toolName}`
const memoryPins = new Map<string, SchemaPin>();

function makeCacheKey(upstreamId: string, toolName: string): string {
  return `${upstreamId}:${toolName}`;
}

export function initSchemaPins(): void {
  try {
    const db = getSharedDb();
    const rows = db
      .prepare(`
        SELECT id, upstream_id, tool_name, sha256_hash as hash, canonical_schema_json as canonical_json, approved_at as first_seen, drift_detected
        FROM schema_pins
      `)
      .all() as SchemaPin[];

    for (const row of rows) {
      memoryPins.set(makeCacheKey(row.upstream_id, row.tool_name), row);
      memoryPins.set(row.tool_name, row); // fallback for direct tool lookups
    }
  } catch (err) {
    console.error('[SchemaPinning] DB load error:', err);
  }
}

export function pinTools(tools: ToolSchemaObject[], upstreamId: string = 'local-upstream'): void {
  const db = getSharedDb();
  const insertStmt = db.prepare(`
    INSERT OR REPLACE INTO schema_pins (
      id, upstream_id, tool_name, sha256_hash, canonical_schema_json, approved_at, drift_detected, drift_diff_json
    ) VALUES (
      @id, @upstream_id, @tool_name, @sha256_hash, @canonical_schema_json, @approved_at, 0, NULL
    )
  `);

  const now = new Date().toISOString();
  for (const tool of tools) {
    const key = makeCacheKey(upstreamId, tool.name);
    if (!memoryPins.has(key)) {
      const { hash, canonical } = computeToolHash(tool);
      const pinId = `pin_${tool.name}_${Math.random().toString(36).slice(2, 6)}`;
      const pin: SchemaPin = {
        id: pinId,
        upstream_id: upstreamId,
        tool_name: tool.name,
        hash,
        canonical_json: canonical,
        first_seen: now,
        drift_detected: 0,
      };
      memoryPins.set(key, pin);
      memoryPins.set(tool.name, pin);
      try {
        insertStmt.run({
          id: pinId,
          upstream_id: upstreamId,
          tool_name: tool.name,
          sha256_hash: hash,
          canonical_schema_json: canonical,
          approved_at: now,
        });
      } catch (e) {
        console.error(`[SchemaPinning] Failed to persist pin for ${tool.name}:`, e);
      }
    }
  }
}

export function verifyToolSchema(
  tool: ToolSchemaObject,
  upstreamId: string = 'local-upstream'
): SchemaVerificationResult {
  const key = makeCacheKey(upstreamId, tool.name);
  let pin = memoryPins.get(key) || memoryPins.get(tool.name);

  const db = getSharedDb();
  if (!pin) {
    const row = db
      .prepare(
        'SELECT id, upstream_id, tool_name, sha256_hash as hash, canonical_schema_json as canonical_json, approved_at as first_seen, drift_detected FROM schema_pins WHERE upstream_id = ? AND tool_name = ?'
      )
      .get(upstreamId, tool.name) as any;
    if (row) {
      pin = row;
      memoryPins.set(key, row);
      memoryPins.set(tool.name, row);
    }
  }

  if (!pin) {
    // First time seeing tool, pin it
    pinTools([tool], upstreamId);
    return { valid: true, tool_name: tool.name };
  }

  const { hash, canonical } = computeToolHash(tool);
  if (hash === pin.hash) {
    return { valid: true, tool_name: tool.name };
  }

  // Schema drift detected!
  const oldObj = JSON.parse(pin.canonical_json);
  const newObj = {
    name: tool.name,
    description: tool.description ?? '',
    inputSchema: tool.inputSchema ?? {},
    ...(tool.annotations !== undefined ? { annotations: tool.annotations } : {}),
  };

  const isDescMutation = oldObj.description !== newObj.description;
  const isInputMutation = canonicalStringify(oldObj.inputSchema) !== canonicalStringify(newObj.inputSchema);

  const field = isDescMutation ? 'description' : isInputMutation ? 'inputSchema' : 'annotations';
  const diffSummary = isDescMutation
    ? `Description mutated from "${oldObj.description}" to "${newObj.description}"`
    : isInputMutation
    ? `inputSchema mutated from ${canonicalStringify(oldObj.inputSchema)} to ${canonicalStringify(newObj.inputSchema)}`
    : `Annotations mutated`;

  const diff = {
    field,
    oldSchema: oldObj,
    newSchema: newObj,
    oldValue: (oldObj as any)[field],
    newValue: (newObj as any)[field],
    diffSummary,
  };

  try {
    db.prepare(`
      UPDATE schema_pins
      SET drift_detected = 1, drift_diff_json = ?
      WHERE tool_name = ? AND upstream_id = ?
    `).run(JSON.stringify(diff), tool.name, upstreamId);
  } catch {}

  return {
    valid: false,
    tool_name: tool.name,
    driftType: isDescMutation ? 'DESCRIPTION_MUTATION' : 'INPUT_SCHEMA_MUTATION',
    expectedHash: pin.hash,
    actualHash: hash,
    diff,
  };
}

export function approvePin(upstreamId: string, pinId: string): boolean {
  const db = getSharedDb();
  const row = db
    .prepare('SELECT * FROM schema_pins WHERE (id = ? OR tool_name = ?) AND upstream_id = ?')
    .get(pinId, pinId, upstreamId) as any;

  if (!row) return false;

  let newHash = row.sha256_hash;
  let newCanonical = row.canonical_schema_json;

  if (row.drift_diff_json) {
    try {
      const diff = JSON.parse(row.drift_diff_json);
      if (diff.newSchema) {
        newCanonical = canonicalStringify(diff.newSchema);
        newHash = crypto.createHash('sha256').update(newCanonical).digest('hex');
      }
    } catch {}
  }

  const now = new Date().toISOString();
  db.prepare(`
    UPDATE schema_pins
    SET sha256_hash = ?, canonical_schema_json = ?, drift_detected = 0, drift_diff_json = NULL, approved_at = ?
    WHERE id = ?
  `).run(newHash, newCanonical, now, row.id);

  const updatedPin: SchemaPin = {
    id: row.id,
    upstream_id: upstreamId,
    tool_name: row.tool_name,
    hash: newHash,
    canonical_json: newCanonical,
    first_seen: now,
    drift_detected: 0,
  };

  memoryPins.set(makeCacheKey(upstreamId, row.tool_name), updatedPin);
  memoryPins.set(row.tool_name, updatedPin);

  return true;
}

export function resetSchemaPins(): void {
  memoryPins.clear();
  try {
    const db = getSharedDb();
    db.exec('DELETE FROM schema_pins');
  } catch {}
}
