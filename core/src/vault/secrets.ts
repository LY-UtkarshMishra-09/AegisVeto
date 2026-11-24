import dotenv from 'dotenv';
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

dotenv.config({ path: path.join(findRepoRoot(), '.env') });
dotenv.config();

export interface VaultSecretResolution {
  env: Record<string, string>;
  headers: Record<string, string>;
  token?: string;
}

/**
 * Resolves upstream secrets from environment via AEGIS_VAULT_* prefix.
 * Secrets are injected into headers/env ONLY after a tool call clears Layer 1.
 */
export function resolveUpstreamSecret(
  vaultSecretRef: string | null | undefined
): VaultSecretResolution {
  if (!vaultSecretRef) {
    return { env: {}, headers: {} };
  }

  const env: Record<string, string> = {};
  const headers: Record<string, string> = {};

  const cleanKey = vaultSecretRef.toUpperCase().replace(/[^A-Z0-9_]/g, '_');
  const primaryKey = `AEGIS_VAULT_${cleanKey}`;

  // Check primary env variables
  const directValue =
    process.env[primaryKey] ||
    process.env[`AEGIS_VAULT_${vaultSecretRef}`] ||
    process.env[vaultSecretRef];

  if (directValue) {
    env[cleanKey] = directValue;
    env[vaultSecretRef] = directValue;
    headers['Authorization'] = directValue.startsWith('Bearer ')
      ? directValue
      : `Bearer ${directValue}`;
    return { env, headers, token: directValue };
  }

  // Check granular variables like AEGIS_VAULT_<REF>_HEADER_<NAME>
  for (const [k, v] of Object.entries(process.env)) {
    if (v && k.startsWith(primaryKey)) {
      const suffix = k.slice(primaryKey.length).replace(/^_/, '');
      if (suffix.startsWith('HEADER_')) {
        const headerName = suffix.replace(/^HEADER_/, '').replace(/_/g, '-');
        headers[headerName] = v;
      } else if (suffix === 'HEADER') {
        headers['Authorization'] = v;
      } else {
        env[suffix || cleanKey] = v;
      }
    }
  }

  return { env, headers, token: directValue };
}
