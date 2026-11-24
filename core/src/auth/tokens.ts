import * as jose from 'jose';
import { z } from 'zod';
import crypto from 'node:crypto';

// EdDSA key pair generated once at startup or stored in memory
let privateKey: Parameters<typeof jose.SignJWT.prototype.sign>[0];
let publicKey: Parameters<typeof jose.jwtVerify>[1];
let keyFingerprint = 'ed25519-default';

const ISSUER = 'aegisveto.security.local';
const DEFAULT_TTL_SEC = 900; // 15 minutes

export const TokenRequestSchema = z.object({
  agent_id: z.string().optional().default('local-dev-agent'),
  session_id: z.string().optional(),
  allowed_scopes: z.array(z.string()).default(['read_file', 'bash_exec', '*']),
  max_calls: z.number().int().positive().default(100),
  ttl_sec: z.number().int().positive().max(86400).default(DEFAULT_TTL_SEC),
});

export type TokenRequest = z.input<typeof TokenRequestSchema>;

export interface TokenPayload {
  agent_id: string;
  session_id: string;
  allowed_scopes: string[];
  max_calls: number;
}

export async function initKeys(): Promise<void> {
  const kp = await jose.generateKeyPair('EdDSA');
  privateKey = kp.privateKey;
  publicKey = kp.publicKey;

  // Export public key to compute fingerprint
  try {
    const spki = await jose.exportSPKI(publicKey);
    keyFingerprint = crypto.createHash('sha256').update(spki).digest('hex').slice(0, 16);
  } catch {
    keyFingerprint = 'ed25519-active';
  }
}

export function getKeyFingerprint(): string {
  return keyFingerprint;
}

export async function issueToken(req: TokenRequest): Promise<{ token: string; session_id: string; agent_id: string; expires_at: string; key_fingerprint: string }> {
  if (!privateKey) {
    await initKeys();
  }

  const agentId = req.agent_id || 'local-dev-agent';
  const sessionId = req.session_id ?? `sess_${crypto.randomBytes(6).toString('hex')}`;
  const ttlSec = req.ttl_sec ?? DEFAULT_TTL_SEC;
  const expiresAt = new Date(Date.now() + ttlSec * 1000);
  const allowedScopes = req.allowed_scopes ?? ['*'];
  const maxCalls = req.max_calls ?? 100;

  const token = await new jose.SignJWT({
    agent_id: agentId,
    session_id: sessionId,
    allowed_scopes: allowedScopes,
    max_calls: maxCalls,
  })
    .setProtectedHeader({ alg: 'EdDSA' })
    .setIssuedAt()
    .setIssuer(ISSUER)
    .setSubject(agentId)
    .setExpirationTime(expiresAt)
    .sign(privateKey);

  return {
    token,
    session_id: sessionId,
    agent_id: agentId,
    expires_at: expiresAt.toISOString(),
    key_fingerprint: keyFingerprint,
  };
}

export async function verifyToken(token: string): Promise<TokenPayload> {
  if (!publicKey) {
    await initKeys();
  }

  const { payload } = await jose.jwtVerify(token, publicKey, { issuer: ISSUER });
  return {
    agent_id: (payload.agent_id as string) || (payload.sub as string) || 'local-dev-agent',
    session_id: (payload.session_id as string) || '',
    allowed_scopes: (payload.allowed_scopes as string[]) || ['*'],
    max_calls: (payload.max_calls as number) || 100,
  };
}
