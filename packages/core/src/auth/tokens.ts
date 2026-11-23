import * as jose from 'jose';
import { z } from 'zod';
import crypto from 'node:crypto';

// EdDSA key pair generated once at startup — jose v6 returns CryptoKey on Node 22+
let privateKey: Parameters<typeof jose.SignJWT.prototype.sign>[0];
let publicKey: Parameters<typeof jose.jwtVerify>[1];

const ISSUER = 'aegisveto.security.local';
const DEFAULT_TTL_SEC = 900; // 15 minutes

export const TokenRequestSchema = z.object({
  session_id: z.string().optional(),
  allowed_scopes: z.array(z.string()).default(['read_file', 'bash_exec']),
  max_calls: z.number().int().positive().default(100),
  ttl_sec: z.number().int().positive().max(3600).default(DEFAULT_TTL_SEC),
});

export type TokenRequest = z.infer<typeof TokenRequestSchema>;

export interface TokenPayload {
  session_id: string;
  allowed_scopes: string[];
  max_calls: number;
}

export async function initKeys(): Promise<void> {
  const kp = await jose.generateKeyPair('EdDSA');
  privateKey = kp.privateKey;
  publicKey = kp.publicKey;
}

export async function issueToken(req: TokenRequest): Promise<{ token: string; session_id: string; expires_at: string }> {
  const sessionId = req.session_id ?? `sess_${crypto.randomBytes(6).toString('hex')}`;
  const expiresAt = new Date(Date.now() + req.ttl_sec * 1000);

  const token = await new jose.SignJWT({
    session_id: sessionId,
    allowed_scopes: req.allowed_scopes,
    max_calls: req.max_calls,
  })
    .setProtectedHeader({ alg: 'EdDSA' })
    .setIssuedAt()
    .setIssuer(ISSUER)
    .setExpirationTime(expiresAt)
    .sign(privateKey);

  return { token, session_id: sessionId, expires_at: expiresAt.toISOString() };
}

export async function verifyToken(token: string): Promise<TokenPayload> {
  const { payload } = await jose.jwtVerify(token, publicKey, { issuer: ISSUER });
  return {
    session_id: payload.session_id as string,
    allowed_scopes: payload.allowed_scopes as string[],
    max_calls: payload.max_calls as number,
  };
}
