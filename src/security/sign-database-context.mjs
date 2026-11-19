import { createHmac } from 'node:crypto';
import { verifyIdentityToken } from './verify-identity.mjs';

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Trusted service only. Never expose this as an unrestricted SQL/API signing oracle.
 * challenge must come from the same live database transaction, not a client request.
 * The database independently checks active membership. Revocation and project-level
 * authorization are additional acceptance gates. Key supplied by secure provisioning.
 */
export function signDatabaseContext({ token, tenantId, challenge }, { verifier, key, now = Math.floor(Date.now()/1000) }) {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error('invalid database context key');
  if (!Number.isSafeInteger(now) || now < 1 || !uuid.test(tenantId) || typeof tenantId !== 'string') throw new Error('invalid tenant or clock');
  const principal = verifyIdentityToken(token, { ...verifier, now });
  if (!challenge || !Number.isSafeInteger(challenge.pid) || challenge.pid < 1 || challenge.pid > 2147483647 ||
      typeof challenge.xid !== 'string' || !/^[1-9][0-9]{0,19}$/.test(challenge.xid) ||
      BigInt(challenge.xid) > 18446744073709551615n) throw new Error('invalid transaction challenge');
  const expiry = Math.min(now + 45, principal.expiresAt);
  const payload = ['v1', tenantId.toLowerCase(), principal.actorId.toLowerCase(), challenge.pid, challenge.xid, expiry].join('|');
  return payload + '|' + createHmac('sha256', key).update(payload, 'utf8').digest('hex');
}
