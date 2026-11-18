import { createPublicKey, verify as verifySignature } from 'node:crypto';

const decode = (part) => {
  if (!/^[A-Za-z0-9_-]+$/.test(part) || part.length > 16384) throw new Error('invalid token encoding');
  const raw = Buffer.from(part, 'base64url');
  if (raw.toString('base64url') !== part) throw new Error('noncanonical token encoding');
  const value = JSON.parse(raw.toString('utf8'));
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid token object');
  return value;
};

export function verifyIdentityToken(token, { publicKey, issuer, audience, now = Math.floor(Date.now()/1000) }) {
  if (typeof token !== 'string' || token.length > 32768) throw new Error('invalid token');
  if (!publicKey || !issuer || !audience) throw new Error('missing verifier configuration');
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('invalid compact token');
  const [h,p,s] = parts;
  const header = decode(h);
  const claims = decode(p);
  if (header.alg !== 'RS256' || header.typ !== 'JWT' || header.crit !== undefined) throw new Error('unsupported token header');
  const signature = Buffer.from(s, 'base64url');
  if (!s || signature.toString('base64url') !== s) throw new Error('invalid signature encoding');
  const key = createPublicKey(publicKey);
  if (key.asymmetricKeyType !== 'rsa' || !verifySignature('RSA-SHA256',Buffer.from(h+'.'+p),key,signature)) {
    throw new Error('invalid token signature');
  }
  if (claims.iss !== issuer || claims.aud !== audience || typeof claims.sub !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(claims.sub)) {
    throw new Error('invalid identity claims');
  }
  if (!Number.isSafeInteger(now) || !Number.isSafeInteger(claims.exp) || claims.exp <= now ||
      !Number.isSafeInteger(claims.iat) || claims.iat > now ||
      !Number.isSafeInteger(claims.nbf) || claims.nbf > now) throw new Error('token outside validity window');
  if (claims.exp - claims.iat > 3600 || claims.exp <= claims.iat) throw new Error('token lifetime exceeds policy');
  return Object.freeze({ actorId: claims.sub, issuer: claims.iss, audience: claims.aud, expiresAt: claims.exp });
}
