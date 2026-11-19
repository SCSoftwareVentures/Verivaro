import { createHash, randomBytes } from 'node:crypto';
// Never log bearer tokens or digest values. Digest is a private gateway credential.
export function digestShareToken(token) {
 if(typeof token!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(token)) throw new Error('invalid share token');
 const bytes=Buffer.from(token,'base64url');
 if(bytes.length!==32||bytes.toString('base64url')!==token) throw new Error('invalid share token');
 return createHash('sha256').update(bytes).digest();
}
export function generateShareToken(){
 const token=randomBytes(32).toString('base64url');
 return Object.freeze({token,digest:digestShareToken(token)});
}
