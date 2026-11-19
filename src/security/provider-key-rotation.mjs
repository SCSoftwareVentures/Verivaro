import {createHash,createPublicKey,verify} from 'node:crypto';
import {createProviderVerifier} from './provider-identity.mjs';
// Signed operator-approved keyset snapshots, never fetched from JWT headers.
// Independently trusted monotonic checkpoint is required at startup.
export function createRotatingProviderVerifier({issuer,audience,requiredAcr,requiredAmr,authorityKey,checkpoint,catalogue,signature,now=()=>Math.floor(Date.now()/1000)}){
 const authority=authorityKey?.type==='public'?authorityKey:createPublicKey(authorityKey);
 if(authority.asymmetricKeyType!=='ed25519'||!Number.isSafeInteger(checkpoint?.sequence)||checkpoint.sequence<1||! /^[a-f0-9]{64}$/.test(checkpoint.digest))throw Error('invalid keyset trust anchor');
 let current;
 function accept(bytes,sig,anchor){
  if(!Buffer.isBuffer(bytes)||bytes.length>65536||!Buffer.isBuffer(sig)||sig.length!==64||!verify(null,bytes,authority,sig))throw Error('keyset signature denied');
  const m=JSON.parse(bytes.toString('utf8')),digest=createHash('sha256').update(bytes).digest('hex'),n=now();
  if(!m||m.version!==1||m.issuer!==issuer||m.audience!==audience||!Number.isSafeInteger(m.sequence)||m.sequence!==anchor.sequence||digest!==anchor.digest||
   !Number.isSafeInteger(m.issuedAt)||!Number.isSafeInteger(m.expiresAt)||m.issuedAt>n||m.expiresAt<=n||m.expiresAt-m.issuedAt>86400||m.expiresAt<=m.issuedAt||
   !Array.isArray(m.keys)||m.keys.length<1||m.keys.length>8)throw Error('keyset scope or freshness denied');
  const verifier=createProviderVerifier({issuer,audience,requiredAcr,requiredAmr,keys:m.keys.map(k=>({kid:k.kid,publicKey:k.pem}))});
  return {sequence:m.sequence,digest,expiresAt:m.expiresAt,verifier};
 }
 current=accept(catalogue,signature,checkpoint);
 return Object.freeze({issuer,audience,
  verify(token,n=now()){if(now()>=current.expiresAt)throw Error('keyset expired');return current.verifier.verify(token,n);},
  rotate(bytes,sig,anchor){
   const replacement=accept(bytes,sig,anchor);
   if(replacement.sequence<=current.sequence)throw Error('keyset rollback denied');
   current=replacement;return Object.freeze({sequence:current.sequence,digest:current.digest});
  }
 });
}
