// Offline operator-only, fail-closed retention gate. An active legal hold
// registry and independent signed approvals are mandatory before deletion.
import {createHash,createPrivateKey,createPublicKey,sign,verify} from 'node:crypto';
const fail=()=>{throw Error('PDF retention approval denied');};
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const sha=/^[a-f0-9]{64}$/;
const iso=t=>typeof t==='string'&&Number.isFinite(Date.parse(t))&&new Date(t).toISOString()===t;
const hash=b=>createHash('sha256').update(b).digest('hex');
const identity=key=>{const k=key?.type==='public'?key:createPublicKey(key);if(k.asymmetricKeyType!=='ed25519')fail();return {key:k,fingerprint:hash(k.export({format:'der',type:'spki'}))};};
const keys=(obj,expected)=>obj&&typeof obj==='object'&&!Array.isArray(obj)&&Object.keys(obj).sort().join(',')===expected.slice().sort().join(',');
const scope=['tenantId','projectId','quarantineId','sourceSha256'];
const policyKeys=['version','action',...scope,'policyId','issuedAt','retainUntil','legalHold'];
const approvalKeys=['version','action',...scope,'policyId','actorId','issuedAt','expiresAt'];
function payloadBytes(x,kind){
 const p=x?.payload;
 if(!keys(x,['payload','signature'])||!p||!uuid.test(p.tenantId)||!uuid.test(p.projectId)||!uuid.test(p.quarantineId)||!sha.test(p.sourceSha256)||!uuid.test(p.policyId)||p.version!==1||p.action!=='delete-original-pdf'||!iso(p.issuedAt))fail();
 if(kind==='policy'){
  if(!keys(p,policyKeys)||!iso(p.retainUntil)||p.legalHold!==false||Date.parse(p.retainUntil)<=Date.parse(p.issuedAt))fail();
 }else if(kind==='approval'){
  if(!keys(p,approvalKeys)||!uuid.test(p.actorId)||!iso(p.expiresAt)||Date.parse(p.expiresAt)<=Date.parse(p.issuedAt)||Date.parse(p.expiresAt)-Date.parse(p.issuedAt)>48*3600000)fail();
 }else fail();
 return Buffer.from(JSON.stringify(p),'utf8');
}
export function signPdfRetentionDocument(payload,privateKey,kind){
 const key=privateKey?.type==='private'?privateKey:createPrivateKey(privateKey);
 if(key.asymmetricKeyType!=='ed25519')fail();
 return {payload,signature:sign(null,payloadBytes({payload,signature:''},kind),key).toString('base64url')};
}
function verifyDocument(document,trustedKey,kind){
 const bytes=payloadBytes(document,kind),signature=document.signature;
 if(typeof signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(signature))fail();
 const decoded=Buffer.from(signature,'base64url');
 if(decoded.length!==64||decoded.toString('base64url')!==signature||!verify(null,bytes,trustedKey.key,decoded))fail();
 return document.payload;
}
export function createPdfRetentionGate({policyPublicKey,approvers,holdLookup,clock=()=>new Date()}={}){
 if(typeof holdLookup!=='function'||typeof clock!=='function'||!Array.isArray(approvers)||approvers.length<2||approvers.length>8)fail();
 const policyKey=identity(policyPublicKey),members=new Map(),fingerprints=new Set([policyKey.fingerprint]);
 for(const a of approvers){
  if(!uuid.test(a?.actorId)||members.has(a.actorId))fail();
  const k=identity(a.publicKey);
  if(fingerprints.has(k.fingerprint))fail();
  fingerprints.add(k.fingerprint);members.set(a.actorId,k);
 }
 return async function verifyDeletion(meta,authorization,signal){
  signal?.throwIfAborted();
  if(!meta||!authorization||!keys(authorization,['policy','approvals'])||!Array.isArray(authorization.approvals)||authorization.approvals.length!==2)fail();
  const now=clock();if(!(now instanceof Date)||!Number.isFinite(now.getTime()))fail();
  const time=now.getTime(),policy=verifyDocument(authorization.policy,policyKey,'policy');
  for(const k of scope)if(policy[k]!== (k==='sourceSha256'?meta.sha256:meta[k]))fail();
  if(Date.parse(policy.issuedAt)>time||Date.parse(policy.retainUntil)>time)fail();
  const signers=new Set();
  for(const doc of authorization.approvals){
   const actor=doc?.payload?.actorId,key=members.get(actor);
   if(!key||signers.has(actor))fail();
   const approval=verifyDocument(doc,key,'approval');
   for(const k of scope)if(approval[k]!==policy[k])fail();
   if(approval.policyId!==policy.policyId||Date.parse(approval.issuedAt)<Date.parse(policy.issuedAt)||Date.parse(approval.issuedAt)>time||Date.parse(approval.expiresAt)<=time)fail();
   signers.add(actor);
  }
  signal?.throwIfAborted();
  // A missing, stale or ambiguous answer is never interpreted as "no hold".
  const held=await holdLookup(Object.freeze({tenantId:meta.tenantId,projectId:meta.projectId,quarantineId:meta.quarantineId,sourceSha256:meta.sha256}),signal);
  signal?.throwIfAborted();
  if(held!==false)fail();
  return true;
 };
}
