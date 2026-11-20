import {createHash,createPrivateKey,createPublicKey,sign,verify} from 'node:crypto';
import {verifyTrustProofPage} from './trustproof.mjs';
const hash=x=>createHash('sha256').update(x).digest('hex'),hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x),id=x=>typeof x==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(x),date=x=>typeof x==='string'&&Number.isFinite(Date.parse(x))&&new Date(x).toISOString()===x;
const fail=()=>{throw Error('audit checkpoint verification failed');};
function payload(v){
 if(!v||Object.keys(v).sort().join(',')!=='algorithm,headHash,headSequence,issuedAt,keyFingerprint,ledgerCount,projectId,sourceCount,tenantId,version'||v.version!==1||v.algorithm!=='Ed25519'||!id(v.tenantId)||!id(v.projectId)||!Number.isSafeInteger(v.headSequence)||v.headSequence<0||v.headSequence>8192||v.sourceCount!==v.headSequence||v.ledgerCount!==v.headSequence||!hex(v.headHash)||!hex(v.keyFingerprint)||!date(v.issuedAt))fail();
 return Buffer.from(JSON.stringify({version:1,algorithm:'Ed25519',tenantId:v.tenantId,projectId:v.projectId,headSequence:v.headSequence,headHash:v.headHash,sourceCount:v.sourceCount,ledgerCount:v.ledgerCount,keyFingerprint:v.keyFingerprint,issuedAt:v.issuedAt}),'utf8');
}
function publicIdentity(key){
 const k=key?.type==='public'?key:createPublicKey(key);if(k.asymmetricKeyType!=='ed25519')fail();return {key:k,fingerprint:hash(k.export({type:'spki',format:'der'}))};
}
export function createAuditCheckpointSigner(privateKey){
 const key=privateKey?.type==='private'?privateKey:createPrivateKey(privateKey);if(key.asymmetricKeyType!=='ed25519')fail();
 const pub=publicIdentity(key);
 return Object.freeze({fingerprint:pub.fingerprint,async issue({tenantId,projectId,readPage,signal,clock=()=>new Date()}){
  let cursor=0,previous='0'.repeat(64),head=null;const seen=new Set();
  for(let i=0;i<32;i++){
   signal?.throwIfAborted();const page=await readPage(cursor,256);
   if(page.tenantId!==tenantId||page.projectId!==projectId||page.headSequence>8192)fail();
   head??={headSequence:page.headSequence,headHash:page.headHash};
   const result=verifyTrustProofPage(page,{tenantId,projectId,afterSequence:cursor,previousHash:previous,...head});
   for(const e of page.entries){const k=e.sourceType+':'+e.sourceId;if(seen.has(k))fail();seen.add(k);}
   cursor=result.nextSequence;previous=result.nextHash;
   if(result.complete){
    // Recheck from the same head before signing; current authorization is checked by readPage.
    const end=await readPage(cursor,1);verifyTrustProofPage(end,{tenantId,projectId,afterSequence:cursor,previousHash:previous,...head});
    if(seen.size!==cursor)fail();
    signal?.throwIfAborted();
    const checkpoint={version:1,algorithm:'Ed25519',tenantId,projectId,...head,sourceCount:page.sourceCount,ledgerCount:page.ledgerCount,keyFingerprint:pub.fingerprint,issuedAt:clock().toISOString()};
    return {checkpoint,signature:sign(null,payload(checkpoint),key).toString('base64url'),publicKey:pub.key.export({type:'spki',format:'pem'}),limitations:['Application attestation of selected audit records, not an independent timestamp or legal signature.','Verify using an independently trusted public key. Retain checkpoint outside the application.','Database source digests and counts are attestations, not independently inspected raw evidence.']};
   }
  }
  fail();
 }});
}
export function verifySignedAuditCheckpoint(envelope,trustedPublicKey){
 const p=publicIdentity(trustedPublicKey),c=envelope?.checkpoint,s=envelope?.signature;
 if(c?.keyFingerprint!==p.fingerprint||typeof s!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(s))fail();
 const raw=Buffer.from(s,'base64url');if(raw.length!==64||raw.toString('base64url')!==s||!verify(null,payload(c),p.key,raw))fail();
 return {signatureVerified:true,checkpoint:c};
}
