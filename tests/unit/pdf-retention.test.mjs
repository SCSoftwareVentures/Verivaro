import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readdir,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {generateKeyPairSync,randomBytes,randomUUID} from 'node:crypto';
import {canonicalTextPdf} from '../../src/security/evidence-formats.mjs';
import {createOriginalPdfQuarantine} from '../../src/security/pdf-quarantine.mjs';
import {createPdfRetentionGate,signPdfRetentionDocument} from '../../src/security/pdf-retention.mjs';
const now='2026-11-21T11:00:00.000Z';
const id=()=>randomUUID(),source=canonicalTextPdf(['Equipment must carry ID.']),pair=()=>generateKeyPairSync('ed25519');
test('dual signatures, independent hold and durable deletion receipts',async()=>{
 const root=await mkdtemp(join(tmpdir(),'vv-pdf-life-')),key=randomBytes(32),policyKey=pair(),reviewers=[pair(),pair()],actors=[id(),id()];let hold=true;
 const gate=createPdfRetentionGate({policyPublicKey:policyKey.publicKey,approvers:reviewers.map((k,i)=>({actorId:actors[i],publicKey:k.publicKey})),holdLookup:async()=>hold,clock:()=>new Date(now)});
 let acquired=0;const vault=createOriginalPdfQuarantine({root,key,keyId:'lifecycle',scan:async()=> 'clean',retentionGate:gate,withExclusiveHoldLock:async(meta,fn,signal)=>{acquired++;signal.throwIfAborted();return fn();}}),signal=new AbortController().signal;
 try{
  const meta=await vault.put({source,tenantId:id(),projectId:id(),signal});
  const scope={tenantId:meta.tenantId,projectId:meta.projectId,quarantineId:meta.quarantineId,sourceSha256:meta.sha256};
  const policy=signPdfRetentionDocument({...scope,version:1,action:'delete-original-pdf',policyId:id(),issuedAt:'2026-10-01T00:00:00.000Z',retainUntil:'2026-11-20T00:00:00.000Z',legalHold:false},policyKey.privateKey,'policy');
  const approvals=reviewers.map((k,i)=>signPdfRetentionDocument({...scope,version:1,action:'delete-original-pdf',policyId:policy.payload.policyId,actorId:actors[i],issuedAt:'2026-11-20T00:00:00.000Z',expiresAt:'2026-11-22T00:00:00.000Z'},k.privateKey,'approval'));
  const authorization={policy,approvals};
  await assert.rejects(vault.destroy(meta,{authorization,signal}));assert.equal((await readdir(root)).length,1);
  hold=false;
  await assert.rejects(vault.destroy(meta,{authorization:{policy,approvals:[approvals[0],approvals[0]]},signal}));
  await assert.rejects(vault.destroy({...meta,tenantId:id()},{authorization,signal}));
  await assert.rejects(vault.destroy(meta,{authorization:{policy,approvals:[approvals[0],{...approvals[1],payload:{...approvals[1].payload,sourceSha256:'0'.repeat(64)}}]},signal}));
  const result=await vault.destroy(meta,{authorization,signal});
  assert.equal(result.deleted,true);assert.ok(acquired>=5);assert.deepEqual(await readdir(root),[meta.quarantineId+'.deleted']);
  const receipt=JSON.parse(await readFile(join(root,result.receiptName),'utf8'));
  assert.equal(receipt.sha256,meta.sha256);
  await assert.rejects(vault.read(meta,{signal}));await assert.rejects(vault.destroy(meta,{authorization,signal}));
 }finally{vault.close();key.fill(0);await rm(root,{force:true,recursive:true});}
});
test('retention requires a trusted hold-lock coordinator',()=>{const k=randomBytes(32);try{assert.throws(()=>createOriginalPdfQuarantine({root:'/tmp/test',key:k,keyId:'test',scan:async()=> 'clean',retentionGate:async()=>true}));}finally{k.fill(0);}});
test('future retention, expired approvals and unavailable legal-hold data deny deletion',async()=>{
 const policyKey=pair(),a=pair(),b=pair(),actors=[id(),id()],meta={tenantId:id(),projectId:id(),quarantineId:id(),sha256:'a'.repeat(64)};
 let held=undefined;
 const gate=createPdfRetentionGate({policyPublicKey:policyKey.publicKey,approvers:[{actorId:actors[0],publicKey:a.publicKey},{actorId:actors[1],publicKey:b.publicKey}],holdLookup:async()=>held,clock:()=>new Date(now)});
 const scope={tenantId:meta.tenantId,projectId:meta.projectId,quarantineId:meta.quarantineId,sourceSha256:meta.sha256};
 const mk=(until,expiry='2026-11-22T00:00:00.000Z')=>{
  const policy=signPdfRetentionDocument({...scope,version:1,action:'delete-original-pdf',policyId:id(),issuedAt:'2026-11-19T00:00:00.000Z',retainUntil:until,legalHold:false},policyKey.privateKey,'policy');
  const approvals=[a,b].map((k,i)=>signPdfRetentionDocument({...scope,version:1,action:'delete-original-pdf',policyId:policy.payload.policyId,actorId:actors[i],issuedAt:'2026-11-20T00:00:00.000Z',expiresAt:expiry},k.privateKey,'approval'));
  return {policy,approvals};
 };
 const signal=new AbortController().signal;
 for(const auth of [mk('2026-11-22T00:00:00.000Z'),mk('2026-11-20T00:00:00.000Z','2026-11-20T12:00:00.000Z')])await assert.rejects(gate(meta,auth,signal));
 const auth=mk('2026-11-20T00:00:00.000Z');await assert.rejects(gate(meta,auth,signal));
 held=false;assert.equal(await gate(meta,auth,signal),true);
 held=true;await assert.rejects(gate(meta,auth,signal));
 assert.throws(()=>createPdfRetentionGate({policyPublicKey:policyKey.publicKey,approvers:[{actorId:actors[0],publicKey:a.publicKey},{actorId:actors[1],publicKey:a.publicKey}],holdLookup:async()=>false}));
});

test('journal and signed retention gate deny unknown and active holds, permit explicit release',async()=>{
 const {createLocalPdfHoldRegistry}=await import('../../src/security/pdf-hold-registry.mjs');
 const root=await mkdtemp(join(tmpdir(),'vv-ret-hold-')),holdRoot=await mkdtemp(join(tmpdir(),'vv-ret-journal-')),key=randomBytes(32),holdKey=randomBytes(32);
 const policyKey=pair(),a=pair(),b=pair(),actors=[id(),id()],signal=new AbortController().signal;
 let allowed=true;
 const registry=createLocalPdfHoldRegistry({root:holdRoot,key:holdKey,authorizeChange:async()=>allowed});
 const retention=createPdfRetentionGate({policyPublicKey:policyKey.publicKey,approvers:[{actorId:actors[0],publicKey:a.publicKey},{actorId:actors[1],publicKey:b.publicKey}],holdLookup:registry.holdLookup,clock:()=>new Date(now)});
 const vault=createOriginalPdfQuarantine({root,key,keyId:'originals',scan:async()=> 'clean',retentionGate:retention,withExclusiveHoldLock:registry.withExclusiveHoldLock});
 try{
  const m=await vault.put({tenantId:id(),projectId:id(),source,signal}),sc={tenantId:m.tenantId,projectId:m.projectId,quarantineId:m.quarantineId,sourceSha256:m.sha256};
  const policy=signPdfRetentionDocument({...sc,version:1,action:'delete-original-pdf',policyId:id(),issuedAt:'2026-10-01T00:00:00.000Z',retainUntil:'2026-11-20T00:00:00.000Z',legalHold:false},policyKey.privateKey,'policy');
  const approvals=[a,b].map((k,i)=>signPdfRetentionDocument({...sc,version:1,action:'delete-original-pdf',policyId:policy.payload.policyId,actorId:actors[i],issuedAt:'2026-11-20T00:00:00.000Z',expiresAt:'2026-11-22T00:00:00.000Z'},k.privateKey,'approval'));
  const authorization={policy,approvals};
  await assert.rejects(vault.destroy(m,{authorization,signal})); // no event, unknown
  await registry.recordHoldChange(m,{actorId:id(),held:true,reason:'Evidence litigation hold active',signal});
  await assert.rejects(vault.destroy(m,{authorization,signal}));
  allowed=false;await assert.rejects(registry.recordHoldChange(m,{actorId:id(),held:false,reason:'Not approved for release',signal}));
  allowed=true;await registry.recordHoldChange(m,{actorId:id(),held:false,reason:'Trusted reviewer released legal hold',signal});
  assert.equal((await vault.destroy(m,{authorization,signal})).deleted,true);
  await assert.rejects(vault.read(m,{signal}));
 }finally{vault.close();registry.close();key.fill(0);holdKey.fill(0);await rm(root,{force:true,recursive:true});await rm(holdRoot,{force:true,recursive:true});}
});
