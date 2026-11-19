import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {resolve} from 'node:path';
import {randomUUID,generateKeyPairSync,createHash} from 'node:crypto';
import {createEvidenceAuditor,signEvidenceCheckpoint,verifyEvidenceTransition,compareEvidenceInventory} from '../../src/security/evidence-attestation.mjs';
if(process.env.VV_LIVE_TEST!=='1'||process.env.PGDATABASE!=='verivaro_test'||!process.env.VV_TEST_DRIVER_DIR||!process.env.VV_EVIDENCE_AUDITOR_PASSWORD)throw Error('disposable CI only');
const {Pool}=createRequire(resolve(process.env.VV_TEST_DRIVER_DIR,'package.json'))('pg');
const cfg={host:process.env.PGHOST,port:Number(process.env.PGPORT),database:process.env.PGDATABASE,max:1,connectionTimeoutMillis:3000,query_timeout:35000};
test('live custody ledger independently signs append-only evidence inventory; tamper and role bypass denied',{timeout:60000},async()=>{
 const admin=new Pool({...cfg,user:process.env.PGUSER,password:process.env.PGPASSWORD}),audit=new Pool({...cfg,user:'vv_ci_evidence_auditor',password:process.env.VV_EVIDENCE_AUDITOR_PASSWORD});
 const inventory=createEvidenceAuditor(audit,{expectedLogin:'vv_ci_evidence_auditor'});
 const {privateKey:signingKey,publicKey:verificationKey}=generateKeyPairSync('ed25519'),scope={installationId:randomUUID(),database:'verivaro_test'};
 try{
  const first=await inventory();assert.ok(first.some(x=>x.encrypted));assert.ok(first.every(x=>Object.keys(x).length===3));
  const a=signEvidenceCheckpoint({...scope,inventory:first,signingKey,initial:true});
  const id=randomUUID();
  await admin.query("INSERT INTO verivaro.evidence(id,tenant_id,project_id,sha256,storage_ref,created_by) VALUES($1,$2,$3,$4,$5,$6)",[id,'11111111-1111-4111-8111-111111111111','33333333-3333-4333-8333-333333333333',createHash('sha256').update(id).digest('hex'),'private://'+id,randomUUID()]);
  const second=await inventory(),b=signEvidenceCheckpoint({...scope,inventory:second,signingKey,previous:a});
  assert.equal(verifyEvidenceTransition({...scope,verificationKey,previous:a,next:b}).added,1);
  assert.equal(compareEvidenceInventory({...scope,verificationKey,...b,inventory:second}).unattested,0);
  const c=await audit.connect();
  try{await c.query('SET ROLE verivaro_evidence_auditor');
   await assert.rejects(c.query('SELECT envelope FROM verivaro_private.evidence_objects'),e=>e.code==='42501');
   await assert.rejects(c.query('SELECT verivaro_ingestion.authorize_upload($1,$2)',[randomUUID(),randomUUID()]),e=>e.code==='42501');
  }finally{c.release(true);}
  // Simulate a malicious DBA changing an envelope, inside a rolled-back test
  // transaction. Verify the database-side integrity gate directly.
  const d=await admin.connect();
  try{
   await d.query('BEGIN');
   await d.query('ALTER TABLE verivaro_private.evidence_objects DISABLE TRIGGER evidence_object_immutable');
   await d.query("UPDATE verivaro_private.evidence_objects SET envelope=set_byte(envelope,0,get_byte(envelope,0)#1) WHERE evidence_id=(SELECT evidence_id FROM verivaro_private.evidence_objects LIMIT 1)");
   await assert.rejects(d.query('SELECT * FROM verivaro_ingestion.attestation_inventory()'),/evidence integrity mismatch/);
  }finally{await d.query('ROLLBACK');d.release(true);}
  assert.equal(compareEvidenceInventory({...scope,verificationKey,...b,inventory:await inventory()}).unattested,0);
  console.log('independent_evidence_checkpoint_gate_passed');
 }finally{await admin.end();await audit.end();}
});
