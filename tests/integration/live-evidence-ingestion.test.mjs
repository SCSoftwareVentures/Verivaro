import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {resolve,join} from 'node:path';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {randomUUID,randomBytes,sign,createHash} from 'node:crypto';
import {local} from '../fixtures/provider-fixture.mjs';
import {fixturePng} from '../fixtures/evidence-formats-fixture.mjs';
import {canonicalTextPdf} from '../../src/security/evidence-formats.mjs';
import {scannerFixture} from '../fixtures/clamd-fixture.mjs';
import {createClamdScanner} from '../../src/security/clamd-scanner.mjs';
import {createEvidenceIngestion,createIngestionDatabase,IngestionDenied,IngestionRejected,IngestionConflict,IngestionQuota} from '../../src/security/evidence-ingestion.mjs';
import {openEvidence,createEvidenceRecoverySource} from '../../src/security/evidence-objects.mjs';
if(process.env.VV_LIVE_TEST!=='1'||process.env.PGDATABASE!=='verivaro_test'||!process.env.VV_TEST_DRIVER_DIR||!process.env.VV_INGEST_PASSWORD)throw Error('disposable CI only');
const {Pool}=createRequire(resolve(process.env.VV_TEST_DRIVER_DIR,'package.json'))('pg');
const cfg={host:process.env.PGHOST,port:Number(process.env.PGPORT),database:process.env.PGDATABASE,max:4,connectionTimeoutMillis:3000};
const tenant='11111111-1111-4111-8111-111111111111',project='33333333-3333-4333-8333-333333333333';
const verifier={publicKey:local.publicKey,issuer:'urn:verivaro:ingest-fixture',audience:'api'},enc=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
function token(actor,sid){const n=Math.floor(Date.now()/1000),b=enc({alg:'RS256',typ:'JWT'})+'.'+enc({iss:verifier.issuer,aud:verifier.audience,sub:actor,sid,iat:n,nbf:n,exp:n+300});return b+'.'+sign('RSA-SHA256',Buffer.from(b),local.privateKey).toString('base64url');}
test('real encrypted evidence registration, required scan, permissions, immutable audit and retry',{timeout:45000},async()=>{
 const admin=new Pool({...cfg,user:process.env.PGUSER,password:process.env.PGPASSWORD}),pool=new Pool({...cfg,user:'vv_ci_ingest',password:process.env.VV_INGEST_PASSWORD});
 const dir=await mkdtemp(join(tmpdir(),'vv-ingest-'));let fixture;
 try{
  const principals={};
  for(const role of ['contributor','viewer']){
   const actor=randomUUID(),sid=randomUUID();await admin.query('INSERT INTO verivaro.memberships(tenant_id,actor_id,role) VALUES($1,$2,$3)',[tenant,actor,role]);
   await admin.query('INSERT INTO verivaro.project_members(tenant_id,project_id,actor_id,role) VALUES($1,$2,$3,$4)',[tenant,project,actor,role]);
   await admin.query("INSERT INTO verivaro_private.identity_sessions(session_id,actor_id,expires_at) VALUES($1,$2,clock_timestamp()+interval '5 minutes')",[sid,actor]);principals[role]={actor,sid,token:token(actor,sid)};
  }
  fixture=await scannerFixture(dir);const key=randomBytes(32),contextKey=(await admin.query('SELECT key_bytes FROM verivaro_private.context_key WHERE singleton')).rows[0].key_bytes;
  const db=createIngestionDatabase(pool,{expectedLogin:'vv_ci_ingest',verifier,contextKey}),scan=createClamdScanner({socketPath:fixture.socketPath});
  const ingest=createEvidenceIngestion({db,scan,key,keyId:'fixture'});
  const input={data:Buffer.from('independently scanned evidence'),token:principals.contributor.token,tenantId:tenant,projectId:project,requestId:randomUUID(),signal:new AbortController().signal};
  await assert.rejects(ingest({...input,token:principals.viewer.token}),IngestionDenied);assert.equal(fixture.calls,0);
  await assert.rejects(ingest({...input,data:Buffer.from([255])}),IngestionRejected);assert.equal(fixture.calls,0);
  fixture.setVerdict('infected');await assert.rejects(ingest(input),IngestionRejected);
  fixture.setVerdict('error');await assert.rejects(ingest(input),/scanner unavailable/);
  assert.equal((await admin.query('SELECT count(*)::int AS n FROM verivaro_private.evidence_objects WHERE request_id=$1',[input.requestId])).rows[0].n,0);
  fixture.setVerdict('clean');const results=await Promise.all(Array.from({length:4},()=>ingest(input)));
  assert.ok(results.every(r=>r.id===results[0].id));const {id,sha256,bytes}=results[0];assert.equal(sha256,createHash('sha256').update(input.data).digest('hex'));assert.equal(bytes,input.data.length);
  const r=(await admin.query("SELECT *,encode(cipher_digest,'hex') AS cipher_hex FROM verivaro_private.evidence_objects WHERE evidence_id=$1",[id])).rows[0];
  assert.equal(r.scan_policy,'clamd-instream-format-v2');assert.equal(r.actor_id,principals.contributor.actor);
  assert.deepEqual(openEvidence({id,tenantId:tenant,projectId:project,sha256,bytes,keyId:r.key_id,envelope:r.envelope,cipherDigest:r.cipher_hex},key),input.data);
  const source=createEvidenceRecoverySource({client:admin,sourceRoot:dir,readKey:async k=>{assert.equal(k,'fixture');return key;}});
  const stream=await source(id,{signal:input.signal,maxBytes:262144});const parts=[];for await(const b of stream)parts.push(Buffer.from(b));assert.deepEqual(Buffer.concat(parts),input.data);
  await assert.rejects(ingest({...input,data:Buffer.from('different')}),IngestionConflict);
  await assert.rejects(admin.query('DELETE FROM verivaro_private.evidence_objects WHERE evidence_id=$1',[id]),e=>e.code==='42501');
  const c=await pool.connect();try{await c.query('SET ROLE verivaro_evidence_ingestor');await assert.rejects(c.query('SELECT * FROM verivaro_private.evidence_objects'),e=>e.code==='42501');await assert.rejects(c.query('INSERT INTO verivaro.evidence(id) VALUES($1)',[randomUUID()]),e=>e.code==='42501');}finally{c.release(true);}
  for(const [mediaType,data] of [['image/png',fixturePng()],['application/pdf',canonicalTextPdf(['Verified PDF evidence'])]]){
   const x=await ingest({...input,data,mediaType,requestId:randomUUID()});
   assert.equal(x.bytes,data.length);
   assert.equal((await admin.query('SELECT media_type FROM verivaro_private.evidence_objects WHERE evidence_id=$1',[x.id])).rows[0].media_type,mediaType);
  }
  // Exact actor storage budget exercised with real encrypted 256 KiB objects.
  const block=Buffer.alloc(262144,65);
  for(let i=0;i<31;i++)await ingest({...input,data:block,requestId:randomUUID()});
  const quotaRequest=randomUUID();
  await assert.rejects(ingest({...input,data:block,requestId:quotaRequest}),IngestionQuota);
  assert.equal((await admin.query('SELECT count(*)::int AS n FROM verivaro_private.evidence_objects WHERE request_id=$1',[quotaRequest])).rows[0].n,0);
  assert.equal((await ingest(input)).id,id);
  // Revocation after scan begins must still block the commit.
  const revoked=createEvidenceIngestion({db,key,keyId:'fixture',scan:async()=>{await admin.query('UPDATE verivaro.project_members SET revoked_at=clock_timestamp() WHERE actor_id=$1',[principals.contributor.actor]);return 'clean';}});
  await assert.rejects(revoked({...input,requestId:randomUUID()}),IngestionDenied);
  console.log('encrypted_evidence_ingestion_gate_passed');
 }finally{await fixture?.close();await admin.end();await pool.end();await rm(dir,{recursive:true,force:true});}
});
