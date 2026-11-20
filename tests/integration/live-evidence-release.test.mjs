import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {resolve,join} from 'node:path';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {createServer} from 'node:http';
import {randomUUID,randomBytes,sign} from 'node:crypto';
import {local} from '../fixtures/provider-fixture.mjs';
import {createEvidenceIngestion,createIngestionDatabase} from '../../src/security/evidence-ingestion.mjs';
import {createEvidenceReader} from '../../src/security/evidence-retrieval.mjs';
import {createEvidenceReleaseDatabase,createEvidencePublisher,ReleaseDenied,ReleaseConflict} from '../../src/security/evidence-release.mjs';
import {createShareResolver} from '../../src/security/share-resolver.mjs';
import {createShareDownloadHandler} from '../../src/security/share-download.mjs';
import {createPrivateFileStore} from '../../src/security/private-file-store.mjs';
import {generateShareToken} from '../../src/security/share-token.mjs';
if(process.env.VV_LIVE_TEST!=='1'||process.env.PGDATABASE!=='verivaro_test'||!process.env.VV_TEST_DRIVER_DIR||!process.env.VV_RELEASE_PASSWORD)throw Error('disposable CI only');
const {Pool}=createRequire(resolve(process.env.VV_TEST_DRIVER_DIR,'package.json'))('pg');
const cfg={host:process.env.PGHOST,port:Number(process.env.PGPORT),database:process.env.PGDATABASE,max:4,connectionTimeoutMillis:3000};
const tenantId='11111111-1111-4111-8111-111111111111',projectId='33333333-3333-4333-8333-333333333333';
const verifier={publicKey:local.publicKey,issuer:'urn:verivaro:release-fixture',audience:'api'},enc=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
function token(actor,sid){const n=Math.floor(Date.now()/1000),b=enc({alg:'RS256',typ:'JWT'})+'.'+enc({iss:verifier.issuer,aud:verifier.audience,sub:actor,sid,iat:n,nbf:n,exp:n+300});return b+'.'+sign('RSA-SHA256',Buffer.from(b),local.privateKey).toString('base64url');}
test('live evidence review separates three actors, fences stale approval and releases only approved bytes to recipient',{timeout:60000},async()=>{
 const pools=[];
 function pool(user,password){const p=new Pool({...cfg,user,password});pools.push(p);return p;}
 const admin=pool(process.env.PGUSER,process.env.PGPASSWORD),runtime=pool('vv_ci_runtime',process.env.VV_RUNTIME_PASSWORD),releasePool=pool('vv_ci_release',process.env.VV_RELEASE_PASSWORD),ingestPool=pool('vv_ci_ingest',process.env.VV_INGEST_PASSWORD),readerPool=pool('vv_ci_evidence_reader',process.env.VV_EVIDENCE_READER_PASSWORD),recipientPool=pool('vv_ci_recipient',process.env.VV_RECIPIENT_PASSWORD),bearerPool=pool('vv_ci_share',process.env.VV_SHARE_PASSWORD);
 const root=await mkdtemp(join(tmpdir(),'vv-release-'));let server;
 const key=randomBytes(32),signal=new AbortController().signal,principals={},scope={tenantId,projectId};
 try{
  for(const [label,role] of [['submitter','contributor'],['reviewer','reviewer'],['owner','owner'],['otherReviewer','reviewer'],['viewer','viewer'],['recipient',null]]){
   const actor=randomUUID(),sid=randomUUID();
   if(role){await admin.query('INSERT INTO verivaro.memberships(tenant_id,actor_id,role) VALUES($1,$2,$3)',[tenantId,actor,role]);await admin.query('INSERT INTO verivaro.project_members(tenant_id,project_id,actor_id,role) VALUES($1,$2,$3,$4)',[tenantId,projectId,actor,role]);}
   await admin.query("INSERT INTO verivaro_private.identity_sessions(actor_id,session_id,expires_at) VALUES($1,$2,clock_timestamp()+interval '5 minutes')",[actor,sid]);
   principals[label]={actor,sid,token:token(actor,sid)};
  }
  const contextKey=(await admin.query('SELECT key_bytes FROM verivaro_private.context_key WHERE singleton')).rows[0].key_bytes;
  const workflow=createEvidenceReleaseDatabase(runtime,{expectedLogin:'vv_ci_runtime',verifier,contextKey,mode:'workflow'});
  const release=createEvidenceReleaseDatabase(releasePool,{expectedLogin:'vv_ci_release',verifier,contextKey,mode:'publish'});
  const ingest=createEvidenceIngestion({db:createIngestionDatabase(ingestPool,{expectedLogin:'vv_ci_ingest',verifier,contextKey}),scan:async()=> 'clean',key,keyId:'release-fixture'});
  const retrieve=createEvidenceReader(readerPool,{expectedLogin:'vv_ci_evidence_reader',verifier,contextKey,readKey:async k=>{assert.equal(k,'release-fixture');return key;}});
  const publish=createEvidencePublisher({root,retrieve,release});
  const bytes=Buffer.from('reviewed and approved evidence');
  const object=await ingest({...scope,data:bytes,token:principals.submitter.token,signal,requestId:randomUUID()});
  const req={...scope,evidenceId:object.id,sha256:object.sha256,requestId:randomUUID()};
  const withActor=(r,who)=>({...r,token:principals[who].token});
  await assert.rejects(workflow.request(withActor(req,'owner')),ReleaseDenied);
  assert.equal(await workflow.request(withActor(req,'submitter')),req.requestId);
  assert.equal(await workflow.request(withActor(req,'submitter')),req.requestId);
  await assert.rejects(release.publish(withActor(req,'owner')),ReleaseDenied);
  const approval={...req,decision:'approved',reason:'verified'};
  await assert.rejects(workflow.review(withActor(approval,'submitter')),ReleaseDenied);
  await assert.rejects(workflow.review(withActor(approval,'owner')),ReleaseDenied);
  await assert.rejects(workflow.review(withActor({...approval,sha256:'0'.repeat(64)},'reviewer')),ReleaseDenied);
  const parallel=await Promise.all(Array.from({length:4},()=>workflow.review(withActor(approval,'reviewer'))));assert.ok(parallel.every(Boolean));
  await assert.rejects(workflow.review(withActor(approval,'otherReviewer')),ReleaseConflict);
  await assert.rejects(release.publish(withActor(req,'reviewer')),ReleaseDenied);
  // An intervening role change invalidates the original approval permanently.
  await admin.query('UPDATE verivaro.project_members SET role=role WHERE tenant_id=$1 AND project_id=$2 AND actor_id=$3',[tenantId,projectId,principals.reviewer.actor]);
  await assert.rejects(release.publish(withActor(req,'owner')),ReleaseDenied);
  const rejected={...req,requestId:randomUUID()};
  await workflow.request(withActor(rejected,'submitter'));
  await workflow.review(withActor({...rejected,decision:'rejected',reason:'insufficient_evidence'},'reviewer'));
  await assert.rejects(release.publish(withActor(rejected,'owner')),ReleaseDenied);
  const valid={...req,requestId:randomUUID()};
  await workflow.request(withActor(valid,'submitter'));
  await workflow.review(withActor({...valid,decision:'approved',reason:'verified'},'reviewer'));
  await assert.rejects(release.publish(withActor({...valid,evidenceId:randomUUID()},'owner')),ReleaseDenied);
  await assert.rejects(release.publish(withActor({...valid,tenantId:'22222222-2222-4222-8222-222222222222'},'owner')),ReleaseDenied);
  const outcome=await publish(withActor(valid,'owner'),{signal});assert.equal(outcome,valid.requestId);
  assert.equal(await publish(withActor(valid,'owner'),{signal}),outcome);
  assert.deepEqual(await readFile(join(root,object.id)),bytes);
  assert.equal((await admin.query("SELECT count(*)::int AS n FROM verivaro_private.evidence_release_receipts WHERE request_id=$1",[valid.requestId])).rows[0].n,1);
  assert.equal((await admin.query("SELECT bearer_allowed FROM verivaro_private.released_exports WHERE export_id=$1",[outcome])).rows[0].bearer_allowed,false);
  for(const table of ['evidence_release_requests','evidence_release_reviews','evidence_release_receipts'])await assert.rejects(admin.query('DELETE FROM verivaro_private.'+table+' WHERE request_id=$1',[valid.requestId]),e=>e.code==='42501');
  const c=await releasePool.connect();
  try{await c.query('SET ROLE verivaro_release_service');
   await assert.rejects(c.query('SELECT verivaro_sharing.register_export($1,$2,$3,$4,$5,false)',[randomUUID(),tenantId,projectId,randomUUID(),object.sha256]),e=>e.code==='42501');
   await assert.rejects(c.query('SELECT * FROM verivaro_private.evidence_release_reviews'),e=>e.code==='42501');
  }finally{c.release(true);}
  const recipient=principals.recipient,share=generateShareToken(),shareId=randomUUID();
  await workflow.issueRecipient({...scope,token:principals.owner.token,exportId:outcome,shareId,digest:share.digest,expiry:new Date(Date.now()+120000),recipientId:recipient.actor});
  server=createServer(createShareDownloadHandler({resolveShare:createShareResolver(bearerPool,{expectedLogin:'vv_ci_share'}),resolveRecipientShare:createShareResolver(recipientPool,{expectedLogin:'vv_ci_recipient',recipientBound:true}),recipientVerifier:verifier,openArtifact:createPrivateFileStore(root),maxBytes:262144,perPeerPerMinute:20}));
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  const get=(identity,recipientRoute=true)=>fetch('http://127.0.0.1:'+server.address().port+'/public/share/'+(recipientRoute?'recipient-download':'download'),{method:'POST',headers:{Authorization:'Bearer '+share.token,...(identity?{'X-Verivaro-Recipient':identity}:{})}});
  const delivered=await get(recipient.token);assert.equal(delivered.status,200);assert.deepEqual(Buffer.from(await delivered.arrayBuffer()),bytes);
  assert.equal((await get(principals.viewer.token)).status,404);
  assert.equal((await get(null,false)).status,404);
  await admin.query('SELECT verivaro_sharing.revoke_export($1)',[outcome]);assert.equal((await get(recipient.token)).status,404);
  await assert.rejects(release.publish(withActor(valid,'owner')),ReleaseConflict);
  console.log('controlled_evidence_release_gate_passed');
 }finally{if(server)await new Promise(r=>{server.closeAllConnections();server.close(r);});await Promise.all(pools.map(p=>p.end()));await rm(root,{recursive:true,force:true});}
});
