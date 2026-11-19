import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {resolve} from 'node:path';
import {randomUUID,randomBytes,sign} from 'node:crypto';
import {buildRejectionPreflight} from '../../src/security/rejection-preflight.mjs';
import {compareSubmissionGraph} from '../../src/security/change-impact.mjs';
import {local} from '../fixtures/provider-fixture.mjs';
import {createEvidenceIngestion,createIngestionDatabase} from '../../src/security/evidence-ingestion.mjs';
import {createEvidenceReleaseDatabase,ReleaseDenied,ReleaseConflict} from '../../src/security/evidence-release.mjs';
if(process.env.VV_LIVE_TEST!=='1'||process.env.PGDATABASE!=='verivaro_test'||!process.env.VV_TEST_DRIVER_DIR||!process.env.VV_INGEST_PASSWORD)throw Error('disposable CI only');
const {Pool}=createRequire(resolve(process.env.VV_TEST_DRIVER_DIR,'package.json'))('pg');
const cfg={host:process.env.PGHOST,port:Number(process.env.PGPORT),database:process.env.PGDATABASE,max:4,connectionTimeoutMillis:3000,query_timeout:7000};
const verifier={publicKey:local.publicKey,issuer:'urn:verivaro:graph-fixture',audience:'api'},enc=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
function token(actor,sid){const n=Math.floor(Date.now()/1000),b=enc({alg:'RS256',typ:'JWT'})+'.'+enc({iss:verifier.issuer,aud:verifier.audience,sub:actor,sid,iat:n,nbf:n,exp:n+300});return b+'.'+sign('RSA-SHA256',Buffer.from(b),local.privateKey).toString('base64url');}
test('persistent graph independently reviews exact versions and links; contradictions and stale revisions block completion',{timeout:60000},async()=>{
 const admin=new Pool({...cfg,user:process.env.PGUSER,password:process.env.PGPASSWORD}),runtime=new Pool({...cfg,user:'vv_ci_runtime',password:process.env.VV_RUNTIME_PASSWORD}),ingestPool=new Pool({...cfg,user:'vv_ci_ingest',password:process.env.VV_INGEST_PASSWORD});
 const tenantId=randomUUID(),projectId=randomUUID(),foreignProject=randomUUID(),scope={tenantId,projectId},actors={};
 try{
  await admin.query('INSERT INTO verivaro.tenants(id,name) VALUES($1,$2)',[tenantId,'Graph fixture']);
  for(const p of [projectId,foreignProject])await admin.query('INSERT INTO verivaro.projects(id,tenant_id,name) VALUES($1,$2,$3)',[p,tenantId,'Graph project']);
  for(const [name,role] of [['owner','owner'],['author','contributor'],['reviewer','reviewer'],['reviewer2','reviewer'],['viewer','viewer'],['outsider','viewer']]){
   const a=randomUUID(),sid=randomUUID();
   await admin.query('INSERT INTO verivaro.memberships(tenant_id,actor_id,role) VALUES($1,$2,$3)',[tenantId,a,role]);
   await admin.query('INSERT INTO verivaro.project_members(tenant_id,project_id,actor_id,role) VALUES($1,$2,$3,$4)',[tenantId,name==='outsider'?foreignProject:projectId,a,role]);
   await admin.query("INSERT INTO verivaro_private.identity_sessions(actor_id,session_id,expires_at) VALUES($1,$2,clock_timestamp()+interval '5 minutes')",[a,sid]);actors[name]={a,token:token(a,sid)};
  }
  await admin.query("INSERT INTO verivaro.project_members(tenant_id,project_id,actor_id,role) VALUES($1,$2,$3,'contributor')",[tenantId,foreignProject,actors.author.a]);
  const contextKey=(await admin.query('SELECT key_bytes FROM verivaro_private.context_key WHERE singleton')).rows[0].key_bytes;
  const graph=createEvidenceReleaseDatabase(runtime,{expectedLogin:'vv_ci_runtime',verifier,contextKey,mode:'workflow'}),ingest=createEvidenceIngestion({db:createIngestionDatabase(ingestPool,{expectedLogin:'vv_ci_ingest',verifier,contextKey}),scan:async()=> 'clean',key:randomBytes(32),keyId:'graph-fixture'});
  const as=(who,x={})=>({...scope,token:actors[who].token,...x});
  const status=async()=> (await graph.assessment(as('viewer'))).summary;
  assert.equal((await status()).status,'not_assessed');
  await assert.rejects(graph.assessment(as('outsider')),ReleaseDenied);
  const rule={requirementId:randomUUID(),versionId:randomUUID(),expectedRevision:0,title:'Equipment identifier',criterion:'Serial number must match the approved register.',applicability:'required'};
  await assert.rejects(graph.writeRequirement(as('viewer',rule)),ReleaseDenied);
  const result=await graph.writeRequirement(as('author',rule));assert.deepEqual(await graph.writeRequirement(as('author',rule)),result);
  await assert.rejects(graph.writeRequirement(as('author',{...rule,title:'changed'})),ReleaseConflict);
  assert.equal((await status()).status,'blocked');
  const approve={versionId:rule.versionId,decision:'approved',reason:'Criterion confirmed manually'};
  await assert.rejects(graph.reviewRequirement(as('author',approve)),ReleaseDenied);
  await graph.reviewRequirement(as('reviewer',approve));
  const signal=new AbortController().signal;
  const upload=(text,who='author',p=projectId)=>ingest(as(who,{projectId:p,data:Buffer.from(text),requestId:randomUUID(),signal}));
  const good=await upload('Serial A123'),bad=await upload('Serial B456'),foreign=await upload('Foreign evidence','author',foreignProject),self=await upload('Reviewer supplied evidence','reviewer');
  const link=(e)=>({versionId:rule.versionId,linkId:randomUUID(),evidenceId:e.id,sha256:e.sha256});
  await assert.rejects(graph.linkEvidence(as('author',link(foreign))),ReleaseDenied);
  const first=link(good);await graph.linkEvidence(as('author',first));assert.equal(await graph.linkEvidence(as('author',first)),first.linkId);
  assert.equal((await status()).status,'blocked');
  const pass={linkId:first.linkId,decision:'pass',reason:'Exact identifier matched'};
  await assert.rejects(graph.reviewLink(as('author',pass)),ReleaseDenied);
  await graph.reviewLink(as('reviewer',pass));assert.equal((await status()).status,'criteria_satisfied');
  const ready=buildRejectionPreflight(await graph.assessment(as('viewer')));assert.equal(ready.mandatoryCoveragePercent,100);assert.equal(ready.blockers,0);
  // Simulate storage corruption with trusted admin in disposable CI only;
  // restore exact envelope immediately even when assertion fails.
  const originalEnvelope=(await admin.query('SELECT envelope FROM verivaro_private.evidence_objects WHERE evidence_id=$1',[good.id])).rows[0].envelope;
  const broken=Buffer.from(originalEnvelope);broken[0]^=1;
  await admin.query('ALTER TABLE verivaro_private.evidence_objects DISABLE TRIGGER evidence_object_immutable');
  try{
   await admin.query('UPDATE verivaro_private.evidence_objects SET envelope=$2 WHERE evidence_id=$1',[good.id,broken]);
   const corrupt=await graph.assessment(as('viewer'));assert.equal(corrupt.requirements[0].state,'integrity_failure');assert.equal(corrupt.summary.status,'blocked');
   assert.equal(buildRejectionPreflight(corrupt).issues[0].code,'INTEGRITY_FAILURE');
  }finally{
   try{await admin.query('UPDATE verivaro_private.evidence_objects SET envelope=$2 WHERE evidence_id=$1',[good.id,originalEnvelope]);}finally{await admin.query('ALTER TABLE verivaro_private.evidence_objects ENABLE TRIGGER evidence_object_immutable');}
  }
  assert.equal((await status()).status,'criteria_satisfied');
  const submissionId=randomUUID(),prepared=await graph.prepareSubmission(as('author',{submissionId}));
  assert.deepEqual(await graph.prepareSubmission(as('author',{submissionId})),prepared);
  const submission={submissionId,sha256:prepared.sha256};
  const inspect=await graph.inspectSubmission(as('reviewer',submission));assert.equal(inspect.sha256,prepared.sha256);
  assert.equal(JSON.parse(inspect.manifest).evidence[0].id,good.id);
  const impactScope={tenantId:JSON.parse(inspect.manifest).tenantId,projectId:JSON.parse(inspect.manifest).projectId,submissionId};
  const impact=async()=>compareSubmissionGraph(inspect,await graph.assessment(as('viewer')),impactScope);
  assert.equal((await impact()).changedCount,0);
  await assert.rejects(graph.inspectSubmission(as('outsider',submission)),ReleaseDenied);
  await assert.rejects(graph.authorizeSubmission(as('owner',submission)),ReleaseDenied);
  await assert.rejects(graph.reviewSubmission(as('author',{...submission,decision:'approved',reason:'No self review'})),ReleaseDenied);
  const decision={...submission,decision:'approved',reason:'Reviewed the exact manifest and evidence'};
  assert.equal(await graph.reviewSubmission(as('reviewer',decision)),true);
  assert.equal(await graph.reviewSubmission(as('reviewer',decision)),true);
  assert.equal(await graph.authorizeSubmission(as('owner',submission)),true);
  assert.equal(await graph.authorizeSubmission(as('owner',submission)),true);
  const approvedPackage=await graph.readSubmission(as('owner',submission));assert.equal(approvedPackage.manifest,inspect.manifest);
  await assert.rejects(graph.readSubmission(as('author',submission)),ReleaseDenied);
  assert.equal((await graph.listSubmissions(as('owner')))[0].canDownload,true);
  const second=link(bad);await graph.linkEvidence(as('author',second));
  const linkedImpact=await impact();assert.equal(linkedImpact.changedCount,1);assert.ok(linkedImpact.changes[0].reasons.includes('evidence_links_changed'));assert.equal(linkedImpact.currentStatus,'blocked');
  assert.equal((await status()).status,'blocked');
  await assert.rejects(graph.readSubmission(as('owner',submission)),ReleaseConflict);
  await graph.reviewLink(as('reviewer2',{linkId:second.linkId,decision:'fail',reason:'Conflicting identifier'}));
  const conflicting=await graph.assessment(as('owner'));assert.equal(conflicting.requirements[0].state,'conflict');assert.equal(conflicting.summary.blockers,1);assert.equal(buildRejectionPreflight(conflicting).issues[0].code,'CONFLICTING_EVIDENCE');
  const selfLink=link(self);await graph.linkEvidence(as('author',selfLink));
  await assert.rejects(graph.reviewLink(as('reviewer',{linkId:selfLink.linkId,decision:'pass',reason:'Own upload'})),ReleaseDenied);
  const next={...rule,versionId:randomUUID(),expectedRevision:1,criterion:'Updated register identifier must match.'};
  const competing=await Promise.allSettled([graph.writeRequirement(as('author',next)),graph.writeRequirement(as('author',{...next,versionId:randomUUID()}))]);
  assert.equal(competing.filter(x=>x.status==='fulfilled').length,1);assert.ok(competing.find(x=>x.status==='rejected').reason instanceof ReleaseConflict);
  const nextId=competing.find(x=>x.status==='fulfilled').value.versionId;
  await assert.rejects(graph.reviewRequirement(as('reviewer',approve)),ReleaseConflict);
  const changed=await graph.assessment(as('viewer'));assert.equal(changed.requirements[0].versionId,nextId);assert.deepEqual(changed.requirements[0].links,[]);assert.equal(changed.summary.verifiedRequired,0);
  const revisedImpact=await impact();assert.ok(revisedImpact.changes[0].reasons.includes('criterion_revision_changed'));assert.equal(revisedImpact.changes[0].currentState,'awaiting_rule_review');
  const uncertain={...rule,requirementId:randomUUID(),versionId:randomUUID(),applicability:'unknown'};
  await graph.writeRequirement(as('author',uncertain));await graph.reviewRequirement(as('reviewer',{...approve,versionId:uncertain.versionId}));
  const unknown=await graph.assessment(as('owner'));assert.equal(unknown.summary.blockers,2);assert.ok(unknown.requirements.some(x=>x.state==='unknown_applicability'));
  const c=await runtime.connect();try{await c.query('SET ROLE verivaro_runtime');await assert.rejects(c.query('SELECT * FROM verivaro_private.requirement_versions'),e=>e.code==='42501');}finally{c.release(true);}
  for(const table of ['requirement_versions','requirement_reviews','requirement_evidence_links','requirement_link_reviews'])await assert.rejects(admin.query('DELETE FROM verivaro_private.'+table+' WHERE false'),e=>e.code==='42501');
  await graph.archiveProject(as('owner',{requestId:randomUUID(),revision:0}));
  await assert.rejects(graph.writeRequirement(as('author',{...rule,requirementId:randomUUID(),versionId:randomUUID()})),ReleaseDenied);
  assert.equal((await status()).status,'blocked');
  console.log('persistent_requirement_graph_and_readiness_gate_passed');console.log('rejection_preflight_storage_integrity_gate_passed');console.log('immutable_submission_approval_and_staleness_gate_passed');
 }finally{await Promise.all([admin.end(),runtime.end(),ingestPool.end()]);}
});
