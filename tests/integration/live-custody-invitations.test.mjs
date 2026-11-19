import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {resolve} from 'node:path';
import {randomUUID,randomBytes,createHash,sign} from 'node:crypto';
import {local} from '../fixtures/provider-fixture.mjs';
import {createTenantAdministration,TenantDenied,TenantConflict} from '../../src/security/tenant-administration.mjs';
import {createEvidenceReleaseDatabase} from '../../src/security/evidence-release.mjs';
if(process.env.VV_LIVE_TEST!=='1'||process.env.PGDATABASE!=='verivaro_test'||!process.env.VV_TEST_DRIVER_DIR||!process.env.VV_TENANT_OPERATOR_PASSWORD)throw Error('disposable CI only');
const {Pool}=createRequire(resolve(process.env.VV_TEST_DRIVER_DIR,'package.json'))('pg');
const cfg={host:process.env.PGHOST,port:Number(process.env.PGPORT),database:process.env.PGDATABASE,max:4,connectionTimeoutMillis:3000,query_timeout:7000};
const verifier={publicKey:local.publicKey,issuer:'urn:verivaro:tenant-fixture',audience:'api'},enc=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
function token(actor,sid){const n=Math.floor(Date.now()/1000),b=enc({alg:'RS256',typ:'JWT'})+'.'+enc({iss:verifier.issuer,aud:verifier.audience,sub:actor,sid,iat:n,nbf:n,exp:n+300});return b+'.'+sign('RSA-SHA256',Buffer.from(b),local.privateKey).toString('base64url');}
test('archived custody succession and provider-bound invitations preserve archive and tenant isolation',{timeout:60000},async()=>{
 const admin=new Pool({...cfg,user:process.env.PGUSER,password:process.env.PGPASSWORD}),runtime=new Pool({...cfg,user:'vv_ci_runtime',password:process.env.VV_RUNTIME_PASSWORD}),operator=new Pool({...cfg,user:'vv_ci_tenant_operator',password:process.env.VV_TENANT_OPERATOR_PASSWORD});
 try{
  const trustedIssuer='https://custody-fixture.invalid',contextKey=(await admin.query('SELECT key_bytes FROM verivaro_private.context_key WHERE singleton')).rows[0].key_bytes;
  const op=createTenantAdministration(operator,{expectedLogin:'vv_ci_tenant_operator',mode:'operator',trustedIssuer}),ws=createTenantAdministration(runtime,{expectedLogin:'vv_ci_runtime',mode:'workspace',trustedIssuer,contextKey,verifier}),projects=createEvidenceReleaseDatabase(runtime,{expectedLogin:'vv_ci_runtime',mode:'workflow',contextKey,verifier});
  const tenantId=randomUUID(),owner=await op.bootstrap({tenantId,requestId:randomUUID(),name:'Custody fixture',verifiedSubject:'owner-'+randomUUID(),caseId:randomUUID()});
  async function session(a){const sid=randomUUID();await admin.query("INSERT INTO verivaro_private.identity_sessions(actor_id,session_id,expires_at) VALUES($1,$2,clock_timestamp()+interval '10 minutes')",[a,sid]);return token(a,sid);}
  const ownerToken=await session(owner),scope={tenantId,token:ownerToken};
  async function issue(){
   const verifiedSubject='invite-'+randomUUID(),requestId=randomUUID(),code=randomBytes(32).toString('base64url'),caseId=randomUUID();
   await ws.requestEnrollment({...scope,requestId,role:'reviewer',subjectDigest:createHash('sha256').update(verifiedSubject).digest('hex')});
   const args={tenantId,requestId,verifiedSubject,code,caseId};const actor=await op.issueInvitation(args);assert.equal(await op.issueInvitation(args),actor);
   assert.equal((await admin.query('SELECT count(*)::int n FROM verivaro.memberships WHERE tenant_id=$1 AND actor_id=$2',[tenantId,actor])).rows[0].n,0);
   return {...args,actor,token:await session(actor)};
  }
  const invited=await issue(),cancelled=await issue(),parallel=await issue();
  await assert.rejects(op.enroll(invited),TenantDenied);
  await assert.rejects(ws.redeemInvitation({...invited,token:ownerToken}),TenantDenied);
  await assert.rejects(ws.redeemInvitation({...invited,code:randomBytes(32).toString('base64url')}),TenantDenied);
  await assert.rejects(ws.redeemInvitation({...invited,tenantId:randomUUID()}),TenantDenied);
  await ws.cancelInvitation({...scope,requestId:cancelled.requestId});
  assert.equal(await ws.cancelInvitation({...scope,requestId:cancelled.requestId}),true);
  await assert.rejects(ws.redeemInvitation(cancelled),TenantDenied);
  const both=await Promise.all([ws.redeemInvitation(invited),ws.redeemInvitation(invited)]);assert.equal(both[0],both[1]);
  const otherGen=await ws.redeemInvitation(parallel);
  await ws.access({...scope,requestId:randomUUID(),targetId:parallel.actor,role:'viewer',generation:otherGen});
  await assert.rejects(ws.redeemInvitation(parallel),TenantDenied);
  const entries=await ws.enrollments(scope);assert.ok(entries.some(x=>x.id===cancelled.requestId&&x.state==='cancelled'));assert.ok(entries.some(x=>x.id===invited.requestId&&x.state==='enrolled'));
  const projectId=await projects.createProject({...scope,requestId:randomUUID(),name:'Historical project'});
  const secondId=await projects.createProject({...scope,requestId:randomUUID(),name:'Historical project with prior assignment'});
  await projects.changeAccess({...scope,projectId:secondId,requestId:randomUUID(),targetId:invited.actor,role:'reviewer',generation:null});
  for(const p of [projectId,secondId]){
   const report=await projects.report({...scope,projectId:p});await projects.archiveProject({...scope,projectId:p,requestId:randomUUID(),revision:report.project.revision});
  }
  const snapshot=(await admin.query('SELECT * FROM verivaro.projects WHERE tenant_id=$1 ORDER BY id',[tenantId])).rows;
  await assert.rejects(projects.changeAccess({...scope,projectId,requestId:randomUUID(),targetId:invited.actor,role:'reviewer',generation:null}),e=>e.message==='release denied');
  const requestId=randomUUID();await ws.requestTransfer({...scope,requestId,targetId:invited.actor,generation:both[0]});
  assert.equal(await ws.acceptTransfer({...invited,requestId}),true);
  const complete={tenantId,requestId,caseId:randomUUID()};assert.deepEqual(await Promise.all([op.completeTransfer(complete),op.completeTransfer(complete)]),[invited.actor,invited.actor]);
  assert.deepEqual((await admin.query('SELECT * FROM verivaro.projects WHERE tenant_id=$1 ORDER BY id',[tenantId])).rows,snapshot);
  const next={tenantId,token:invited.token};
  for(const p of [projectId,secondId]){
   assert.ok((await projects.report({...next,projectId:p})).project.archivedAt);
   await assert.rejects(projects.report({...scope,projectId:p}),e=>e.message==='release denied');
   await assert.rejects(admin.query('UPDATE verivaro.projects SET name=$1 WHERE id=$2',['blocked',p]),e=>e.code==='42501');
  }
  assert.equal((await admin.query('SELECT count(*)::int n FROM verivaro_private.archive_custody_handover WHERE request_id=$1',[requestId])).rows[0].n,2);
  await assert.rejects(admin.query('DELETE FROM verivaro_private.archive_custody_handover WHERE request_id=$1',[requestId]),e=>e.code==='42501');
  await assert.rejects(admin.query("UPDATE verivaro.project_members SET expires_at=clock_timestamp()+interval '1 day' WHERE tenant_id=$1 AND project_id=$2 AND actor_id=$3",[tenantId,projectId,invited.actor]),e=>e.code==='42501');
  console.log('archive_custody_and_invitation_gate_passed');
 }finally{await Promise.all([admin.end(),runtime.end(),operator.end()]);}
});
