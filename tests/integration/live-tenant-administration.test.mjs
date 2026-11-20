import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {resolve} from 'node:path';
import {randomUUID,createHash,sign} from 'node:crypto';
import {local} from '../fixtures/provider-fixture.mjs';
import {createTenantAdministration,TenantDenied,TenantConflict} from '../../src/security/tenant-administration.mjs';
import {createEvidenceReleaseDatabase} from '../../src/security/evidence-release.mjs';
if(process.env.VV_LIVE_TEST!=='1'||process.env.PGDATABASE!=='verivaro_test'||!process.env.VV_TEST_DRIVER_DIR||!process.env.VV_TENANT_OPERATOR_PASSWORD)throw Error('disposable CI only');
const {Pool}=createRequire(resolve(process.env.VV_TEST_DRIVER_DIR,'package.json'))('pg');
const cfg={host:process.env.PGHOST,port:Number(process.env.PGPORT),database:process.env.PGDATABASE,max:4,connectionTimeoutMillis:3000,query_timeout:7000};
const verifier={publicKey:local.publicKey,issuer:'urn:verivaro:tenant-fixture',audience:'api'},enc=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
function token(actor,sid){const n=Math.floor(Date.now()/1000),b=enc({alg:'RS256',typ:'JWT'})+'.'+enc({iss:verifier.issuer,aud:verifier.audience,sub:actor,sid,iat:n,nbf:n,exp:n+300});return b+'.'+sign('RSA-SHA256',Buffer.from(b),local.privateKey).toString('base64url');}
test('tenant bootstrap, independently approved enrollment, membership revocation and accepted ownership succession',{timeout:60000},async()=>{
 const admin=new Pool({...cfg,user:process.env.PGUSER,password:process.env.PGPASSWORD}),runtime=new Pool({...cfg,user:'vv_ci_runtime',password:process.env.VV_RUNTIME_PASSWORD}),operator=new Pool({...cfg,user:'vv_ci_tenant_operator',password:process.env.VV_TENANT_OPERATOR_PASSWORD});
 try{
  const trustedIssuer='https://tenant-fixture.invalid',contextKey=(await admin.query('SELECT key_bytes FROM verivaro_private.context_key WHERE singleton')).rows[0].key_bytes;
  const op=createTenantAdministration(operator,{expectedLogin:'vv_ci_tenant_operator',mode:'operator',trustedIssuer}),ws=createTenantAdministration(runtime,{expectedLogin:'vv_ci_runtime',mode:'workspace',trustedIssuer,contextKey,verifier}),projects=createEvidenceReleaseDatabase(runtime,{expectedLogin:'vv_ci_runtime',mode:'workflow',contextKey,verifier});
  const tenantId=randomUUID(),boot={tenantId,requestId:randomUUID(),name:'Tenant admin fixture',verifiedSubject:'owner-'+randomUUID(),caseId:randomUUID()};
  const owner=await op.bootstrap(boot);assert.equal(await op.bootstrap(boot),owner);
  await assert.rejects(op.bootstrap({...boot,name:'different'}),TenantConflict);
  async function session(a){const sid=randomUUID();await admin.query("INSERT INTO verivaro_private.identity_sessions(actor_id,session_id,expires_at) VALUES($1,$2,clock_timestamp()+interval '5 minutes')",[a,sid]);return token(a,sid);}
  const ownerToken=await session(owner),scope={tenantId,token:ownerToken};
  async function enroll(role){
   const verifiedSubject='person-'+randomUUID(),requestId=randomUUID(),args={...scope,requestId,role,subjectDigest:createHash('sha256').update(verifiedSubject).digest('hex')};
   assert.equal(await ws.requestEnrollment(args),requestId);assert.equal(await ws.requestEnrollment(args),requestId);
   const approve={tenantId,requestId,verifiedSubject,caseId:randomUUID()};
   await assert.rejects(op.enroll({...approve,verifiedSubject:'wrong'}),TenantDenied);
   const actor=await op.enroll(approve);assert.equal(await op.enroll(approve),actor);
   return {actor,token:await session(actor)};
  }
  await assert.rejects(ws.requestEnrollment({...scope,requestId:randomUUID(),role:'owner',subjectDigest:'a'.repeat(64)}),TenantDenied);
  const successor=await enroll('reviewer'),other=await enroll('contributor'),directory=await ws.directory(scope);
  assert.equal(directory.length,3);assert.ok(directory.every(x=>x.bound));
  await assert.rejects(ws.directory({tenantId,token:other.token}),TenantDenied);
  const projectId=await projects.createProject({...scope,requestId:randomUUID(),name:'Handover project'});
  const otherGen=directory.find(x=>x.actorId===other.actor).generation;
  await projects.changeAccess({...scope,projectId,requestId:randomUUID(),targetId:other.actor,role:'contributor',generation:null});
  const change={...scope,requestId:randomUUID(),targetId:other.actor,role:'viewer',generation:otherGen};
  const newGen=await ws.access(change);assert.equal(await ws.access(change),newGen);
  assert.ok((await admin.query('SELECT revoked_at FROM verivaro.project_members WHERE tenant_id=$1 AND project_id=$2 AND actor_id=$3',[tenantId,projectId,other.actor])).rows[0].revoked_at);
  await assert.rejects(ws.access({...change,requestId:randomUUID()}),TenantConflict);
  await assert.rejects(ws.access({...change,targetId:owner,requestId:randomUUID()}),TenantDenied);
  const requestId=randomUUID(),transfer={...scope,requestId,targetId:successor.actor,generation:directory.find(x=>x.actorId===successor.actor).generation};
  await ws.requestTransfer(transfer);
  const complete={tenantId,requestId,caseId:randomUUID()};
  await assert.rejects(op.completeTransfer(complete),TenantDenied);
  await assert.rejects(ws.acceptTransfer({...scope,requestId}),TenantDenied);
  await assert.rejects(ws.acceptTransfer({tenantId,requestId,token:other.token}),TenantDenied);
  assert.equal(await ws.acceptTransfer({tenantId,requestId,token:successor.token}),true);
  assert.equal(await ws.acceptTransfer({tenantId,requestId,token:successor.token}),true);
  const parallel=await Promise.all([op.completeTransfer(complete),op.completeTransfer(complete)]);assert.deepEqual(parallel,[successor.actor,successor.actor]);
  await assert.rejects(ws.directory(scope),TenantDenied);
  const nextScope={tenantId,token:successor.token};
  assert.ok((await ws.directory(nextScope)).some(x=>x.actorId===successor.actor&&x.role==='owner'));
  assert.ok((await projects.directory({...nextScope,projectId})).some(x=>x.actorId===other.actor&&!x.active));
  assert.equal((await admin.query("SELECT count(*)::int n FROM verivaro.memberships WHERE tenant_id=$1 AND role='owner' AND revoked_at IS NULL",[tenantId])).rows[0].n,1);
  assert.equal((await admin.query("SELECT count(*)::int n FROM verivaro_private.tenant_admin_receipts WHERE request_id=$1",[requestId])).rows[0].n,1);
  await assert.rejects(admin.query('DELETE FROM verivaro_private.tenant_admin_receipts WHERE request_id=$1',[requestId]),e=>e.code==='42501');
  const c=await runtime.connect();try{await c.query('SET ROLE verivaro_runtime');await assert.rejects(c.query('SELECT verivaro_tenant_admin.complete_transfer($1,$2,$3)',[tenantId,requestId,complete.caseId]),e=>e.code==='42501');}finally{c.release(true);}
  const p=await operator.connect();try{await p.query('SET ROLE verivaro_tenant_operator');await assert.rejects(p.query('SELECT * FROM verivaro_private.provider_bindings'),e=>e.code==='42501');await assert.rejects(p.query('SELECT verivaro_tenant_admin.directory($1)',[tenantId]),e=>e.code==='42501');}finally{p.release(true);}
  console.log('tenant_enrollment_ownership_succession_gate_passed');
 }finally{await Promise.all([admin.end(),runtime.end(),operator.end()]);}
});
