import {assertServiceLogin,validateServiceIdentity} from './service-login.mjs';
import {signDatabaseContext} from './sign-database-context.mjs';
import {createHash} from 'node:crypto';
export class TenantDenied extends Error{}
export class TenantConflict extends Error{}
const subject=x=>{if(typeof x!=='string'||x.length<1||x.length>255||/[^\x21-\x7e]/.test(x))throw Error('invalid verified subject');return createHash('sha256').update(x).digest();};
const issuer=x=>{const u=new URL(x);if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash||Buffer.byteLength(x)>512||!/^[\x21-\x7e]+$/.test(x))throw Error('invalid trusted issuer');return x;};
export function createTenantAdministration(pool,{expectedLogin,mode,verifier,contextKey,trustedIssuer}){
 const role=mode==='operator'?'verivaro_tenant_operator':mode==='workspace'?'verivaro_runtime':null;
 validateServiceIdentity(role,expectedLogin);if(typeof pool?.connect!=='function')throw Error('invalid tenant pool');
 const pinned=issuer(trustedIssuer);
 if(mode==='workspace'&&(!Buffer.isBuffer(contextKey)||contextKey.length!==32||!verifier))throw Error('invalid tenant context');
 const key=contextKey?Buffer.from(contextKey):null;
 async function run(t,token,sql,values){
  const c=await pool.connect();let tx=false,clean=false;
  try{
   await c.query('DISCARD ALL');await assertServiceLogin(c,role,expectedLogin);await c.query('SET ROLE '+role);
   await c.query('BEGIN ISOLATION LEVEL READ COMMITTED');tx=true;
   await c.query("SET LOCAL statement_timeout='5s'");await c.query("SET LOCAL lock_timeout='2s'");await c.query("SET LOCAL idle_in_transaction_session_timeout='10s'");
   if(mode==='workspace'){
    const challenge=(await c.query('SELECT pg_backend_pid() AS pid, pg_current_xact_id()::text AS xid')).rows[0];
    await c.query("SELECT set_config('verivaro.signed_context',$1,true)",[signDatabaseContext({token,tenantId:t,challenge},{verifier,key})]);
   }
   const r=await c.query(sql,values);if(r.rows.length!==1)throw Error('invalid tenant result');
   await c.query('COMMIT');tx=false;await c.query('DISCARD ALL');clean=true;return r.rows[0].result;
  }catch(e){if(tx&&e.message!=='Query read timeout')try{await c.query('ROLLBACK');}catch{}if(e.code==='42501')throw new TenantDenied('tenant administration denied');if(e.code==='23505')throw new TenantConflict('tenant administration conflict');throw Error('tenant administration unavailable');}
  finally{c.release(clean?undefined:new Error('discard tenant administration lease'));}
 }
 if(mode==='operator')return Object.freeze({
  bootstrap:({tenantId,requestId,name,verifiedSubject,caseId})=>run(tenantId,null,'SELECT verivaro_tenant_admin.bootstrap($1,$2,$3,$4,$5,$6) AS result',[tenantId,requestId,name,pinned,subject(verifiedSubject),caseId]),
  enroll:({tenantId,requestId,verifiedSubject,caseId})=>run(tenantId,null,'SELECT verivaro_tenant_admin.approve_enrollment($1,$2,$3,$4,$5) AS result',[tenantId,requestId,pinned,subject(verifiedSubject),caseId]),
  completeTransfer:({tenantId,requestId,caseId})=>run(tenantId,null,'SELECT verivaro_tenant_admin.complete_transfer($1,$2,$3) AS result',[tenantId,requestId,caseId])
 });
 return Object.freeze({
  requestEnrollment:({tenantId,token,requestId,subjectDigest,role})=>{if(typeof subjectDigest!=='string'||! /^[a-f0-9]{64}$/.test(subjectDigest))throw Error('invalid enrollment digest');return run(tenantId,token,'SELECT verivaro_tenant_admin.request_enrollment($1,$2,$3,$4,$5) AS result',[tenantId,requestId,pinned,Buffer.from(subjectDigest,'hex'),role]);},
  enrollments:({tenantId,token})=>run(tenantId,token,'SELECT verivaro_tenant_admin.enrollment_requests($1) AS result',[tenantId]),
  directory:({tenantId,token})=>run(tenantId,token,'SELECT verivaro_tenant_admin.directory($1) AS result',[tenantId]),
  access:({tenantId,token,requestId,targetId,role,generation})=>run(tenantId,token,'SELECT verivaro_tenant_admin.change_access($1,$2,$3,$4,$5) AS result',[tenantId,requestId,targetId,role,generation]),
  requestTransfer:({tenantId,token,requestId,targetId,generation})=>run(tenantId,token,'SELECT verivaro_tenant_admin.request_transfer($1,$2,$3,$4) AS result',[tenantId,requestId,targetId,generation]),
  acceptTransfer:({tenantId,token,requestId})=>run(tenantId,token,'SELECT verivaro_tenant_admin.accept_transfer($1,$2) AS result',[tenantId,requestId]),
  transfers:({tenantId,token})=>run(tenantId,token,'SELECT verivaro_tenant_admin.pending_transfers($1) AS result',[tenantId])
 });
}
