import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {resolve} from 'node:path';
import {randomBytes} from 'node:crypto';
import {assertServiceLogin} from '../../src/security/service-login.mjs';
import {createDistributedAdmission} from '../../src/security/distributed-admission.mjs';
if(process.env.VV_LIVE_TEST!=='1'||process.env.PGDATABASE!=='verivaro_test'||!process.env.VV_TEST_DRIVER_DIR||!process.env.VV_ADMISSION_PASSWORD)throw Error('disposable CI only');
const {Pool}=createRequire(resolve(process.env.VV_TEST_DRIVER_DIR,'package.json'))('pg');
const cfg={host:process.env.PGHOST,port:Number(process.env.PGPORT),database:process.env.PGDATABASE,max:1,connectionTimeoutMillis:3000};
test('live dedicated service identity rejects indirect, direct and administrative privilege drift',{timeout:30000},async()=>{
 const admin=new Pool({...cfg,user:process.env.PGUSER,password:process.env.PGPASSWORD}),pool=new Pool({...cfg,user:'vv_ci_admission_a',password:process.env.VV_ADMISSION_PASSWORD});
 const role='verivaro_admission_service',login='vv_ci_admission_a',signal=new AbortController().signal;
 const adapter=createDistributedAdmission(pool,{peerKey:randomBytes(32),expectedLogin:login});
 async function check(expected=login,target=role){const c=await pool.connect();try{await c.query('DISCARD ALL');await assertServiceLogin(c,target,expected);}finally{c.release(true);}}
 async function rejectAfter(grant,revoke){
  await admin.query(grant);
  try{await assert.rejects(check());await assert.rejects(adapter.acquire('192.0.2.1',1024,signal),/admission operation failed/);}
  finally{await admin.query(revoke);}
  await check();
 }
 try{
  await check();
  await assert.rejects(check('vv_ci_admission_b'));await assert.rejects(check(login,'verivaro_alert_sender'));
  await rejectAfter('GRANT pg_read_all_data TO vv_ci_admission_a','REVOKE pg_read_all_data FROM vv_ci_admission_a');
  await rejectAfter('GRANT verivaro_monitor_reader TO vv_ci_admission_a','REVOKE verivaro_monitor_reader FROM vv_ci_admission_a');
  await rejectAfter('GRANT USAGE ON SCHEMA verivaro_private TO vv_ci_admission_a','REVOKE USAGE ON SCHEMA verivaro_private FROM vv_ci_admission_a');
  await rejectAfter('GRANT SELECT (key_bytes) ON verivaro_private.context_key TO vv_ci_admission_a','REVOKE SELECT (key_bytes) ON verivaro_private.context_key FROM vv_ci_admission_a');
  await rejectAfter('GRANT CREATE ON SCHEMA public TO vv_ci_admission_a','REVOKE CREATE ON SCHEMA public FROM vv_ci_admission_a');
  await rejectAfter('GRANT verivaro_admission_service TO vv_ci_admission_a WITH ADMIN OPTION','REVOKE ADMIN OPTION FOR verivaro_admission_service FROM vv_ci_admission_a');
  // A group role made LOGIN is specifically forbidden for a pinned deployment.
  await rejectAfter('ALTER ROLE verivaro_admission_service LOGIN','ALTER ROLE verivaro_admission_service NOLOGIN');
  await check();
  const c=await pool.connect();try{await c.query('DISCARD ALL');await assertServiceLogin(c,role,login);await c.query('SET ROLE verivaro_admission_service');assert.equal((await c.query('SELECT current_user AS role')).rows[0].role,role);}finally{c.release(true);}
 }finally{await pool.end();await admin.end();}
});
