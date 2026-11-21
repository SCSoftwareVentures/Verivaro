import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {resolve,join} from 'node:path';
import {loadServicePoolConfig} from '../../src/security/service-pool-config.mjs';
import {createMonitorDatabase} from '../../src/security/monitor-database.mjs';
import {retireServiceCredential} from '../../src/security/service-credential-retirement.mjs';
if(process.env.VV_LIVE_TEST!=='1'||process.env.PGDATABASE!=='verivaro_test'||!process.env.VV_TLS_FIXTURE||!process.env.VV_TEST_DRIVER_DIR)throw Error('disposable TLS CI only');
const {Pool}=createRequire(resolve(process.env.VV_TEST_DRIVER_DIR,'package.json'))('pg');
const dir=process.env.VV_TLS_FIXTURE,role='verivaro_monitor_reader';
const config={host:process.env.PGHOST,port:Number(process.env.PGPORT),database:process.env.PGDATABASE,max:2,connectionTimeoutMillis:3000};
const env=(login,which,extra={})=>({PGHOST:'localhost',PGPORT:process.env.PGPORT,PGUSER:login,PGDATABASE:'verivaro_test',VV_DB_PASSWORD_FILE:join(dir,which+'-password'),VV_DB_CA_FILE:join(dir,'ca.pem'),...extra});
test('live PostgreSQL TLS rejects wrong CA, hostname and plaintext; credential retirement terminates old sessions',{timeout:45000},async()=>{
 const admin=new Pool({...config,user:process.env.PGUSER,password:process.env.PGPASSWORD});
 const oldLogin='vv_ci_tls_old',newLogin='vv_ci_tls_new';
 const oldCfg=await loadServicePoolConfig({env:env(oldLogin,'old'),role}),newCfg=await loadServicePoolConfig({env:env(newLogin,'new'),role});
 const oldPool=new Pool(oldCfg),newPool=new Pool(newCfg);let held;
 oldPool.on('error',()=>{});newPool.on('error',()=>{});
 async function rejected(settings,pattern){const pool=new Pool(settings);try{await assert.rejects(pool.connect(),pattern);}finally{await pool.end();}}
 try{
  const valid=createMonitorDatabase(oldPool,{mode:'reader',expectedLogin:oldLogin});assert.ok((await valid.snapshot()).health);
  const tls=await oldPool.query('SELECT ssl,version,cipher FROM pg_stat_ssl WHERE pid=pg_backend_pid()');
  assert.equal(tls.rows[0].ssl,true);assert.match(tls.rows[0].version,/^TLSv1\.[23]$/);console.log('verified_postgresql_tls='+tls.rows[0].version);
  await rejected(await loadServicePoolConfig({env:env(oldLogin,'old',{VV_DB_CA_FILE:join(dir,'wrong.pem')}),role}),/certificate|self.signed|issuer/i);
  await rejected(await loadServicePoolConfig({env:env(oldLogin,'old',{PGHOST:'vv-wrong.test'}),role}),/hostname|altnames|certificate/i);
  await rejected({...oldCfg,ssl:false},/pg_hba|reject|encryption/i);
  const replacement=createMonitorDatabase(newPool,{mode:'reader',expectedLogin:newLogin});assert.ok((await replacement.snapshot()).health);
  // Incident regression: the existing credential MUST remain usable while an
  // unexpected elevated replacement is rejected without any retirement DDL.
  await admin.query('GRANT pg_read_all_data TO vv_ci_tls_new');
  try{
   const c=await admin.connect();
   try{await assert.rejects(retireServiceCredential(c,{role,oldLogin,newLogin,confirm:oldLogin}),/credential retirement failed/);}
   finally{c.release(true);}
   assert.equal((await oldPool.query('SELECT 1 AS ok')).rows[0].ok,1);
  }finally{await admin.query('REVOKE pg_read_all_data FROM vv_ci_tls_new');}
  await admin.query('GRANT verivaro_monitor_reader TO vv_ci_tls_new WITH ADMIN OPTION');
  try{
   const c=await admin.connect();
   try{await assert.rejects(retireServiceCredential(c,{role,oldLogin,newLogin,confirm:oldLogin}),/credential retirement failed/);}
   finally{c.release(true);}
   assert.equal((await oldPool.query('SELECT 1 AS ok')).rows[0].ok,1);
  }finally{await admin.query('REVOKE ADMIN OPTION FOR verivaro_monitor_reader FROM vv_ci_tls_new');}
  held=await oldPool.connect();held.on('error',()=>{});
  await held.query('SET ROLE verivaro_monitor_reader');
  const pid=held.processID;
  const c=await admin.connect();
  try{
   await assert.rejects(retireServiceCredential(c,{role,oldLogin,newLogin,confirm:'wrong'}));
   const retired=await retireServiceCredential(c,{role,oldLogin,newLogin,confirm:oldLogin});assert.deepEqual(retired,{retired:true,remainingSessions:0});
   assert.equal((await c.query('SELECT count(*)::int AS n FROM pg_stat_activity WHERE pid=$1',[pid])).rows[0].n,0);
  }finally{c.release(true);}
  await assert.rejects(held.query('SELECT 1'));
  await rejected(oldCfg,/not permitted|authentication|password|login/i);
  assert.ok((await replacement.snapshot()).health);
 }finally{held?.release(true);await oldPool.end();await newPool.end();await admin.end();}
});
