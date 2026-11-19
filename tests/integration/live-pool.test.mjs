// Live integration: disposable synthetic PostgreSQL only; no production connection.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {generateKeyPairSync,sign,randomUUID} from 'node:crypto';
import {resolve} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {signDatabaseContext} from '../../src/security/sign-database-context.mjs';
import {createScopedDatabase} from '../../src/security/scoped-database.mjs';

if(process.env.PGDATABASE!=='verivaro_test' || process.env.VV_LIVE_TEST!=='1' ||
 !process.env.VV_TEST_DRIVER_DIR || !process.env.VV_RUNTIME_PASSWORD) throw Error('disposable CI configuration required');
const require=createRequire(resolve(process.env.VV_TEST_DRIVER_DIR,'package.json'));
const {Pool}=require('pg');
const a={tenant:'11111111-1111-4111-8111-111111111111',actor:'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',project:'33333333-3333-4333-8333-333333333333'};
const b={tenant:'22222222-2222-4222-8222-222222222222',actor:'ffffffff-ffff-4fff-8fff-ffffffffffff',project:'44444444-4444-4444-8444-444444444444'};
const hidden='88888888-8888-4888-8888-888888888888';
const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
const config={host:process.env.PGHOST,port:Number(process.env.PGPORT),database:process.env.PGDATABASE,connectionTimeoutMillis:3000,idleTimeoutMillis:5000,max:1};
a.sid=randomUUID(); b.sid=randomUUID();
const token=(actor,sid)=>{
 const now=Math.floor(Date.now()/1000);
 const enc=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
 const payload=enc({alg:'RS256',typ:'JWT'})+'.'+enc({iss:'ci',aud:'api',sub:actor,sid,iat:now-1,nbf:now-1,exp:now+120});
 return payload+'.'+sign('RSA-SHA256',Buffer.from(payload),privateKey).toString('base64url');
};
const input=(f,operation='listProjects',args={})=>({token:token(f.actor,f.sid),tenantId:f.tenant,operation,args});

test('real PostgreSQL pool: reused lease, tenant isolation, revocation, cancellation', {timeout:45000},async t=>{
 const admin=new Pool({...config,user:process.env.PGUSER,password:process.env.PGPASSWORD,max:2});
 const runtime=new Pool({...config,user:'verivaro_runtime',password:process.env.VV_RUNTIME_PASSWORD});
 const pids=[], releases=[];
 let businessStarted;
 // Transparent observation around the actual driver; no mock result.
 const observed={async connect(){
  const client=await runtime.connect();
  pids.push(client.processID);
  return {
   async query(sql,values){
    const pending=client.query(sql,values);
    if(sql.startsWith('SELECT id,') && businessStarted) businessStarted(client.processID);
    return pending;
   },
   release(error){releases.push(Boolean(error));client.release(error);}
  };
 }};
 try {
  const key=(await admin.query('SELECT key_bytes FROM verivaro_private.context_key WHERE singleton')).rows[0].key_bytes;
  for(const f of [a,b]){
   await admin.query("INSERT INTO verivaro_private.identity_sessions(session_id,actor_id,expires_at) VALUES($1,$2,clock_timestamp()+interval '1 hour')",[f.sid,f.actor]);
   await admin.query("INSERT INTO verivaro.memberships(tenant_id,actor_id,role) VALUES($1,$2,'viewer')",[f.tenant,f.actor]);
   await admin.query("INSERT INTO verivaro.project_members(tenant_id,project_id,actor_id,role) VALUES($1,$2,$3,'viewer')",[f.tenant,f.project,f.actor]);
  }
  const db=createScopedDatabase(observed,{key,verifier:{publicKey,issuer:'ci',audience:'api'}});
  await t.test('same physical connection reused safely across tenants',async()=>{
   assert.deepEqual((await db.execute(input(a))).map(r=>r.id),[a.project]);
   assert.deepEqual((await db.execute(input(b))).map(r=>r.id),[b.project]);
   assert.equal(pids[0],pids[1]);
   assert.deepEqual(releases.slice(0,2),[false,false]);
   const lease=await runtime.connect();
   try{
    assert.equal((await lease.query('SELECT count(*)::int AS n FROM verivaro.projects')).rows[0].n,0);
    await lease.query("SELECT set_config('verivaro.tenant_id',$1,false)",[b.tenant]);
    await lease.query("SELECT set_config('verivaro.actor_id',$1,false)",[b.actor]);
   }finally{lease.release();}
   assert.deepEqual((await db.execute(input(a))).map(r=>r.id),[a.project]);
   assert.deepEqual(await db.execute(input(a,'getProject',{projectId:hidden})),[]);
   assert.deepEqual(await db.execute(input(a,'listEvidence',{projectId:hidden})),[]);
   assert.deepEqual(await db.execute(input(a,'getProject',{projectId:b.project})),[]);
  });
  await t.test('forged tenant and invalid token fail and physically discard leases',async()=>{
   await assert.rejects(db.execute({...input(a),tenantId:b.tenant}),/failed/);
   const rejectedPid=pids.at(-1);
   assert.equal(releases.at(-1),true);
   assert.deepEqual((await db.execute(input(b))).map(r=>r.id),[b.project]);
   assert.notEqual(pids.at(-1),rejectedPid);
   await assert.rejects(db.execute({...input(a),token:'invalid'}),/failed/);
   assert.equal(releases.at(-1),true);
  });
  await t.test('actual server-side cancellation discards aborted transaction connection',async()=>{
   const locker=await admin.connect();
   let pending;
   try{
    await locker.query('BEGIN');
    await locker.query('LOCK TABLE verivaro.projects IN ACCESS EXCLUSIVE MODE');
    let ready;
    const started=new Promise(r=>{ready=r;});
    businessStarted=ready;
    pending=db.execute(input(a));
    // Attach handler immediately to avoid unhandled rejection on unexpected early failure.
    const observedError=pending.then(()=>null,e=>e);
    const pid=await Promise.race([started,observedError.then(()=>{throw Error('operation ended before business query');}),delay(2500).then(()=>{throw Error('business query did not start');})]);
    let waiting=false;
    for(let i=0;i<30;i++){
     const state=await admin.query("SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1",[pid]);
     if(state.rows[0]?.wait_event_type==='Lock'){waiting=true;break;}
     await delay(40);
    }
    assert.equal(waiting,true,'query must be blocked before cancellation');
    const cancelled=await admin.query('SELECT pg_cancel_backend($1) AS cancelled',[pid]);
    assert.equal(cancelled.rows[0].cancelled,true);
    assert.match((await observedError)?.message??'',/scoped database operation failed/);
    assert.equal(releases.at(-1),true);
    assert.equal(pids.at(-1),pid);
   }finally{
    businessStarted=undefined;
    await locker.query('ROLLBACK');
    locker.release();
    if(pending)await pending.catch(()=>{});
   }
   const previous=pids.at(-1);
   assert.deepEqual((await db.execute(input(b))).map(r=>r.id),[b.project]);
   assert.notEqual(pids.at(-1),previous);
  });
  await t.test('session isolation, unregistered session denial and recovery with new identifier',async()=>{
   const alternate={...a,sid:randomUUID()};
   await admin.query("INSERT INTO verivaro_private.identity_sessions(session_id,actor_id,expires_at) VALUES($1,$2,clock_timestamp()+interval '1 hour')",[alternate.sid,a.actor]);
   assert.deepEqual((await db.execute(input(alternate))).map(r=>r.id),[a.project]);
   await assert.rejects(db.execute(input({...a,sid:randomUUID()})),/failed/);
   await assert.rejects(db.execute(input({...a,sid:b.sid})),/failed/);
   // Verify revocation against the same still-open runtime transaction.
   const live=await runtime.connect();
   try{
    await live.query('BEGIN ISOLATION LEVEL READ COMMITTED');
    const challenge=(await live.query('SELECT pg_backend_pid() AS pid, pg_current_xact_id()::text AS xid')).rows[0];
    const ctx=signDatabaseContext({token:token(a.actor,a.sid),tenantId:a.tenant,challenge},{key,verifier:{publicKey,issuer:'ci',audience:'api'}});
    await live.query("SELECT set_config('verivaro.signed_context',$1,true)",[ctx]);
    assert.equal((await live.query('SELECT count(*)::int AS n FROM verivaro.projects')).rows[0].n,1);
    await admin.query('UPDATE verivaro_private.identity_sessions SET revoked_at=clock_timestamp() WHERE session_id=$1',[a.sid]);
    assert.equal((await live.query('SELECT count(*)::int AS n FROM verivaro.projects')).rows[0].n,0);
    await live.query('ROLLBACK');
   }finally{live.release(true);}
   await assert.rejects(db.execute(input(a)),/failed/);
   assert.deepEqual((await db.execute(input(alternate))).map(r=>r.id),[a.project]);
   await assert.rejects(admin.query('UPDATE verivaro_private.identity_sessions SET revoked_at=NULL WHERE session_id=$1',[a.sid]),e=>e.code==='42501');
   await assert.rejects(admin.query('DELETE FROM verivaro_private.identity_sessions WHERE session_id=$1',[a.sid]),e=>e.code==='42501');
   const expired={...a,sid:randomUUID()};
   await admin.query("INSERT INTO verivaro_private.identity_sessions(session_id,actor_id,created_at,expires_at) VALUES($1,$2,clock_timestamp()-interval '2 hours',clock_timestamp()-interval '1 hour')",[expired.sid,a.actor]);
   await assert.rejects(db.execute(input(expired)),/failed/);
   a.sid=alternate.sid;
  });
  await t.test('revoked project and globally disabled identity are immediately denied on next request',async()=>{
   await admin.query('UPDATE verivaro.project_members SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND actor_id=$2',[a.tenant,a.actor]);
   assert.deepEqual(await db.execute(input(a)),[]);
   await admin.query('INSERT INTO verivaro_private.disabled_actors(actor_id) VALUES($1)',[b.actor]);
   await assert.rejects(db.execute(input(b)),/failed/);
   assert.equal(releases.at(-1),true);
  });
 }finally{await runtime.end();await admin.end();}
});
