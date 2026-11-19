import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {resolve} from 'node:path';
import {randomUUID,randomBytes,createHash} from 'node:crypto';
import {createServer} from 'node:http';
import {Readable} from 'node:stream';
import {createDistributedAdmission} from '../../src/security/distributed-admission.mjs';
import {createShareDownloadHandler} from '../../src/security/share-download.mjs';
import {encryptedReservation} from '../../src/security/spool-budget.mjs';
import {generateShareToken} from '../../src/security/share-token.mjs';
if(process.env.PGDATABASE!=='verivaro_test'||process.env.VV_LIVE_TEST!=='1'||!process.env.VV_TEST_DRIVER_DIR||!process.env.VV_ADMISSION_PASSWORD||!process.env.VV_ADMISSION_B_PASSWORD)throw Error('disposable CI required');
const {Pool}=createRequire(resolve(process.env.VV_TEST_DRIVER_DIR,'package.json'))('pg');
const config={host:process.env.PGHOST,port:Number(process.env.PGPORT),database:process.env.PGDATABASE,max:8,connectionTimeoutMillis:3000,idleTimeoutMillis:5000};
const signal=()=>new AbortController().signal;
const size=1024*1024,need=encryptedReservation(size);
test('real multi-login admission: quota, rate, crash reconciliation and HTTP preauthorization', {timeout:45000},async t=>{
 const admin=new Pool({...config,user:process.env.PGUSER,password:process.env.PGPASSWORD});
 const pa=new Pool({...config,user:'vv_ci_admission_a',password:process.env.VV_ADMISSION_PASSWORD});
 const pb=new Pool({...config,user:'vv_ci_admission_b',password:process.env.VV_ADMISSION_B_PASSWORD});
 const key=randomBytes(32),a=createDistributedAdmission(pa,{peerKey:key}),b=createDistributedAdmission(pb,{peerKey:key});
 async function configure(capacity,active,global,peer){
  await admin.query('DELETE FROM verivaro_private.download_leases');
  await admin.query('DELETE FROM verivaro_private.download_peer_buckets');
  await admin.query('UPDATE verivaro_private.download_admission_config SET capacity_bytes=$1,max_active=$2,global_limit=$3,peer_limit=$4,bucket=-1,count=0',[capacity,active,global,peer]);
 }
 async function count(){return (await admin.query('SELECT count(*)::int AS n FROM verivaro_private.download_leases')).rows[0].n;}
 try{
  await t.test('simultaneous independent pools cannot overcommit durable quota',async()=>{
   await configure(need*2,4,120,120);
   const leases=await Promise.all(Array.from({length:10},(_,i)=>(i%2?a:b).acquire('192.0.2.'+(i+1),size,signal())));
   assert.equal(leases.filter(Boolean).length,2);assert.equal(await count(),2);
   await Promise.all(leases.filter(Boolean).map(l=>l.release()));assert.equal(await count(),0);
  });
  await t.test('global and per-peer limits persist across replicas; mapped IPv4 normalized',async()=>{
   await configure(need*4,4,3,1);
   const first=await a.acquire('192.0.2.2',size,signal());assert.ok(first);await first.release();
   assert.equal(await b.acquire('::ffff:192.0.2.2',size,signal()),null);
   const second=await b.acquire('192.0.2.3',size,signal());assert.ok(second);await second.release();
   assert.equal(await a.acquire('192.0.2.4',size,signal()),null);
   assert.equal(await count(),0);
   assert.equal((await admin.query('SELECT count(*)::int AS n FROM verivaro_private.download_peer_buckets')).rows[0].n,2);
  });
  await t.test('lost worker connection does not silently free a reservation; separate reconciler required',async()=>{
   await configure(need,1,120,120);
   const lease=randomUUID();
   const worker=await pa.connect();
   try{
    await worker.query('SET ROLE verivaro_admission_service');
    assert.equal((await worker.query('SELECT verivaro_admission.acquire($1,$2,$3) AS ok',[lease,randomBytes(32),need])).rows[0].ok,true);
   }finally{worker.release(true);}
   assert.equal(await count(),1);
   const wrong=await pb.connect();
   try{
    await wrong.query('SET ROLE verivaro_admission_service');
    assert.equal((await wrong.query('SELECT verivaro_admission.release($1) AS ok',[lease])).rows[0].ok,false);
    await assert.rejects(wrong.query('SELECT verivaro_admission.reconcile($1,$2)',[lease,randomUUID()]),e=>e.code==='42501');
   }finally{wrong.release(true);}
   assert.equal(await b.acquire('192.0.2.9',size,signal()),null);
   const approval=randomUUID();
   const operator=await admin.connect();
   try{
    await operator.query('SET ROLE verivaro_admission_reconciler');
    assert.equal((await operator.query('SELECT verivaro_admission.reconcile($1,$2) AS ok',[lease,approval])).rows[0].ok,true);
    assert.equal((await operator.query('SELECT verivaro_admission.reconcile($1,$2) AS ok',[lease,approval])).rows[0].ok,false);
   }finally{operator.release(true);}
   assert.equal(await count(),0);
   assert.equal((await admin.query('SELECT count(*)::int AS n FROM verivaro_private.download_reconciliations WHERE approval_ref=$1',[approval])).rows[0].n,1);
   const fresh=await b.acquire('192.0.2.9',size,signal());assert.ok(fresh);await fresh.release();
  });
  await t.test('real HTTP rejects globally saturated attempts before resolver or storage',async()=>{
   await configure(need,1,120,120);
   const hold=await a.acquire('192.0.2.20',size,signal());assert.ok(hold);
   let calls=0,opens=0;
   const data=Buffer.from('approved'),item={artifact_id:randomUUID(),sha256:createHash('sha256').update(data).digest('hex')};
   const server=createServer(createShareDownloadHandler({distributedAdmission:b,resolveShare:async()=>{calls++;return item;},openArtifact:async()=>{opens++;return Readable.from([data]);},maxBytes:size}));
   await new Promise(r=>server.listen(0,'127.0.0.1',r));
   const request=()=>fetch('http://127.0.0.1:'+server.address().port+'/public/share/download',{method:'POST',headers:{Authorization:'Bearer '+generateShareToken().token}});
   try{
    const denied=await request();assert.equal(denied.status,429);await denied.text();assert.equal(calls,0);assert.equal(opens,0);
    await hold.release();
    const success=await request();assert.equal(success.status,200);assert.deepEqual(Buffer.from(await success.arrayBuffer()),data);
    // Response finish and durable release can race the receiving client.
    for(let i=0;i<100&&await count();i++)await new Promise(r=>setTimeout(r,10));
    assert.equal(await count(),0);assert.equal(calls,2);assert.equal(opens,1);
   }finally{await hold.release();await new Promise(r=>{server.closeAllConnections();server.close(r);});}
  });
  await assert.rejects(pa.query('SELECT * FROM verivaro_private.download_leases'),e=>e.code==='42501');
  await assert.rejects(pa.query('SELECT * FROM verivaro.projects'),e=>e.code==='42501');
 }finally{await pa.end();await pb.end();await admin.end();}
});
