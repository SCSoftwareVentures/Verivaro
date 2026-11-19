import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {mkdtemp,readdir,rm,readlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer,request as httpRequest} from 'node:http';
import {Readable} from 'node:stream';
import {setTimeout as delay} from 'node:timers/promises';
import {createSpoolBudget,encryptedReservation} from '../../src/security/spool-budget.mjs';
import {createShareDownloadHandler} from '../../src/security/share-download.mjs';
import {generateShareToken} from '../../src/security/share-token.mjs';
const MiB=1024*1024;
const signal=()=>new AbortController().signal;
const enough=async()=>({bavail:2n**30n,bsize:4096n});
async function root(t){const p=await mkdtemp(join(tmpdir(),'vv-budget-'));t.after(()=>rm(p,{recursive:true,force:true}));return p;}
async function server(t,settings){
 const s=createServer(createShareDownloadHandler(settings));
 await new Promise((r,j)=>{s.once('error',j);s.listen(0,'127.0.0.1',r);});
 t.after(()=>new Promise(r=>{s.closeAllConnections();s.close(r);}));
 const url='http://127.0.0.1:'+s.address().port+'/public/share/download',headers={Authorization:'Bearer '+generateShareToken().token};
 return {url,headers,get:()=>fetch(url,{method:'POST',headers})};
}
async function until(fn){
 for(let i=0;i<200;i++){if(await fn())return;await delay(10);}
 throw Error('condition not reached');
}
test('reservation includes encryption and metadata overhead; simultaneous admissions never overcommit',async t=>{
 const directory=await root(t),size=64*MiB,need=encryptedReservation(size);
 assert.ok(need>size);
 const budget=createSpoolBudget({directory,capacityBytes:need*2,inspect:enough});
 const leases=await Promise.all(Array.from({length:8},()=>budget.reserve(size,signal())));
 assert.equal(leases.filter(Boolean).length,2);
 assert.equal(budget.snapshot().reservedBytes,need*2);
 for(const l of leases){l?.release();l?.release();}
 assert.equal(budget.snapshot().active,0);assert.equal(budget.snapshot().reservedBytes,0);
});
test('low free space, statfs failure and abort release reservations',async t=>{
 const directory=await root(t);
 for(const inspect of [async()=>({bavail:1n,bsize:4096n}),async()=>{throw Error('statfs failure');}]){
  const budget=createSpoolBudget({directory,inspect});
  const result=await budget.reserve(MiB,signal()).catch(()=>null);
  assert.equal(result,null);assert.equal(budget.snapshot().reservedBytes,0);
 }
 const ctrl=new AbortController(),budget=createSpoolBudget({directory,inspect:async()=>{ctrl.abort();return enough();}});
 await assert.rejects(budget.reserve(MiB,ctrl.signal));assert.equal(budget.snapshot().active,0);
});
test('real HTTP: four simultaneous 64 MiB encrypted transfers, fifth denied, all resources reclaimed',{timeout:45000},async t=>{
 const directory=await root(t),size=64*MiB,chunk=Buffer.alloc(256*1024,0x3c),count=size/chunk.length;
 const hash=createHash('sha256');for(let i=0;i<count;i++)hash.update(chunk);
 const item={artifact_id:randomUUID(),sha256:hash.digest('hex')};
 const budget=createSpoolBudget({directory,capacityBytes:encryptedReservation(size)*4});
 let entered=0,release;
 const barrier=new Promise(r=>{release=r;});
 const config={resolveShare:async()=>item,openArtifact:async()=>Readable.from((async function*(){entered++;await barrier;for(let i=0;i<count;i++)yield chunk;})()),spoolDirectory:directory,spoolBudget:budget,maxBytes:size,maxConcurrent:8,timeoutMs:30000};
 const a=await server(t,config),b=await server(t,config);
 const start=performance.now(),pending=[a.get(),b.get(),a.get(),b.get()];
 try{
  await until(()=>entered===4);
  assert.equal(budget.snapshot().active,4);
  const excess=await a.get();assert.equal(excess.status,429);await excess.text();
 }finally{release();}
 await Promise.all(pending.map(async p=>{
  const res=await p;assert.equal(res.status,200);
  let total=0;const verify=createHash('sha256');
  for await(const bytes of res.body){total+=bytes.length;verify.update(bytes);}
  assert.equal(total,size);assert.equal(verify.digest('hex'),item.sha256);
 }));
 await until(()=>budget.snapshot().active===0);
 assert.equal(budget.snapshot().reservedBytes,0);assert.deepEqual(await readdir(directory),[]);
 const descriptors=await Promise.all((await readdir('/proc/self/fd')).map(id=>readlink('/proc/self/fd/'+id).catch(()=>'')));
 assert.ok(!descriptors.some(path=>path.startsWith(directory+'/')));
 console.log('encrypted_parallel_4x64MiB_ms='+Math.round(performance.now()-start)+' peak_reserved_bytes='+budget.snapshot().peakReservedBytes+' peak_rss_KiB='+process.resourceUsage().maxRSS);
});
test('disconnect during staging and denied final authorization return budget',{timeout:10000},async t=>{
 const directory=await root(t),chunk=Buffer.alloc(256*1024,0x31),size=MiB;
 const budget=createSpoolBudget({directory,capacityBytes:encryptedReservation(size)});
 const item={artifact_id:randomUUID(),sha256:createHash('sha256').update(chunk).digest('hex')};
 let entered=0;
 const a=await server(t,{resolveShare:async()=>item,openArtifact:async(id,{signal})=>Readable.from((async function*(){entered++;yield chunk;await delay(5000,null,{signal});yield chunk;})()),spoolDirectory:directory,spoolBudget:budget,maxBytes:size,timeoutMs:6000});
 const req=httpRequest(a.url,{method:'POST',headers:a.headers});req.on('error',()=>{});req.end();
 await until(()=>entered===1&&budget.snapshot().active===1);
 req.destroy();
 await until(()=>budget.snapshot().active===0);
 let calls=0;
 const b=await server(t,{resolveShare:async()=>++calls===1?item:null,openArtifact:async()=>Readable.from([chunk]),spoolDirectory:directory,spoolBudget:budget,maxBytes:size});
 const res=await b.get();assert.equal(res.status,404);await res.text();
 await until(()=>budget.snapshot().active===0);
 assert.deepEqual(await readdir(directory),[]);
});
test('actual filesystem reserve threshold rejects before opening source',async t=>{
 const directory=await root(t),budget=createSpoolBudget({directory,minimumFreeBytes:Number.MAX_SAFE_INTEGER-MiB,capacityBytes:encryptedReservation(MiB)});
 let opened=0;
 const a=await server(t,{resolveShare:async()=>({artifact_id:randomUUID(),sha256:'a'.repeat(64)}),openArtifact:async()=>{opened++;throw Error();},spoolDirectory:directory,spoolBudget:budget,maxBytes:MiB});
 const res=await a.get();assert.equal(res.status,429);await res.text();assert.equal(opened,0);assert.equal(budget.snapshot().active,0);
});
