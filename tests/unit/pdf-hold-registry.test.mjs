import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readdir,readFile,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomBytes,randomUUID} from 'node:crypto';
import {createLocalPdfHoldRegistry} from '../../src/security/pdf-hold-registry.mjs';
const id=()=>randomUUID(),meta=()=>({tenantId:id(),projectId:id(),quarantineId:id(),sha256:'a'.repeat(64)});
const signal=()=>new AbortController().signal;
test('default unknown, cross-instance exclusion and explicit independently authorized hold release',async()=>{
 const root=await mkdtemp(join(tmpdir(),'vv-hold-')),key=randomBytes(32),m=meta();let allowed=true;
 const a=createLocalPdfHoldRegistry({root,key,authorizeChange:async()=>allowed});
 const b=createLocalPdfHoldRegistry({root,key,authorizeChange:async()=>true});
 try{
  await assert.rejects(a.holdLookup(m,signal()));
  assert.equal(await a.withExclusiveHoldLock(m,()=>a.holdLookup(m,signal()),signal()),undefined);
  await a.recordHoldChange(m,{actorId:id(),held:true,reason:'Initial litigation hold',signal:signal()});
  await a.withExclusiveHoldLock(m,async()=>{
   assert.equal(await a.holdLookup(m,signal()),true);
   await assert.rejects(b.recordHoldChange(m,{actorId:id(),held:false,reason:'Premature release attempt',signal:signal()}));
  },signal());
  allowed=false;
  await assert.rejects(a.recordHoldChange(m,{actorId:id(),held:false,reason:'Unauthorized release attempt',signal:signal()}));
  allowed=true;
  const release=await a.recordHoldChange(m,{actorId:id(),held:false,reason:'Authorized registry hold release',signal:signal()});
  assert.equal(release.sequence,2);
  assert.equal(await b.withExclusiveHoldLock(m,()=>b.holdLookup({...m,sourceSha256:m.sha256,sha256:undefined},signal()),signal()),false);
  await assert.rejects(b.withExclusiveHoldLock(m,()=>b.holdLookup({...m,sourceSha256:'0'.repeat(64)},signal()),signal()));
  await assert.rejects(a.recordHoldChange(m,{actorId:id(),held:false,reason:'Duplicate hold release request',signal:signal()}));
 }finally{a.close();b.close();key.fill(0);await rm(root,{recursive:true,force:true});}
});
test('journal corruption, torn records and cancelled lock fail closed',async()=>{
 const root=await mkdtemp(join(tmpdir(),'vv-hold-')),key=randomBytes(32),m=meta(),r=createLocalPdfHoldRegistry({root,key,authorizeChange:async()=>true});
 try{
  await r.recordHoldChange(m,{actorId:id(),held:false,reason:'Authorized no-hold confirmation',signal:signal()});
  const file=join(root,(await readdir(root)).find(x=>x.endsWith('.holdlog'))),saved=await readFile(file),altered=Buffer.from(saved);
  const at=altered.indexOf(Buffer.from('false'));assert.ok(at>0);altered[at]=116;await writeFile(file,altered);
  await assert.rejects(r.withExclusiveHoldLock(m,()=>r.holdLookup(m,signal()),signal()));
  await writeFile(file,saved.subarray(0,-1));await assert.rejects(r.withExclusiveHoldLock(m,()=>r.holdLookup(m,signal()),signal()));
  await writeFile(file,saved);
  const abort=new AbortController();abort.abort();
  await assert.rejects(r.withExclusiveHoldLock(m,()=>true,abort.signal));
  assert.equal((await readdir(root)).filter(x=>x.endsWith('.lock')).length,0);
 }finally{r.close();key.fill(0);await rm(root,{recursive:true,force:true});}
});
