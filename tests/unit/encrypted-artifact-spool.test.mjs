import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {mkdtemp,readdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer} from 'node:http';
import {Readable} from 'node:stream';
import {stageEncryptedArtifact} from '../../src/security/encrypted-artifact-spool.mjs';
import {createShareDownloadHandler} from '../../src/security/share-download.mjs';
import {generateShareToken} from '../../src/security/share-token.mjs';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
async function directory(t){const path=await mkdtemp(join(tmpdir(),'vv-encrypted-'));t.after(()=>rm(path,{recursive:true,force:true}));return path;}
test('anonymous encrypted spool handles fragmented data, exact hash and one-time read',async t=>{
 const root=await directory(t),data=Buffer.alloc(300*1024+17,0x7a);
 const stage=await stageEncryptedArtifact(Readable.from([data.subarray(0,7),data.subarray(7)]),{directory:root,maxBytes:data.length,sha256:sha(data),signal:new AbortController().signal});
 try{
  assert.deepEqual(await readdir(root),[]);
  const hash=createHash('sha256');let length=0;
  for await(const chunk of stage.read()){assert.ok(chunk.length<=256*1024);length+=chunk.length;hash.update(chunk);}
  assert.equal(length,data.length);assert.equal(hash.digest('hex'),sha(data));
  await assert.rejects(async()=>{for await(const chunk of stage.read())void chunk;});
 }finally{await stage.close();await stage.close();}
 assert.deepEqual(await readdir(root),[]);
});
test('staging rejects oversized, corrupt, empty and aborted sources with no residual files',async t=>{
 const root=await directory(t),good=Buffer.from('good');
 for(const [source,hash,max] of [[Readable.from([good]),sha(good),3],[Readable.from([good]),sha(Buffer.from('bad')),10],[Readable.from([]),sha(Buffer.alloc(0)),10]]){
  await assert.rejects(stageEncryptedArtifact(source,{directory:root,maxBytes:max,sha256:hash,signal:new AbortController().signal}));
  assert.deepEqual(await readdir(root),[]);
 }
 const ctrl=new AbortController();
 const source=Readable.from((async function*(){yield good;ctrl.abort();yield good;})());
 await assert.rejects(stageEncryptedArtifact(source,{directory:root,maxBytes:10,sha256:sha(good),signal:ctrl.signal}));
 assert.deepEqual(await readdir(root),[]);
});
test('real HTTP 64 MiB encrypted delivery, bounded block reads, hash and cleanup', {timeout:30000},async t=>{
 const root=await directory(t);
 const block=Buffer.alloc(256*1024,0x5b),blocks=256,expected=createHash('sha256');
 for(let i=0;i<blocks;i++)expected.update(block);
 const hash=expected.digest('hex'),item={artifact_id:randomUUID(),sha256:hash};
 const {token}=generateShareToken();
 let calls=0,produced=0;
 const handler=createShareDownloadHandler({resolveShare:async()=>{calls++;return item;},openArtifact:async()=>Readable.from((async function*(){for(let i=0;i<blocks;i++){produced++;yield block;}})()),spoolDirectory:root,maxBytes:64*1024*1024,timeoutMs:30000,maxConcurrent:1});
 const server=createServer(handler);
 await new Promise((r,j)=>{server.once('error',j);server.listen(0,'127.0.0.1',r);});
 t.after(()=>new Promise(r=>{server.closeAllConnections();server.close(r);}));
 const start=performance.now();
 const res=await fetch('http://127.0.0.1:'+server.address().port+'/public/share/download',{method:'POST',headers:{Authorization:'Bearer '+token}});
 assert.equal(res.status,200);assert.equal(Number(res.headers.get('content-length')),blocks*block.length);assert.equal(produced,blocks);assert.equal(calls,2);
 const verify=createHash('sha256');let received=0;
 for await(const chunk of res.body){received+=chunk.length;verify.update(chunk);}
 assert.equal(received,blocks*block.length);assert.equal(verify.digest('hex'),hash);
 assert.deepEqual(await readdir(root),[]);
 console.log('encrypted_download_64MiB_ms='+Math.round(performance.now()-start));
});
test('encrypted HTTP staging rechecks revocation and refuses plaintext on mismatch',async t=>{
 const root=await directory(t),data=Buffer.from('approved'),item={artifact_id:randomUUID(),sha256:sha(data)};
 for(const corrupt of [false,true]){
  let calls=0;
  const server=createServer(createShareDownloadHandler({resolveShare:async()=>++calls===1?item:null,openArtifact:async()=>Readable.from([corrupt?Buffer.from('wrong'):data]),spoolDirectory:root,maxBytes:1024}));
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  try{
   const res=await fetch('http://127.0.0.1:'+server.address().port+'/public/share/download',{method:'POST',headers:{Authorization:'Bearer '+generateShareToken().token}});
   assert.equal(res.status,404);assert.equal(await res.text(),'Not available\n');assert.equal(calls,corrupt?1:2);
   assert.deepEqual(await readdir(root),[]);
  }finally{await new Promise(r=>{server.closeAllConnections();server.close(r);});}
 }
});
