import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {createHash,randomUUID} from 'node:crypto';
import {mkdtemp,writeFile,symlink,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Readable} from 'node:stream';
import {createShareDownloadHandler} from '../../src/security/share-download.mjs';
import {createPrivateFileStore} from '../../src/security/private-file-store.mjs';
import {generateShareToken} from '../../src/security/share-token.mjs';
const artifact=randomUUID(), bytes=Buffer.from('synthetic approved export');
const metadata={artifact_id:artifact,sha256:createHash('sha256').update(bytes).digest('hex')};
const {token}=generateShareToken();
async function serve(t,settings){
 const server=createServer(createShareDownloadHandler(settings));
 await new Promise((r,j)=>{server.once('error',j);server.listen(0,'127.0.0.1',r);});
 t.after(()=>new Promise(r=>{server.closeAllConnections();server.close(r);}));
 const base='http://127.0.0.1:'+server.address().port;
 return (opts={})=>fetch(base+(opts.path??'/public/share/download'),{method:opts.method??'POST',headers:opts.headers??{Authorization:'Bearer '+token},body:opts.body});
}
test('real HTTP returns only verified bytes with strict security headers',async t=>{
 const folder=await mkdtemp(join(tmpdir(),'vv-share-'));t.after(()=>rm(folder,{recursive:true,force:true}));
 await writeFile(join(folder,artifact),bytes);
 let resolves=0;
 const request=await serve(t,{resolveShare:async()=>{resolves++;return metadata;},openArtifact:createPrivateFileStore(folder),maxBytes:1024});
 const res=await request();
 assert.equal(res.status,200);assert.deepEqual(Buffer.from(await res.arrayBuffer()),bytes);
 assert.equal(resolves,2);assert.match(res.headers.get('cache-control'),/no-store/);
 assert.equal(res.headers.get('referrer-policy'),'no-referrer');
 assert.equal(res.headers.get('x-content-type-options'),'nosniff');
 assert.match(res.headers.get('content-disposition'),/^attachment;/);
 assert.equal(res.headers.get('content-type'),'application/octet-stream');
});
test('invalid/pre-revoked/malformed requests never open an artifact',async t=>{
 let opens=0;
 const request=await serve(t,{resolveShare:async()=>null,openArtifact:async()=>{opens++;throw Error();}});
 for(const opts of [{},{headers:{}},{headers:{Authorization:'Bearer malformed'}},{method:'GET'},{path:'/public/share/download?token='+token},{headers:{Authorization:'Bearer '+token,Range:'bytes=0-1'}},{body:'unexpected'}]){
  const res=await request(opts);assert.equal(res.status,404);assert.equal(await res.text(),'Not available\n');
 }
 assert.equal(opens,0);
});
test('revocation or artifact substitution during retrieval returns no file bytes',async t=>{
 for(const final of [null,{...metadata,artifact_id:randomUUID()},{...metadata,sha256:'a'.repeat(64)}]){
  let calls=0;
  const request=await serve(t,{resolveShare:async()=>++calls===1?metadata:final,openArtifact:async()=>Readable.from([bytes]),maxBytes:1024});
  const res=await request();assert.equal(res.status,404);assert.equal(await res.text(),'Not available\n');assert.equal(calls,2);
 }
});
test('corruption, excessive size and traversal/symlink artifacts fail closed',async t=>{
 const folder=await mkdtemp(join(tmpdir(),'vv-share-'));t.after(()=>rm(folder,{recursive:true,force:true}));
 await writeFile(join(folder,artifact),Buffer.from('tampered'));
 const linked=randomUUID();await symlink(join(folder,artifact),join(folder,linked));
 for(const item of [metadata,{...metadata,artifact_id:'../outside'},{...metadata,artifact_id:linked}]){
  const req=await serve(t,{resolveShare:async()=>item,openArtifact:createPrivateFileStore(folder),maxBytes:1024});
  assert.equal((await req()).status,404);
 }
 const req=await serve(t,{resolveShare:async()=>metadata,openArtifact:async()=>Readable.from([Buffer.alloc(1025)]),maxBytes:1024});
 assert.equal((await req()).status,404);
});
test('bounded peer rate limit cannot be bypassed with forwarded header',async t=>{
 const request=await serve(t,{resolveShare:async()=>null,openArtifact:async()=>{throw Error();},perPeerPerMinute:2});
 for(let i=0;i<3;i++){
  const res=await request({headers:{Authorization:'Bearer '+token,'X-Forwarded-For':'192.0.2.'+i}});
  assert.equal(res.status,i<2?404:429);
 }
});
