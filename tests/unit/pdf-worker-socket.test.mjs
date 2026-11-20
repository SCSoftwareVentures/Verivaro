import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,chmod,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomBytes,createHash} from 'node:crypto';
import {createServer} from 'node:net';
import {canonicalPagedTextPdf} from '../../src/security/evidence-formats.mjs';
import {canonicalScannedPdf} from '../../src/security/scanned-pdf.mjs';
import {fixturePng} from '../fixtures/evidence-formats-fixture.mjs';
import {readCanonicalScannedPdf} from '../../src/security/scanned-pdf.mjs';
import {startPdfWorker,createPdfWorkerClient,verifyPdfDerivative} from '../../src/security/pdf-worker-socket.mjs';
const original=canonicalPagedTextPdf([['Equipment must carry ID.']]),sha=b=>createHash('sha256').update(b).digest('hex');
const canonical=()=>canonicalScannedPdf(fixturePng({width:16,height:12,pixels:Buffer.alloc(12*49)}));
const derive=async source=>{const pdf=canonical(),render=readCanonicalScannedPdf(pdf);try{return {pdf,manifest:{version:1,sourceSha256:sha(source),sourceBytes:source.length,derivedSha256:sha(pdf),derivedBytes:pdf.length,pageCount:1,pages:[{page:1,width:16,height:12,rasterSha256:render.rasterSha256}],originalRetained:false,reviewRequired:true,format:'offline-poppler-to-canonical-raster-v1',notice:'Derived copy; does not establish source authenticity.'}};}finally{render.png.fill(0);}};
test('PDF worker authenticates before original is sent and independently verifies derivative',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'vv-pdfw-')),socketPath=join(dir,'worker.sock'),key=randomBytes(32);let worker,client,wrong,calls=0;
 try{
  worker=await startPdfWorker({socketPath,key,convert:async(input,signal)=>{assert.equal(sha(input),sha(original));assert.equal(signal.aborted,false);calls++;return derive(input);}});
  client=createPdfWorkerClient({socketPath,key});
  const source=Buffer.from(original),result=await client(source,new AbortController().signal);
  assert.equal(result.manifest.sourceSha256,sha(source));assert.equal(verifyPdfDerivative(source,result.pdf,result.manifest),true);
  assert.equal(calls,1);
  wrong=createPdfWorkerClient({socketPath,key:randomBytes(32),timeoutMs:2500});
  await assert.rejects(wrong(source,new AbortController().signal));assert.equal(calls,1);
  const edited={...result.manifest,derivedSha256:'0'.repeat(64)};
  assert.throws(()=>verifyPdfDerivative(source,result.pdf,edited));
  await chmod(dir,0o777);await assert.rejects(client(source,new AbortController().signal));
  await chmod(dir,0o700);result.pdf.fill(0);
 }finally{client?.close();wrong?.close();await worker?.close();key.fill(0);await rm(dir,{recursive:true,force:true});}
});
test('forged worker does not receive original PDF; client rejects before upload',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'vv-pdfw-')),socketPath=join(dir,'worker.sock'),key=randomBytes(32);
 let client,seen=0;const peers=new Set(),server=createServer({allowHalfOpen:true},socket=>{
  peers.add(socket);socket.on('error',()=>{});socket.once('close',()=>peers.delete(socket));
  socket.on('data',data=>{seen+=data.length;socket.write(randomBytes(64));});socket.on('end',()=>socket.end());
 });
 try{
  await new Promise(resolve=>server.listen(socketPath,resolve));await chmod(socketPath,0o660);
  client=createPdfWorkerClient({socketPath,key,timeoutMs:1800});
  await assert.rejects(client(original,new AbortController().signal));assert.equal(seen,32);
  const abort=new AbortController();abort.abort();await assert.rejects(client(original,abort.signal));assert.equal(seen,32);
 }finally{client?.close();for(const s of peers)s.destroy();await new Promise(resolve=>server.close(resolve));key.fill(0);await rm(dir,{recursive:true,force:true});}
});
test('malformed converter output and mismatched manifest are denied',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'vv-pdfw-')),socketPath=join(dir,'worker.sock'),key=randomBytes(32);
 let worker,client;
 try{
  worker=await startPdfWorker({socketPath,key,convert:async input=>{const r=await derive(input);r.manifest.pages[0].rasterSha256='0'.repeat(64);return r;}});
  client=createPdfWorkerClient({socketPath,key,timeoutMs:1800});
  await assert.rejects(client(original,new AbortController().signal));
  assert.throws(()=>verifyPdfDerivative(original,Buffer.from('%PDF-bad'),{version:1}));
 }finally{client?.close();await worker?.close();key.fill(0);await rm(dir,{recursive:true,force:true});}
});
test('systemd service template encodes isolated non-root security boundary',async()=>{
 const unit=await readFile(new URL('../../services/pdf-worker/verivaro-pdf.service',import.meta.url),'utf8');
 for(const line of ['User=verivaro-pdf','Group=verivaro-pdf-client','PrivateNetwork=yes','RestrictAddressFamilies=AF_UNIX','NoNewPrivileges=yes','PrivateTmp=yes','ProtectSystem=strict','MemoryMax=512M','TasksMax=32','CPUQuota=100%','LimitCORE=0','CapabilityBoundingSet=','LoadCredential=pdf-key:'])assert.ok(unit.includes(line),line);
 assert.equal(unit.includes('ExecStart=/usr/bin/node /opt/verivaro/services/pdf-worker/main.mjs'),true);
});
