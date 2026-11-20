// Authenticated, local-only PDF normalizer transport. No HTTP listener, shell,
// user-chosen renderer args or fallback to the application process.
import {createServer,createConnection} from 'node:net';
import {createHmac,createHash,randomBytes,timingSafeEqual} from 'node:crypto';
import {lstat,chmod} from 'node:fs/promises';
import {dirname,isAbsolute} from 'node:path';
import {validateEvidence} from './evidence-objects.mjs';
import {readCanonicalScannedPdf} from './scanned-pdf.mjs';
import {readCanonicalMultipageScannedPdf} from './scanned-pdf-multipage.mjs';
import {PDF_NORMALIZER_MAX_SOURCE} from './pdf-normalization.mjs';
const deny=()=>Error('PDF worker communication denied');
const SHA=/^[a-f0-9]{64}$/;
const REQUEST_MAX=PDF_NORMALIZER_MAX_SOURCE, REPLY_MAX=4+262144+8192;
const digest=b=>createHash('sha256').update(b).digest('hex');
function limits(socketPath,key,ms){
 if(typeof socketPath!=='string'||!isAbsolute(socketPath)||Buffer.byteLength(socketPath)>100||/[\x00-\x1f]/.test(socketPath)||!Buffer.isBuffer(key)||key.length!==32||!Number.isInteger(ms)||ms<500||ms>90000)throw deny();
}
async function checkDir(path){
 const d=await lstat(dirname(path));
 if(!d.isDirectory()||(d.mode&0o027)!==0)throw deny();
}
async function checkSocket(path){
 await checkDir(path);
 const s=await lstat(path);
 if(!s.isSocket()||(s.mode&0o007)!==0||(s.mode&0o600)!==0o600)throw deny();
}
function readExact(socket,n){
 return new Promise((resolve,reject)=>{
  const b=Buffer.alloc(n);let used=0,done=false;
  const clear=()=>{socket.off('data',data);socket.off('error',bad);socket.off('end',bad);socket.off('close',bad);};
  const bad=()=>{if(done)return;done=true;clear();b.fill(0);reject(deny());};
  const data=part=>{
   if(used+part.length>n){part.fill(0);bad();return;}
   part.copy(b,used);used+=part.length;part.fill(0);
   if(used===n){done=true;clear();socket.pause();resolve(b);}
  };
  socket.on('data',data);socket.once('error',bad);socket.once('end',bad);socket.once('close',bad);socket.resume();
 });
}
function readAll(socket,max){
 return new Promise((resolve,reject)=>{
  let n=0,parts=[],done=false;
  const clear=()=>{socket.off('data',data);socket.off('error',bad);socket.off('end',finish);socket.off('close',bad);};
  const cleanup=()=>{for(const p of parts)p.fill(0);parts=[];};
  const bad=()=>{if(done)return;done=true;clear();cleanup();reject(deny());};
  const finish=()=>{if(done)return;done=true;clear();let result;try{result=Buffer.concat(parts,n);}finally{cleanup();}resolve(result);};
  const data=p=>{n+=p.length;if(n>max){p.fill(0);bad();socket.destroy();}else parts.push(p);};
  socket.on('data',data);socket.once('error',bad);socket.once('end',finish);socket.once('close',bad);
 });
}
const proof=(key,client,server)=>createHmac('sha256',key).update('vv-pdf-worker-proof-v1').update(client).update(server).digest();
const signature=(key,label,nonce,length,body)=>createHmac('sha256',key).update(label).update(nonce).update(length).update(body).digest();
function frame(key,label,nonce,body){
 const len=Buffer.alloc(4);len.writeUInt32BE(body.length);
 return Buffer.concat([len,signature(key,label,nonce,len,body),body]);
}
function decodeFrame(key,label,nonce,data,max){
 if(!Buffer.isBuffer(data)||data.length<37)throw deny();
 const len=data.readUInt32BE(0);if(len<1||len>max||len+36!==data.length)throw deny();
 const expected=signature(key,label,nonce,data.subarray(0,4),data.subarray(36));
 try{if(!timingSafeEqual(expected,data.subarray(4,36)))throw deny();}
 finally{expected.fill(0);}
 return Buffer.from(data.subarray(36));
}
function assertInput(original){
 if(!Buffer.isBuffer(original)||original.length<20||original.length>REQUEST_MAX||!/^%PDF-1\.[0-7]\r?\n/.test(original.subarray(0,12).toString('latin1')))throw deny();
}
export function verifyPdfDerivative(original,pdf,manifest){
 assertInput(original);
 if(!Buffer.isBuffer(pdf)||pdf.length<1||pdf.length>262144||!manifest||typeof manifest!=='object'||Array.isArray(manifest))throw deny();
 const keys=['version','sourceSha256','sourceBytes','derivedSha256','derivedBytes','pageCount','pages','originalRetained','reviewRequired','format','notice'];
 if(Object.keys(manifest).sort().join('|')!==keys.sort().join('|')||manifest.version!==1||manifest.originalRetained!==false||manifest.reviewRequired!==true||manifest.format!=='offline-poppler-to-canonical-raster-v1'||typeof manifest.notice!=='string'||manifest.notice.length>512||!manifest.notice.includes('Derived copy')||!SHA.test(manifest.sourceSha256)||!SHA.test(manifest.derivedSha256)||manifest.sourceSha256!==digest(original)||manifest.derivedSha256!==digest(pdf)||manifest.sourceBytes!==original.length||manifest.derivedBytes!==pdf.length||!Number.isInteger(manifest.pageCount)||manifest.pageCount<1||manifest.pageCount>4||!Array.isArray(manifest.pages)||manifest.pages.length!==manifest.pageCount)throw deny();
 validateEvidence(pdf,'application/pdf');
 for(let page=1;page<=manifest.pageCount;page++){
  const p=manifest.pages[page-1];
  if(!p||Object.keys(p).sort().join('|')!=='height|page|rasterSha256|width'||p.page!==page||!SHA.test(p.rasterSha256)||!Number.isInteger(p.width)||!Number.isInteger(p.height)||p.width<1||p.height<1)throw deny();
  const verified=manifest.pageCount===1?readCanonicalScannedPdf(pdf):readCanonicalMultipageScannedPdf(pdf,{page});
  try{if(verified.page!==page||verified.width!==p.width||verified.height!==p.height||verified.rasterSha256!==p.rasterSha256)throw deny();}
  finally{verified.png.fill(0);}
 }
 return true;
}
function packResponse(original,result){
 const pdf=result?.pdf,manifest=result?.manifest;
 verifyPdfDerivative(original,pdf,manifest);
 const metadata=Buffer.from(JSON.stringify(manifest),'utf8');if(metadata.length>8192)throw deny();
 const len=Buffer.alloc(4);len.writeUInt32BE(pdf.length);
 return Buffer.concat([len,pdf,metadata]);
}
function unpackResponse(original,body){
 if(!Buffer.isBuffer(body)||body.length<6)throw deny();
 const n=body.readUInt32BE(0);
 if(n<1||n>262144||n+4>=body.length||body.length-n-4>8192)throw deny();
 const pdf=Buffer.from(body.subarray(4,n+4));
 try{
  const manifest=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(body.subarray(n+4)));
  verifyPdfDerivative(original,pdf,manifest);return {pdf,manifest};
 }catch{pdf.fill(0);throw deny();}
}
export async function startPdfWorker({socketPath,key,convert,timeoutMs=60000,maxConnections=3}){
 limits(socketPath,key,timeoutMs);
 if(typeof convert!=='function'||!Number.isInteger(maxConnections)||maxConnections<1||maxConnections>6)throw deny();
 await checkDir(socketPath);
 const auth=Buffer.from(key),connections=new Set();let busy=false,closing=false;
 const server=createServer({allowHalfOpen:true},socket=>{
  socket.on('error',()=>{});
  if(closing||connections.size>=maxConnections){socket.destroy();return;}
  connections.add(socket);
  const controller=new AbortController(),serverNonce=randomBytes(32);
  let clientNonce,nonce,hello,framed,original,result,reply,payload,owns=false;
  const timeout=setTimeout(()=>{controller.abort();socket.destroy();},timeoutMs);timeout.unref();
  socket.once('close',()=>{clearTimeout(timeout);controller.abort();connections.delete(socket);});
  void(async()=>{
   try{
    clientNonce=await readExact(socket,32);controller.signal.throwIfAborted();
    nonce=Buffer.concat([clientNonce,serverNonce]);
    hello=Buffer.concat([serverNonce,proof(auth,clientNonce,serverNonce)]);
    const incoming=readAll(socket,REQUEST_MAX+36);
    socket.resume();socket.write(hello);
    framed=await incoming;controller.signal.throwIfAborted();
    original=decodeFrame(auth,'vv-pdf-request-v1',nonce,framed,REQUEST_MAX);assertInput(original);
    if(busy)throw deny();busy=true;owns=true;
    result=await convert(original,controller.signal);controller.signal.throwIfAborted();
    payload=packResponse(original,result);
    reply=frame(auth,'vv-pdf-response-v1',nonce,payload);
    await new Promise(resolve=>{socket.once('close',resolve);socket.end(reply,resolve);});
   }catch{socket.destroy();}
   finally{
    if(owns)busy=false;
    serverNonce.fill(0);clientNonce?.fill(0);nonce?.fill(0);hello?.fill(0);framed?.fill(0);original?.fill(0);result?.pdf?.fill?.(0);reply?.fill(0);payload?.fill(0);
   }
  })();
 });
 try{
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(socketPath,()=>{server.off('error',reject);resolve();});});
  await chmod(socketPath,0o660);await checkSocket(socketPath);
 }catch(e){if(server.listening)await new Promise(resolve=>server.close(resolve));auth.fill(0);throw e;}
 server.on('error',()=>{for(const s of connections)s.destroy();});
 return Object.freeze({async close(){if(closing)return;closing=true;for(const s of connections)s.destroy();await new Promise(resolve=>server.close(resolve));auth.fill(0);}});
}
export function createPdfWorkerClient({socketPath,key,timeoutMs=65000}){
 limits(socketPath,key,timeoutMs);
 const auth=Buffer.from(key);let active=false,closed=false;
 async function convert(original,signal){
  if(active||closed)throw deny();assertInput(original);signal.throwIfAborted();active=true;
  let socket,clientNonce,greeting,nonce,framed,raw,body,timer,abort;
  try{
   await checkSocket(socketPath);signal.throwIfAborted();
   socket=createConnection({path:socketPath,allowHalfOpen:true});socket.on('error',()=>{});
   abort=()=>socket.destroy(deny());signal.addEventListener('abort',abort,{once:true});
   timer=setTimeout(abort,timeoutMs);timer.unref();if(signal.aborted)abort();
   clientNonce=randomBytes(32);
   const awaited=readExact(socket,64);socket.write(clientNonce);greeting=await awaited;
   const serverNonce=greeting.subarray(0,32),expected=proof(auth,clientNonce,serverNonce);
   try{if(!timingSafeEqual(expected,greeting.subarray(32)))throw deny();}
   finally{expected.fill(0);}
   nonce=Buffer.concat([clientNonce,serverNonce]);signal.throwIfAborted();
   framed=frame(auth,'vv-pdf-request-v1',nonce,original);
   const response=readAll(socket,REPLY_MAX+36);
   socket.resume();socket.end(framed);
   raw=await response;signal.throwIfAborted();
   body=decodeFrame(auth,'vv-pdf-response-v1',nonce,raw,REPLY_MAX);
   return unpackResponse(original,body);
  }finally{
   clearTimeout(timer);if(abort)signal.removeEventListener('abort',abort);
   socket?.destroy();clientNonce?.fill(0);greeting?.fill(0);nonce?.fill(0);framed?.fill(0);raw?.fill(0);body?.fill(0);active=false;
  }
 }
 convert.close=()=>{closed=true;auth.fill(0);};return convert;
}
