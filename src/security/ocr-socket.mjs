import {createServer,createConnection} from 'node:net';
import {createHmac,randomBytes,timingSafeEqual} from 'node:crypto';
import {lstat,chmod} from 'node:fs/promises';
import {dirname,isAbsolute} from 'node:path';
import {validateEvidence,MAX_EVIDENCE_UPLOAD} from './evidence-objects.mjs';
import {OCR_MAX_OUTPUT,parseOcrTsv} from './ocr-preview.mjs';
const fail=()=>Error('OCR transport denied');
const challengeSize=32,headerSize=36;
const mac=(key,label,nonce,length,body)=>createHmac('sha256',key).update(label).update(nonce).update(length).update(body).digest();
function frame(key,label,nonce,body){
 const size=Buffer.alloc(4);size.writeUInt32BE(body.length);
 const tag=mac(key,label,nonce,size,body);return Buffer.concat([size,tag,body]);
}
function unframe(key,label,nonce,buffer,max){
 if(buffer.length<headerSize)throw fail();
 const n=buffer.readUInt32BE(0);if(n<1||n>max||buffer.length!==headerSize+n)throw fail();
 const body=buffer.subarray(headerSize),expected=mac(key,label,nonce,buffer.subarray(0,4),body);
 try{if(!timingSafeEqual(expected,buffer.subarray(4,36)))throw fail();return Buffer.from(body);}finally{expected.fill(0);}
}
function config(path,key,timeoutMs){
 if(typeof path!=='string'||!isAbsolute(path)||Buffer.byteLength(path)>100||/[\x00-\x1f]/.test(path)||!Buffer.isBuffer(key)||key.length!==32||!Number.isInteger(timeoutMs)||timeoutMs<100||timeoutMs>20000)throw fail();
}
async function privateDir(path){
 const d=await lstat(dirname(path));if(!d.isDirectory()||(d.mode&0o027)!==0)throw fail(); // no group writes or any world access
}
async function privateSocket(path){
 await privateDir(path);const s=await lstat(path);
 if(!s.isSocket()||(s.mode&0o007)!==0||(s.mode&0o600)!==0o600)throw fail();
}
function collect(socket,max,initial=Buffer.alloc(0)){
 return new Promise((resolve,reject)=>{
  let total=initial.length,chunks=[initial],settled=false;
  const cleanup=()=>{socket.off('data',data);socket.off('end',end);socket.off('error',error);socket.off('close',close);};
  const finish=(e)=>{if(settled)return;settled=true;cleanup();let b;try{if(!e)b=Buffer.concat(chunks,total);}finally{for(const c of chunks)c.fill(0);chunks=[];}e?reject(e):resolve(b);};
  const data=c=>{total+=c.length;if(total>max){c.fill(0);finish(fail());socket.destroy();}else chunks.push(c);};
  const end=()=>finish(),error=()=>finish(fail()),close=()=>finish(fail());
  socket.on('data',data);socket.once('end',end);socket.once('error',error);socket.once('close',close);
 });
}
// Fresh server nonce binds both directions; no timestamps, reusable credential
// packets, plaintext files, caller options or network listeners.
export async function startOcrWorker({socketPath,key,recognize,timeoutMs=12000,maxConnections=4}){
 config(socketPath,key,timeoutMs);if(typeof recognize!=='function'||!Number.isInteger(maxConnections)||maxConnections<1||maxConnections>8)throw fail();
 await privateDir(socketPath);const auth=Buffer.from(key),peers=new Set();let busy=false,closing=false;
 const server=createServer({allowHalfOpen:true},socket=>{
  socket.on('error',()=>{});if(closing||peers.size>=maxConnections){socket.destroy();return;}peers.add(socket);
  const nonce=randomBytes(challengeSize),ac=new AbortController();let request,body,out,response,owns=false;
  const timer=setTimeout(()=>{ac.abort();socket.destroy();},timeoutMs);timer.unref();
  socket.once('close',()=>{clearTimeout(timer);peers.delete(socket);ac.abort();});
  void(async()=>{
   try{
    const incoming=collect(socket,headerSize+MAX_EVIDENCE_UPLOAD);
    socket.write(nonce);
    request=await incoming;ac.signal.throwIfAborted();body=unframe(auth,'vv-ocr-request-v1',nonce,request,MAX_EVIDENCE_UPLOAD);
    validateEvidence(body,'image/png');
    if(busy)throw fail();busy=true;owns=true;
    out=await recognize(body,ac.signal);ac.signal.throwIfAborted();
    parseOcrTsv(out,{width:body.readUInt32BE(16),height:body.readUInt32BE(20)});
    response=frame(auth,'vv-ocr-response-v1',nonce,out);
    await new Promise((resolve,reject)=>{socket.once('close',resolve);socket.end(response,()=>resolve());});
   }catch{socket.destroy();}
   finally{if(owns)busy=false;nonce.fill(0);request?.fill(0);body?.fill(0);out?.fill?.(0);response?.fill(0);}
  })();
 });
 try{
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(socketPath,()=>{server.off('error',reject);resolve();});});
  await chmod(socketPath,0o660);await privateSocket(socketPath);
 }catch(e){if(server.listening)await new Promise(r=>server.close(r));auth.fill(0);throw e;}
 server.on('error',()=>{for(const s of peers)s.destroy();});
 return Object.freeze({async close(){
  if(closing)return;closing=true;for(const s of peers)s.destroy();
  await new Promise(r=>server.close(r));auth.fill(0);
  // Node normally removes its own Unix socket on close. An existing path
  // at this point is never unlinked: it may belong to a replacement.
 }});
}
export function createOcrSocketClient({socketPath,key,timeoutMs=14000}){
 config(socketPath,key,timeoutMs);const auth=Buffer.from(key);let active=false,closed=false;
 async function recognize(data,signal){
  if(active||closed)throw fail();validateEvidence(data,'image/png');signal.throwIfAborted();active=true;
  let socket,nonce,request,response,timer,abort;
  try{
   await privateSocket(socketPath);signal.throwIfAborted();
   socket=createConnection({path:socketPath,allowHalfOpen:true});socket.on('error',()=>{});
   abort=()=>socket.destroy(fail());signal.addEventListener('abort',abort,{once:true});
   timer=setTimeout(abort,timeoutMs);timer.unref();if(signal.aborted)abort();
   nonce=await new Promise((resolve,reject)=>{
    let used=0,b=Buffer.alloc(challengeSize),settled=false;
    const cleanup=()=>{socket.off('data',read);socket.off('error',bad);socket.off('end',bad);socket.off('close',bad);};
    const bad=()=>{if(settled)return;settled=true;cleanup();b.fill(0);reject(fail());};
    const read=c=>{if(used+c.length>challengeSize){c.fill(0);bad();return;}c.copy(b,used);used+=c.length;c.fill(0);if(used===challengeSize){settled=true;cleanup();socket.pause();resolve(b);}};
    socket.on('data',read);socket.once('error',bad);socket.once('end',bad);socket.once('close',bad);
   });
   signal.throwIfAborted();request=frame(auth,'vv-ocr-request-v1',nonce,data);
   const incoming=collect(socket,headerSize+OCR_MAX_OUTPUT);
   socket.resume();socket.end(request);response=await incoming;signal.throwIfAborted();
   return unframe(auth,'vv-ocr-response-v1',nonce,response,OCR_MAX_OUTPUT);
  }finally{clearTimeout(timer);if(abort)signal.removeEventListener('abort',abort);socket?.destroy();nonce?.fill(0);request?.fill(0);response?.fill(0);active=false;}
 }
 recognize.close=()=>{closed=true;auth.fill(0);};return recognize;
}
