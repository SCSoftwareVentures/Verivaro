import {createConnection} from 'node:net';
import {isAbsolute} from 'node:path';
import {createHash} from 'node:crypto';
const MAX=50*1024*1024;
function exchange(socketPath,command,bytes,signal,timeoutMs){
 return new Promise((resolve,reject)=>{
  if(signal?.aborted){reject(Error('scan cancelled'));return;}
  const socket=createConnection({path:socketPath});let response=Buffer.alloc(0),done=false;
  const abort=()=>finish(Error('scan cancelled'));
  const timer=setTimeout(()=>finish(Error('scanner timeout')),timeoutMs);
  function finish(err,value){if(done)return;done=true;clearTimeout(timer);signal?.removeEventListener('abort',abort);socket.destroy();if(err)reject(err);else resolve(value);}
  signal?.addEventListener('abort',abort,{once:true});
  socket.on('error',()=>finish(Error('scanner unavailable')));
  socket.on('end',()=>finish(Error('incomplete scanner response')));
  socket.on('data',chunk=>{
   if(response.length+chunk.length>1024){finish(Error('scanner response too large'));return;}
   response=Buffer.concat([response,chunk]);const i=response.indexOf(0);
   if(i!==-1){if(i!==response.length-1){finish(Error('unexpected scanner data'));return;}try{finish(null,new TextDecoder('utf-8',{fatal:true}).decode(response.subarray(0,i)));}catch{finish(Error('invalid scanner response'));}}
  });
  socket.on('connect',async()=>{try{
   const write=b=>new Promise((res,rej)=>socket.write(b,e=>e?rej(e):res()));
   await write(Buffer.from(command+'\0'));
   if(bytes){for(let offset=0;offset<bytes.length;offset+=65536){if(done)return;const chunk=bytes.subarray(offset,offset+65536),size=Buffer.alloc(4);size.writeUInt32BE(chunk.length);await write(size);await write(chunk);}await write(Buffer.alloc(4));}
  }catch{finish(Error('scanner transport failed'));}});
 });
}
/** Trusted local ClamAV daemon adapter; socket and daemon configuration are operator-only.
 * No remote TCP, subprocess, file path supplied to daemon, or automatic signature updates.
 * Fail closed on scan errors, limits, unexpected responses, or digest disagreement.
 */
export function createClamdScanner({socketPath,timeoutMs=10000}){
 if(typeof socketPath!=='string'||!isAbsolute(socketPath)||socketPath.includes('\0')||!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>30000)throw Error('invalid scanner configuration');
 return async(bytes,metadata,signal)=>{
  if(!Buffer.isBuffer(bytes)||bytes.length<1||bytes.length>MAX||createHash('sha256').update(bytes).digest('hex')!==metadata.sha256)throw Error('scanner input mismatch');
  const version=await exchange(socketPath,'zVERSION',null,signal,timeoutMs);
  if(!/^ClamAV [0-9][0-9A-Za-z.+-]{0,40}(?:\/[^\r\n]{1,200})?$/.test(version))throw Error('unexpected scanner version');
  const engineVersion=version.split('/')[0].slice(7);
  const reply=await exchange(socketPath,'zINSTREAM',bytes,signal,timeoutMs);
  const outcome=reply==='stream: OK'?'clean':/^stream: [^\r\n\0]{1,200} FOUND$/.test(reply)?'rejected':null;
  if(!outcome)throw Error('scanner did not return a verdict');
  return {sha256:metadata.sha256,outcome,engine:'ClamAV',engineVersion};
 };
}
