import {createConnection} from 'node:net';
import {isAbsolute} from 'node:path';
import {MAX_EVIDENCE_UPLOAD} from './evidence-objects.mjs';
// A trusted, independently managed local clamd Unix socket is required.
// Unknown response, timeout and disconnect are never considered clean.
export function createClamdScanner({socketPath,timeoutMs=5000}){
 if(typeof socketPath!=='string'||!isAbsolute(socketPath)||socketPath.length>100||!Number.isInteger(timeoutMs)||timeoutMs<100||timeoutMs>15000)throw Error('invalid scanner configuration');
 return async function scan(data,signal){
  if(!Buffer.isBuffer(data)||data.length<1||data.length>MAX_EVIDENCE_UPLOAD)throw Error('invalid scan input');
  signal.throwIfAborted();
  return new Promise((resolve,reject)=>{
   const socket=createConnection({path:socketPath});let finished=false,received=Buffer.alloc(0);
   const finish=(error,result)=>{if(finished)return;finished=true;clearTimeout(timer);signal.removeEventListener('abort',abort);socket.destroy();error?reject(error):resolve(result);};
   const abort=()=>finish(Error('scan aborted'));
   const timer=setTimeout(()=>finish(Error('scanner timeout')),timeoutMs);timer.unref();signal.addEventListener('abort',abort,{once:true});
   if(signal.aborted)return abort();
   socket.once('connect',()=>{
    const len=Buffer.alloc(4);len.writeUInt32BE(data.length);
    socket.write(Buffer.concat([Buffer.from('zINSTREAM\0'),len,data,Buffer.alloc(4)]));
   });
   socket.on('data',chunk=>{
    if(received.length+chunk.length>1024)return finish(Error('scanner response too large'));
    received=Buffer.concat([received,chunk]);const end=received.indexOf(0);if(end<0)return;
    if(end!==received.length-1)return finish(Error('invalid scanner response'));
    const verdict=received.subarray(0,end).toString('utf8');
    if(verdict==='stream: OK')return finish(null,'clean');
    if(/^stream: [A-Za-z0-9_.:/ -]{1,256} FOUND$/.test(verdict))return finish(null,'infected');
    finish(Error('scanner unavailable'));
   });
   socket.once('error',()=>finish(Error('scanner unavailable')));socket.once('close',()=>finish(Error('scanner disconnected')));
  });
 };
}
