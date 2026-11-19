import { createHash, timingSafeEqual } from 'node:crypto';
import { digestShareToken } from './share-token.mjs';
import { isArtifactId } from './private-file-store.mjs';
const hashPattern=/^[0-9a-f]{64}$/;
const baseHeaders=Object.freeze({
 'Cache-Control':'no-store, private, max-age=0',
 'Referrer-Policy':'no-referrer',
 'X-Content-Type-Options':'nosniff',
 'Content-Security-Policy':"default-src 'none'; sandbox; frame-ancestors 'none'",
 'X-Frame-Options':'DENY',
 'Cross-Origin-Resource-Policy':'same-origin'
});
function send(res,status,body,headers={}){
 if(res.destroyed||res.writableEnded)return;
 res.writeHead(status,{...baseHeaders,'Content-Type':'application/octet-stream','Content-Length':body.length,...headers});
 res.end(body);
}
function deny(res){send(res,404,Buffer.from('Not available\n'),{'Content-Type':'text/plain; charset=utf-8'});}
function validArtifact(item){
 return item&&isArtifactId(item.artifact_id)&&typeof item.sha256==='string'&&hashPattern.test(item.sha256);
}
// No public object URLs, ranges, inline display, or caller-selected filenames.
// Verify full buffered content before sending any bytes. Bound process memory by
// maxBytes * maxConcurrent (plus fixed overhead); large exports need another design.
export function createShareDownloadHandler({resolveShare,openArtifact,maxBytes=8*1024*1024,maxConcurrent=4,requestsPerMinute=120,perPeerPerMinute=20,maxPeers=2048,timeoutMs=10000}){
 if(typeof resolveShare!=='function'||typeof openArtifact!=='function'||
 ![maxBytes,maxConcurrent,requestsPerMinute,perPeerPerMinute,maxPeers,timeoutMs].every(x=>Number.isSafeInteger(x)&&x>0)||
 maxBytes>32*1024*1024||maxConcurrent>16||maxPeers>10000||timeoutMs>30000)throw Error('invalid gateway settings');
 let inFlight=0,bucket=-1,count=0;
 const peers=new Map();
 function admit(peer){
  const minute=Math.floor(Date.now()/60000);
  if(bucket!==minute){bucket=minute;count=0;peers.clear();}
  if(count>=requestsPerMinute)return false;
  if(!peers.has(peer)&&peers.size>=maxPeers)return false;
  const n=peers.get(peer)??0;
  if(n>=perPeerPerMinute)return false;
  peers.set(peer,n+1);count++;return true;
 }
 return async function download(req,res){
  // Deliberately ignore forwarded headers: peer identity is transport-derived.
  const peer=req.socket.remoteAddress??'unknown';
  if(!admit(peer)||inFlight>=maxConcurrent){send(res,429,Buffer.from('Not available\n'),{'Content-Type':'text/plain; charset=utf-8','Retry-After':'60','Connection':'close'});return;}
  if(req.method!=='POST'||req.url!=='/public/share/download'||req.headers['transfer-encoding']!==undefined||
    (req.headers['content-length']!==undefined&&req.headers['content-length']!=='0')||req.headers.range!==undefined){
   deny(res);return;
  }
  const auth=req.headers.authorization;
  if(typeof auth!=='string'||!/^Bearer [A-Za-z0-9_-]{43}$/.test(auth)){deny(res);return;}
  let digest;
  try{digest=digestShareToken(auth.slice(7));}catch{deny(res);return;}
  inFlight++;
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),timeoutMs);
  timer.unref?.();
  const disconnect=()=>{if(!res.writableFinished)controller.abort();};
  res.once('close',disconnect);
  try{
   const first=await resolveShare(digest);
   controller.signal.throwIfAborted();
   if(!validArtifact(first))throw Error('denied');
   const source=await openArtifact(first.artifact_id,{signal:controller.signal,maxBytes});
   // Allocate once rather than retaining arbitrary numbers of chunks.
   const buffer=Buffer.allocUnsafe(maxBytes);
   let length=0;
   for await(const chunk of source){
    controller.signal.throwIfAborted();
    if(!Buffer.isBuffer(chunk)||chunk.length>maxBytes-length)throw Error('invalid artifact bytes');
    chunk.copy(buffer,length);length+=chunk.length;
   }
   controller.signal.throwIfAborted();
   if(!length)throw Error('empty artifact');
   const body=buffer.subarray(0,length);
   if(!timingSafeEqual(createHash('sha256').update(body).digest(),Buffer.from(first.sha256,'hex')))throw Error('integrity mismatch');
   // Recheck AFTER reading and hashing, immediately before sending.
   const final=await resolveShare(digest);
   controller.signal.throwIfAborted();
   if(!validArtifact(final)||final.artifact_id!==first.artifact_id||final.sha256!==first.sha256)throw Error('denied');
   send(res,200,body,{'Content-Disposition':'attachment; filename="verivaro-export.bin"'});
  }catch{deny(res);}
  finally{
   clearTimeout(timer);res.removeListener('close',disconnect);inFlight--;
  }
 };
}
