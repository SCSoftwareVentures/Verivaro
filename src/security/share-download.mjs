import { createHash, timingSafeEqual } from 'node:crypto';
import {pipeline} from 'node:stream/promises';
import {Readable} from 'node:stream';
import {isAbsolute} from 'node:path';
import {createSpoolBudget} from './spool-budget.mjs';
import {stageEncryptedArtifact, MAX_SPOOL_BYTES} from './encrypted-artifact-spool.mjs';
import { verifyIdentityToken } from './verify-identity.mjs';
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
function deny(res){send(res,404,Buffer.from('Not available\n'),{'Content-Type':'text/plain; charset=utf-8','Connection':'close'});}
function validArtifact(item){
 return item&&isArtifactId(item.artifact_id)&&typeof item.sha256==='string'&&hashPattern.test(item.sha256);
}
// No public object URLs, ranges, inline display, or caller-selected filenames.
// Verify full buffered content before sending any bytes. Bound process memory by
// maxBytes * maxConcurrent (plus fixed overhead); large exports need another design.
export function createShareDownloadHandler({resolveShare,resolveRecipientShare,recipientVerifier,openArtifact,spoolDirectory,spoolBudget,maxBytes=8*1024*1024,maxConcurrent=4,requestsPerMinute=120,perPeerPerMinute=20,maxPeers=2048,timeoutMs=10000}){
 if((resolveRecipientShare!==undefined||recipientVerifier!==undefined)&&
 (typeof resolveRecipientShare!=='function'||!recipientVerifier?.publicKey||!recipientVerifier?.issuer||!recipientVerifier?.audience))throw Error('invalid recipient configuration');
 const verifier=recipientVerifier?Object.freeze({...recipientVerifier}):null;
 if(typeof resolveShare!=='function'||typeof openArtifact!=='function'||
 ![maxBytes,maxConcurrent,requestsPerMinute,perPeerPerMinute,maxPeers,timeoutMs].every(x=>Number.isSafeInteger(x)&&x>0)||
 (spoolDirectory!==undefined&&(typeof spoolDirectory!=='string'||!isAbsolute(spoolDirectory)))||
 maxBytes>(spoolDirectory?MAX_SPOOL_BYTES:32*1024*1024)||
 (spoolDirectory&&maxBytes*maxConcurrent>2*1024*1024*1024)||maxConcurrent>16||maxPeers>10000||timeoutMs>30000)throw Error('invalid gateway settings');
 if(spoolBudget!==undefined&&(!spoolDirectory||spoolBudget.directory!==spoolDirectory||typeof spoolBudget.reserve!=='function'))throw Error('invalid shared spool budget');
 const budget=spoolDirectory?(spoolBudget??createSpoolBudget({directory:spoolDirectory})):null;
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
  const recipientRoute=req.url==='/public/share/recipient-download';
  if(req.method!=='POST'||(!recipientRoute&&req.url!=='/public/share/download')||req.headers['transfer-encoding']!==undefined||
    (req.headers['content-length']!==undefined&&req.headers['content-length']!=='0')||req.headers.range!==undefined){
   deny(res);return;
  }
  const auth=req.headers.authorization;
  if(req.rawHeaders.filter((v,i)=>i%2===0&&v.toLowerCase()==='authorization').length!==1){deny(res);return;}
  if(typeof auth!=='string'||!/^Bearer [A-Za-z0-9_-]{43}$/.test(auth)){deny(res);return;}
  let digest;
  try{digest=digestShareToken(auth.slice(7));}catch{deny(res);return;}
  const identityHeaders=req.rawHeaders.filter((v,i)=>i%2===0&&v.toLowerCase()==='x-verivaro-recipient').length;
  const identity=req.headers['x-verivaro-recipient'];
  if(recipientRoute){
   if(!verifier||identityHeaders!==1||typeof identity!=='string'){deny(res);return;}
  }else if(identityHeaders!==0){deny(res);return;}
  // Re-validate signature/lifetime before BOTH authorization checks.
  const authorize=recipientRoute
   ?()=>resolveRecipientShare(digest,verifyIdentityToken(identity,{...verifier,now:Math.floor(Date.now()/1000)}))
   :()=>resolveShare(digest);
  inFlight++;
  const controller=new AbortController();
  const timer=setTimeout(()=>{
   controller.abort();
   if(res.headersSent&&!res.writableFinished)res.destroy();
  },timeoutMs);
  timer.unref?.();
  const disconnect=()=>{if(!res.writableFinished)controller.abort();};
  res.once('close',disconnect);
  let staged,source,reservation;
  try{
   const first=await authorize();
   controller.signal.throwIfAborted();
   if(!validArtifact(first))throw Error('denied');
   if(budget){
    reservation=await budget.reserve(maxBytes,controller.signal);
    if(!reservation){send(res,429,Buffer.from('Not available\n'),{'Content-Type':'text/plain; charset=utf-8','Retry-After':'60','Connection':'close'});return;}
   }
   source=await openArtifact(first.artifact_id,{signal:controller.signal,maxBytes});
   let body;
   if(spoolDirectory){
    staged=await stageEncryptedArtifact(source,{directory:spoolDirectory,maxBytes,sha256:first.sha256,signal:controller.signal});
   }else{
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
   body=buffer.subarray(0,length);
   if(!timingSafeEqual(createHash('sha256').update(body).digest(),Buffer.from(first.sha256,'hex')))throw Error('integrity mismatch');
   }
   // Recheck AFTER reading and hashing, immediately before sending.
   const final=await authorize();
   controller.signal.throwIfAborted();
   if(!validArtifact(final)||final.artifact_id!==first.artifact_id||final.sha256!==first.sha256)throw Error('denied');
   if(staged){
    if(res.destroyed||res.writableEnded)return;
    res.writeHead(200,{...baseHeaders,'Content-Type':'application/octet-stream','Content-Length':staged.length,'Content-Disposition':'attachment; filename="verivaro-export.bin"'});
    await pipeline(Readable.from(staged.read()),res,{signal:controller.signal});
    return;
   }
   // Keep the concurrency slot until bytes are flushed or the peer disconnects.
   await new Promise((resolve,reject)=>{
    const done=()=>{res.removeListener('finish',done);res.removeListener('close',done);res.removeListener('error',failed);resolve();};
    const failed=()=>{done();};
    if(res.destroyed||res.writableEnded){resolve();return;}
    res.once('finish',done);res.once('close',done);res.once('error',failed);
    try{send(res,200,body,{'Content-Disposition':'attachment; filename="verivaro-export.bin"'});}catch(e){done();reject(e);}
   });
  }catch{if(res.headersSent){res.destroy();}else{deny(res);}}
  finally{
   try{source?.destroy?.();}catch{res.destroy();}
   let cleaned=true;
   try{if(staged)await staged.close();}catch{cleaned=false;res.destroy();}
   // Fail closed if descriptor cleanup is uncertain: retain reservation until restart.
   if(cleaned)reservation?.release();
   clearTimeout(timer);res.removeListener('close',disconnect);inFlight--;
  }
 };
}
