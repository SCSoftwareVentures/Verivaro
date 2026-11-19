import {createHash} from 'node:crypto';
import {verifyIdentityToken} from './verify-identity.mjs';
import {TYPES} from './evidence-formats.mjs';
import {MAX_EVIDENCE_UPLOAD} from './evidence-objects.mjs';
import {IngestionDenied,IngestionConflict,IngestionRejected,IngestionQuota} from './evidence-ingestion.mjs';
const id='([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',route=new RegExp('^/api/v1/tenants/'+id+'/projects/'+id+'/evidence(?:/capture/'+id+'/'+id+'/'+id+')?$');
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
export function isEvidenceUpload(req){return req.method==='POST'&&typeof req.url==='string'&&route.test(req.url);}
function reply(res,status,payload,extra={}){
 if(res.destroyed||res.writableEnded)return;
 const body=JSON.stringify(payload);
 res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store, private','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'",'Cross-Origin-Resource-Policy':'same-origin','Connection':'close','Content-Length':Buffer.byteLength(body),...extra});res.end(body);
}
const failure=(res,status,extra)=>reply(res,status,{error:status===401?'authentication_required':status===404?'not_found':status===409?'conflict':status===422?'evidence_rejected':status===507?'storage_quota_exhausted':status===429?'rate_limited':status===503?'temporarily_unavailable':'request_denied'},extra);
function safeHeaders(req,origin){
 const h=req.headers,seen=new Set(),critical=new Set(['host','origin','cookie','authorization','content-length','transfer-encoding','content-encoding','content-type','idempotency-key','x-evidence-sha256','x-capture-actor','expect','sec-fetch-site']);
 for(let i=0;i<req.rawHeaders.length;i+=2){const k=req.rawHeaders[i].toLowerCase();if(critical.has(k)&&seen.has(k))return false;seen.add(k);}
 return h.host===origin.host&&h.authorization===undefined&&h['transfer-encoding']===undefined&&h['content-encoding']===undefined&&h.expect===undefined&&TYPES.includes(h['content-type'])&&
 /^[1-9][0-9]{0,5}$/.test(h['content-length']??'')&&Number(h['content-length'])<=MAX_EVIDENCE_UPLOAD&&uuid.test(h['idempotency-key']??'')&&/^[a-f0-9]{64}$/.test(h['x-evidence-sha256']??'');
}
export function createEvidenceUploadHandler({origin,verifier,admission,resolveSession,ingest,maxConcurrent=4}){
 const u=new URL(origin);
 if(u.protocol!=='https:'||u.href!==u.origin+'/'||typeof resolveSession!=='function'||typeof ingest!=='function'||typeof admission?.peer!=='function'||typeof admission?.actor!=='function'||!Number.isInteger(maxConcurrent)||maxConcurrent<1||maxConcurrent>8)throw Error('invalid upload configuration');
 let active=0;
 return async function upload(req,res){
  if(!isEvidenceUpload(req))return failure(res,404);
  if(!safeHeaders(req,u))return failure(res,400);
  const expectedActor=req.headers['x-capture-actor'];if(expectedActor!==undefined&&(!route.exec(req.url)[3]||!/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(expectedActor)))return failure(res,400);
  if(req.headers.origin!==u.origin||['cross-site','same-site'].includes(req.headers['sec-fetch-site']))return failure(res,403);
  if(active>=maxConcurrent)return failure(res,429,{'Retry-After':'5'});active++;
  const controller=new AbortController(),abort=()=>controller.abort(),chunks=[];let data,timer;
  res.once('close',abort);
  try{
   if(!await admission.peer(req.socket.remoteAddress))return failure(res,429,{'Retry-After':'60'});
   const token=await resolveSession(req);if(!token)return failure(res,401);
   let p;try{p=verifyIdentityToken(token,verifier);}catch{return failure(res,401);}
   if(!await admission.actor(p.actorId))return failure(res,429,{'Retry-After':'60'});
   if(expectedActor!==undefined&&expectedActor!==p.actorId)return failure(res,404);
   controller.signal.throwIfAborted();
   const expected=Number(req.headers['content-length']);let n=0;
   timer=setTimeout(()=>{controller.abort();req.destroy();},5000);timer.unref();
   for await(const chunk of req){
    n+=chunk.length;if(n>expected||n>MAX_EVIDENCE_UPLOAD)throw new IngestionRejected('upload too large');
    chunks.push(chunk);
   }
   clearTimeout(timer);
   if(n!==expected)return failure(res,400);
   data=Buffer.concat(chunks);
   if(createHash('sha256').update(data).digest('hex')!==req.headers['x-evidence-sha256'])return failure(res,422);
   const [,tenantId,projectId,windowId,versionId,milestoneRevisionId]=route.exec(req.url),capture=windowId?{windowId,versionId,milestoneRevisionId}:undefined;
   const result=await ingest({token,tenantId,projectId,requestId:req.headers['idempotency-key'],data,mediaType:req.headers['content-type'],signal:controller.signal,...(capture?{capture}:{})});
   return reply(res,200,{evidence:{id:result.id,sha256:result.sha256,bytes:result.bytes},...(capture?{linkId:result.link_id}:{})});
  }catch(e){return failure(res,e instanceof IngestionDenied?404:e instanceof IngestionConflict?409:e instanceof IngestionRejected?422:e instanceof IngestionQuota?507:503);}
  finally{clearTimeout(timer);res.removeListener('close',abort);data?.fill(0);for(const chunk of chunks)chunk.fill(0);active--;}
 };
}
