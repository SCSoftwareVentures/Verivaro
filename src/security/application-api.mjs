import {verifyIdentityToken} from './verify-identity.mjs';
import {decodeStrictJson} from './provider-identity.mjs';
import {ScopedAccessDenied,ScopedConflict} from './scoped-database.mjs';
const id='([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})';
const routes=new RegExp('^/api/v1/tenants/'+id+'/projects(?:/'+id+'(/evidence)?)?$');
const headers={'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store, private','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'",'Cross-Origin-Resource-Policy':'same-origin'};
const error=(res,status,extra={})=>send(res,status,{error:status===404?'not_found':status===401?'authentication_required':status===409?'conflict':status===429?'rate_limited':status===503?'temporarily_unavailable':'request_denied'},extra);
function send(res,status,payload,extra={}){
 if(res.destroyed||res.writableEnded)return;
 const body=JSON.stringify(payload);if(Buffer.byteLength(body)>512*1024)throw Error('response exceeds limit');
 res.writeHead(status,{...headers,'Content-Length':Buffer.byteLength(body),...extra});res.end(body);
}
function duplicateHeaders(req){
 const seen=new Set(),critical=new Set(['host','cookie','origin','authorization','content-length','transfer-encoding','content-encoding','sec-fetch-site','content-type','idempotency-key']);
 for(let i=0;i<req.rawHeaders.length;i+=2){const h=req.rawHeaders[i].toLowerCase();if(critical.has(h)&&seen.has(h))return true;seen.add(h);}
 return false;
}
const requestId=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
export function isRenameRequest(req){
 return req.method==='PATCH'&&typeof req.url==='string'&&(()=>{const m=routes.exec(req.url);return !!m?.[2]&&!m[3];})();
}
function validMutationHeaders(req){
 return req.headers['content-type']==='application/json'&&/^[1-9][0-9]{0,3}$/.test(req.headers['content-length']??'')&&Number(req.headers['content-length'])<=2048&&requestId.test(req.headers['idempotency-key']??'');
}
async function readMutation(req){
 const chunks=[];let n=0;const timer=setTimeout(()=>req.destroy(),3000);timer.unref();
 try{
  for await(const chunk of req){n+=chunk.length;if(n>2048||n>Number(req.headers['content-length']))throw Error('body too large');chunks.push(chunk);}
  if(n!==Number(req.headers['content-length']))throw Error('truncated body');
  const v=decodeStrictJson(Buffer.concat(chunks).toString('base64url'));
  if(Object.keys(v).length!==2||!Object.hasOwn(v,'name')||!Object.hasOwn(v,'revision')||typeof v.name!=='string'||v.name!==v.name.trim()||
  [...v.name].length<1||[...v.name].length>128||Buffer.byteLength(v.name)>512||/[\x00-\x1f\x7f-\x9f\ud800-\udfff]/u.test(v.name)||
  !Number.isInteger(v.revision)||v.revision<0||v.revision>=2147483647)throw Error('invalid mutation');
  return v;
 }finally{clearTimeout(timer);}
}
export function createApplicationApi({resolveSession,scoped,admission,verifier,origin,maxConcurrent=16}){
 const u=new URL(origin);
 if(u.protocol!=='https:'||u.href!==u.origin+'/'||typeof resolveSession!=='function'||typeof scoped?.execute!=='function'||typeof admission?.peer!=='function'||typeof admission?.actor!=='function'||!verifier||!Number.isInteger(maxConcurrent)||maxConcurrent<1||maxConcurrent>64)throw Error('invalid API configuration');
 let active=0;
 return async function api(req,res){
  // Raw exact path matching: no decoding, query, alias or generic operation dispatch.
  if(typeof req.url!=='string'||req.url.length>256||!req.url.startsWith('/api/'))return error(res,404);
  const mutation=isRenameRequest(req);
  if(mutation)res.setHeader('Connection','close');
  if(duplicateHeaders(req)||req.headers.host!==u.host||req.headers.authorization!==undefined||req.headers['transfer-encoding']!==undefined||
   req.headers['content-encoding']!==undefined||(!mutation&&req.headers['content-length']!==undefined&&req.headers['content-length']!=='0')||
   req.headers['expect']!==undefined)return error(res,400,{'Connection':'close'});
  if(req.method!=='GET'&&!mutation)return error(res,405,{Allow:'GET','Connection':'close'});
  if((mutation&&req.headers.origin!==u.origin)||(req.headers.origin!==undefined&&req.headers.origin!==u.origin)||['cross-site','same-site'].includes(req.headers['sec-fetch-site']))return error(res,403);
  const m=routes.exec(req.url);if(!m)return error(res,404);
  if(mutation&&!validMutationHeaders(req))return error(res,400);
  if(active>=maxConcurrent)return error(res,429,{'Retry-After':'5'});
  active++;
  try{
   // Never trust forwarded headers; behind a proxy this is its shared peer.
   if(!await admission.peer(req.socket.remoteAddress))return error(res,429,{'Retry-After':'60'});
   if(res.destroyed)return;
   const token=await resolveSession(req);
   if(!token)return error(res,401);
   let p;try{p=verifyIdentityToken(token,verifier);}catch{return error(res,401);}
   if(!await admission.actor(p.actorId))return error(res,429,{'Retry-After':'60'});
   if(res.destroyed)return;
   const [,tenantId,projectId,evidence]=m,operation=mutation?'renameProject':!projectId?'listProjects':evidence?'listEvidence':'getProject';
   let args=projectId?{projectId}:{};
   if(mutation){try{args={...args,...await readMutation(req),requestId:req.headers['idempotency-key']};}catch{return error(res,400);}}
   if(res.destroyed)return;
   const rows=await scoped.execute({token,tenantId,operation,args});
   if(!Array.isArray(rows)||rows.length>200)throw Error('invalid response');
   if((operation==='getProject'||mutation)&&!rows.length)return error(res,404);
   // Fixed public projection; storage refs, actor IDs, credentials or other
   // added database columns cannot leak through object serialization.
   const items=rows.map(r=>operation==='listEvidence'?{id:r.id,projectId:r.project_id,sha256:r.sha256,createdAt:r.created_at}:{id:r.id,name:r.name,revision:r.revision,archivedAt:r.archived_at??null});
   return send(res,200,(operation==='getProject'||mutation)?{project:items[0]}:{items,limit:200});
  }catch(e){return error(res,e instanceof ScopedAccessDenied?404:e instanceof ScopedConflict?409:503);}
  finally{active--;}
 };
}
