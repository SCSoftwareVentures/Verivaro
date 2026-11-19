import {verifyIdentityToken} from './verify-identity.mjs';
import {decodeStrictJson} from './provider-identity.mjs';
import {ReleaseDenied,ReleaseConflict} from './evidence-release.mjs';
import {EvidenceAccessDenied} from './evidence-retrieval.mjs';
const U='([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',route=new RegExp('^/api/v1/tenants/'+U+'/projects/'+U+'/releases(?:/(submit|review|publish))?$'),id=new RegExp('^'+U+'$'),v4=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/,hash=/^[a-f0-9]{64}$/;
export function isReleaseWorkspaceRequest(req){return req.url==='/api/v1/workspaces'||typeof req.url==='string'&&route.test(req.url);}
export function isReleaseWorkspaceMutation(req){return req.method==='POST'&&typeof req.url==='string'&&!!route.exec(req.url)?.[3];}
function response(res,status,data){
 if(res.destroyed||res.writableEnded)return;
 const body=JSON.stringify(data);if(Buffer.byteLength(body)>512*1024)throw Error('workspace response limit');
 res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store, private','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'",'Cross-Origin-Resource-Policy':'same-origin','Connection':'close','Content-Length':Buffer.byteLength(body)});res.end(body);
}
function denied(res,status){return response(res,status,{error:status===401?'authentication_required':status===404?'not_found':status===409?'conflict':status===429?'rate_limited':status===503?'temporarily_unavailable':'request_denied'});}
async function read(req,action){
 let n=0;const chunks=[],timer=setTimeout(()=>req.destroy(),3000);timer.unref();
 try{
  for await(const c of req){n+=c.length;if(n>2048||n>Number(req.headers['content-length']))throw Error('invalid body');chunks.push(c);}
  if(n!==Number(req.headers['content-length']))throw Error('invalid body');
  const v=decodeStrictJson(Buffer.concat(chunks).toString('base64url')),keys=action==='review'?['requestId','sha256','decision','reason']:['requestId','sha256','evidenceId'];
  if(Object.keys(v).length!==keys.length||keys.some(k=>!Object.hasOwn(v,k)||typeof v[k]!=='string')||!v4.test(v.requestId)||!hash.test(v.sha256))throw Error('invalid fields');
  if(action==='review'){
   if(!['approved','rejected'].includes(v.decision)||!['verified','integrity_concern','insufficient_evidence','policy_denied'].includes(v.reason)||(v.decision==='approved')!==(v.reason==='verified'))throw Error('invalid review');
  }else if(!id.test(v.evidenceId))throw Error('invalid evidence');
  return v;
 }finally{clearTimeout(timer);for(const b of chunks)b.fill(0);}
}
export function createReleaseWorkspaceApi({origin,verifier,admission,resolveSession,workflow,publish,uploadsEnabled=false}){
 const u=new URL(origin);
 if(u.protocol!=='https:'||u.href!==u.origin+'/'||typeof resolveSession!=='function'||!['tenants','workspace','request','review'].every(k=>typeof workflow?.[k]==='function')||typeof admission?.peer!=='function'||typeof admission?.actor!=='function'||(publish!==undefined&&typeof publish!=='function'))throw Error('invalid workspace API');
 let active=0;
 return async function workspace(req,res){
  if(!isReleaseWorkspaceRequest(req))return denied(res,404);
  const m=route.exec(req.url),action=m?.[3],mutation=!!action;
  if(req.method!==(mutation?'POST':'GET'))return denied(res,405);
  const h=req.headers,seen=new Set();
  for(let i=0;i<req.rawHeaders.length;i+=2){const k=req.rawHeaders[i].toLowerCase();if(seen.has(k))return denied(res,400);seen.add(k);}
  if(h.host!==u.host||h.authorization!==undefined||h['transfer-encoding']!==undefined||h['content-encoding']!==undefined||h.expect!==undefined||
   (mutation?(h['content-type']!=='application/json'||!/^[1-9][0-9]{0,3}$/.test(h['content-length']??'')||Number(h['content-length'])>2048):(h['content-length']!==undefined&&h['content-length']!=='0')))return denied(res,400);
  if(mutation&&h.origin!==u.origin||h.origin!==undefined&&h.origin!==u.origin||['cross-site','same-site'].includes(h['sec-fetch-site']))return denied(res,403);
  if(active>=8)return denied(res,429);active++;
  const controller=new AbortController(),abort=()=>controller.abort();res.once('close',abort);
  try{
   if(!await admission.peer(req.socket.remoteAddress))return denied(res,429);
   const token=await resolveSession(req);if(!token)return denied(res,401);
   let p;try{p=verifyIdentityToken(token,verifier);}catch{return denied(res,401);}
   if(!await admission.actor(p.actorId))return denied(res,429);
   if(res.destroyed)return;
   if(!m)return response(res,200,{items:await workflow.tenants({token})});
   const [,tenantId,projectId]=m,scope={token,tenantId,projectId};
   if(!mutation)return response(res,200,{...await workflow.workspace(scope),publishEnabled:typeof publish==='function',uploadsEnabled});
   if(!publish)return denied(res,404);
   let input;try{input=await read(req,action);}catch{return denied(res,400);}
   controller.signal.throwIfAborted();
   const args={...input,...scope};
   if(action==='submit')return response(res,200,{requestId:await workflow.request(args)});
   if(action==='review')return response(res,200,{reviewed:await workflow.review(args)});
   return response(res,200,{exportId:await publish(args,{signal:controller.signal})});
  }catch(e){return denied(res,e instanceof ReleaseDenied||e instanceof EvidenceAccessDenied?404:e instanceof ReleaseConflict?409:503);}
  finally{res.removeListener('close',abort);active--;}
 };
}
