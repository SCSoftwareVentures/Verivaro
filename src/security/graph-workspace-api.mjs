import {UnsupportedExtraction} from './contractiq-extraction.mjs';
import {EvidenceAccessDenied} from './evidence-retrieval.mjs';
import {verifyIdentityToken} from './verify-identity.mjs';
import {decodeStrictJson} from './provider-identity.mjs';
import {ReleaseDenied,ReleaseConflict} from './evidence-release.mjs';
const U='([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',route=new RegExp('^/api/v1/tenants/'+U+'/projects/'+U+'/verification(?:/(requirement|rule-review|link|link-review|extract|import-source))?$'),id=new RegExp('^'+U+'$'),v4=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/,hash=/^[a-f0-9]{64}$/;
export function isGraphWorkspaceRequest(req){return typeof req.url==='string'&&route.test(req.url);}
export function isGraphWorkspaceMutation(req){return req.method==='POST'&&typeof req.url==='string'&&!!route.exec(req.url)?.[3];}
function response(res,status,data){
 if(res.destroyed||res.writableEnded)return;
 const body=JSON.stringify(data);if(Buffer.byteLength(body)>4*1024*1024)throw Error('workspace response limit');
 res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store, private','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'",'Cross-Origin-Resource-Policy':'same-origin','Connection':'close','Content-Length':Buffer.byteLength(body)});res.end(body);
}
function denied(res,status){return response(res,status,{error:status===401?'authentication_required':status===404?'not_found':status===409?'conflict':status===429?'rate_limited':status===503?'temporarily_unavailable':'request_denied'});}
async function read(req,action){
 let n=0;const chunks=[],timer=setTimeout(()=>req.destroy(),3000);timer.unref();
 try{
  for await(const c of req){n+=c.length;if(n>8192||n>Number(req.headers['content-length']))throw Error('invalid body');chunks.push(c);}
  if(n!==Number(req.headers['content-length']))throw Error('invalid body');
  const v=decodeStrictJson(Buffer.concat(chunks).toString('base64url'));
  const shapes={extract:['evidenceId','sha256'],'import-source':['evidenceId','sha256','line','quoteSha256','requirementId','versionId','applicability'],requirement:['requirementId','versionId','expectedRevision','title','criterion','applicability'],'rule-review':['versionId','decision','reason'],link:['versionId','linkId','evidenceId','sha256'],'link-review':['linkId','decision','reason']},keys=shapes[action];
  if(!v||typeof v!=='object'||Array.isArray(v)||Object.keys(v).length!==keys.length||keys.some(k=>!Object.hasOwn(v,k)))throw Error('invalid fields');
  const isId=k=>typeof v[k]==='string'&&id.test(v[k]),isV4=k=>typeof v[k]==='string'&&v4.test(v[k]);
  const text=(x,n)=>typeof x==='string'&&[...x].length>=1&&[...x].length<=n&&Buffer.byteLength(x)<=4*n&&x===x.trim()&&!/[\x00-\x1f\x7f-\x9f\ud800-\udfff]/u.test(x);
  if(action==='extract'||action==='import-source'){
   if(!isId('evidenceId')||typeof v.sha256!=='string'||!hash.test(v.sha256))throw Error('invalid source');
   if(action==='import-source'&&(!isV4('requirementId')||!isV4('versionId')||!Number.isInteger(v.line)||v.line<1||v.line>262144||typeof v.quoteSha256!=='string'||!hash.test(v.quoteSha256)||!['required','optional','not_applicable','unknown'].includes(v.applicability)))throw Error('invalid source line');
  }else if(action==='requirement'){
   if(!isV4('requirementId')||!isV4('versionId')||!Number.isInteger(v.expectedRevision)||v.expectedRevision<0||v.expectedRevision>15||!text(v.title,128)||!text(v.criterion,1024)||!['required','optional','not_applicable','unknown'].includes(v.applicability))throw Error('invalid requirement');
  }else if(action==='link'){
   if(!isId('versionId')||!isV4('linkId')||!isId('evidenceId')||typeof v.sha256!=='string'||!hash.test(v.sha256))throw Error('invalid link');
  }else if(!(action==='rule-review'?isId('versionId')&&['approved','rejected'].includes(v.decision):isId('linkId')&&['pass','fail','unknown'].includes(v.decision))||!text(v.reason,512))throw Error('invalid review');
  return v;
 }finally{clearTimeout(timer);for(const b of chunks)b.fill(0);}
}
export function createGraphWorkspaceApi({origin,verifier,admission,resolveSession,workflow,extract}){
 const u=new URL(origin);
 if(u.protocol!=='https:'||u.href!==u.origin+'/'||typeof resolveSession!=='function'||!['assessment','writeRequirement','reviewRequirement','linkEvidence','reviewLink'].every(k=>typeof workflow?.[k]==='function')||typeof admission?.peer!=='function'||typeof admission?.actor!=='function')throw Error('invalid workspace API');
 let active=0;
 return async function workspace(req,res){
  if(!isGraphWorkspaceRequest(req))return denied(res,404);
  const m=route.exec(req.url),action=m?.[3],mutation=!!action;
  if(req.method!==(mutation?'POST':'GET'))return denied(res,405);
  const h=req.headers,seen=new Set();
  for(let i=0;i<req.rawHeaders.length;i+=2){const k=req.rawHeaders[i].toLowerCase();if(seen.has(k))return denied(res,400);seen.add(k);}
  if(h.host!==u.host||h.authorization!==undefined||h['transfer-encoding']!==undefined||h['content-encoding']!==undefined||h.expect!==undefined||
   (mutation?(h['content-type']!=='application/json'||!/^[1-9][0-9]{0,3}$/.test(h['content-length']??'')||Number(h['content-length'])>8192):(h['content-length']!==undefined&&h['content-length']!=='0')))return denied(res,400);
  if(mutation&&h.origin!==u.origin||h.origin!==undefined&&h.origin!==u.origin||['cross-site','same-site'].includes(h['sec-fetch-site']))return denied(res,403);
  if(active>=8)return denied(res,429);active++;
  const controller=new AbortController(),abort=()=>controller.abort();res.once('close',abort);
  try{
   if(!await admission.peer(req.socket.remoteAddress))return denied(res,429);
   const token=await resolveSession(req);if(!token)return denied(res,401);
   let p;try{p=verifyIdentityToken(token,verifier);}catch{return denied(res,401);}
   if(!await admission.actor(p.actorId))return denied(res,429);
   if(res.destroyed)return;
   const [,tenantId,projectId]=m,scope={token,tenantId,projectId};
   if(!mutation)return response(res,200,{...await workflow.assessment(scope),extractionEnabled:typeof extract==='function'});
   let input;try{input=await read(req,action);}catch{return denied(res,400);}
   controller.signal.throwIfAborted();
   const args={...input,...scope};
   if(action==='extract'||action==='import-source'){
    if(typeof extract!=='function')return denied(res,404);
    return response(res,200,await extract(args,{importLine:action==='import-source',signal:controller.signal}));
   }
   if(action==='requirement')return response(res,200,await workflow.writeRequirement(args));
   if(action==='rule-review')return response(res,200,{reviewed:await workflow.reviewRequirement(args)});
   if(action==='link')return response(res,200,{linkId:await workflow.linkEvidence(args)});
   return response(res,200,{reviewed:await workflow.reviewLink(args)});
  }catch(e){return denied(res,e instanceof ReleaseDenied||e instanceof EvidenceAccessDenied?404:e instanceof ReleaseConflict?409:e instanceof UnsupportedExtraction?422:503);}
  finally{res.removeListener('close',abort);active--;}
 };
}
