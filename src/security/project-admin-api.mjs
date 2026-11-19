import {createVerificationExport} from './verification-report-export.mjs';
import {createHash} from 'node:crypto';
import {verifyIdentityToken} from './verify-identity.mjs';
import {decodeStrictJson} from './provider-identity.mjs';
import {ReleaseDenied,ReleaseConflict} from './evidence-release.mjs';
import {digestShareToken} from './share-token.mjs';
const U='([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',path=new RegExp('^/api/v1/tenants/'+U+'/projects/(?:create|'+U+'/(directory|access|shares|share-issue|share-revoke|archive|report|report-download|report-pdf|report-package))$'),uuid=new RegExp('^'+U+'$'),v4=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
function match(req){return typeof req.url==='string'?path.exec(req.url):null;}
export function isProjectAdminRequest(req){return !!match(req);}
export function isProjectAdminMutation(req){const m=match(req);return !!m&&req.method==='POST'&&!['directory','shares','report','report-download','report-pdf','report-package'].includes(m[3]);}
function send(res,status,data){if(res.destroyed||res.writableEnded)return;const body=JSON.stringify(data);if(Buffer.byteLength(body)>512*1024)throw Error('response limit');res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store, private','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'",'Cross-Origin-Resource-Policy':'same-origin','Connection':'close','Content-Length':Buffer.byteLength(body)});res.end(body);}
const bad=(res,status)=>send(res,status,{error:status===401?'authentication_required':status===404?'not_found':status===409?'conflict':status===429?'rate_limited':status===503?'temporarily_unavailable':'request_denied'});
const shapes={archive:['requestId','revision'],create:['requestId','name'],access:['requestId','targetId','role','generation'],'share-issue':['exportId','shareId','recipientId','code'],'share-revoke':['shareId']};
async function read(req,op){
 let n=0;const chunks=[],timer=setTimeout(()=>req.destroy(),3000);timer.unref();
 try{
  for await(const c of req){n+=c.length;if(n>2048||n>Number(req.headers['content-length']))throw Error('invalid body');chunks.push(c);}
  if(n!==Number(req.headers['content-length']))throw Error('invalid body');
  const v=decodeStrictJson(Buffer.concat(chunks).toString('base64url')),keys=shapes[op];
  if(Object.keys(v).length!==keys.length||keys.some(k=>!Object.hasOwn(v,k)))throw Error('invalid body');
  const validId=k=>typeof v[k]==='string'&&uuid.test(v[k]),validV4=k=>typeof v[k]==='string'&&v4.test(v[k]);
  if(op==='archive'&&(!validV4('requestId')||!Number.isInteger(v.revision)||v.revision<0||v.revision>=2147483647))throw Error('invalid archive');
  if(op==='create'&&(!validV4('requestId')||typeof v.name!=='string'||v.name!==v.name.trim()||[...v.name].length<1||[...v.name].length>128||Buffer.byteLength(v.name)>512||/[\x00-\x1f\x7f-\x9f\ud800-\udfff]/u.test(v.name)))throw Error('invalid project');
  if(op==='access'&&(!validV4('requestId')||!validId('targetId')||!['viewer','contributor','reviewer','revoke'].includes(v.role)||v.generation!==null&&!validId('generation')))throw Error('invalid access');
  if(op==='share-issue'){if(!validId('exportId')||!validV4('shareId')||!validId('recipientId'))throw Error('invalid share');v.digest=digestShareToken(v.code);delete v.code;}
  if(op==='share-revoke'&&!validV4('shareId'))throw Error('invalid share');
  return v;
 }finally{clearTimeout(timer);for(const c of chunks)c.fill(0);}
}
export function createProjectAdminApi({origin,verifier,admission,resolveSession,workflow,sharingEnabled=false}){
 const u=new URL(origin);if(u.protocol!=='https:'||u.href!==u.origin+'/'||typeof resolveSession!=='function'||typeof admission?.peer!=='function'||typeof admission?.actor!=='function'||!['createProject','directory','changeAccess','shares','createShare','revokeRecipient','archiveProject','report'].every(k=>typeof workflow?.[k]==='function'))throw Error('invalid project administration configuration');let active=0;
 return async function admin(req,res){
  const m=match(req);if(!m)return bad(res,404);
  const [,tenantId,projectId,action]=m,op=action??'create',mutation=!['directory','shares','report','report-download','report-pdf','report-package'].includes(op),h=req.headers,seen=new Set();
  if(req.method!==(mutation?'POST':'GET'))return bad(res,405);
  for(let i=0;i<req.rawHeaders.length;i+=2){const k=req.rawHeaders[i].toLowerCase();if(seen.has(k))return bad(res,400);seen.add(k);}
  if(h.host!==u.host||h.authorization!==undefined||h['transfer-encoding']!==undefined||h['content-encoding']!==undefined||h.expect!==undefined||(mutation?(h['content-type']!=='application/json'||!/^[1-9][0-9]{0,3}$/.test(h['content-length']??'')||Number(h['content-length'])>2048):(h['content-length']!==undefined&&h['content-length']!=='0')))return bad(res,400);
  if(mutation&&h.origin!==u.origin||h.origin!==undefined&&h.origin!==u.origin||['cross-site','same-site'].includes(h['sec-fetch-site']))return bad(res,403);
  if(active>=8)return bad(res,429);active++;
  try{
   if(!await admission.peer(req.socket.remoteAddress))return bad(res,429);
   const token=await resolveSession(req);if(!token)return bad(res,401);
   let p;try{p=verifyIdentityToken(token,verifier);}catch{return bad(res,401);}
   if(!await admission.actor(p.actorId))return bad(res,429);if(res.destroyed)return;
   const scope={token,tenantId,projectId};
   if(['report','report-download','report-pdf','report-package'].includes(op)){
    if(h.range!==undefined)return bad(res,400);
    const report=await workflow.report(scope);
    if(op==='report-pdf'||op==='report-package'){
     const format=op==='report-pdf'?'pdf':'zip',data=createVerificationExport(report,format);
     if(res.destroyed)return;
     res.writeHead(200,{'Content-Type':format==='pdf'?'application/pdf':'application/zip','Content-Disposition':'attachment; filename="verification-'+projectId+'.'+format+'"','Cache-Control':'no-store, private','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'none'; sandbox; frame-ancestors 'none'",'X-Frame-Options':'DENY','Cross-Origin-Resource-Policy':'same-origin','Connection':'close','Content-Length':data.length,'X-Report-SHA256':createHash('sha256').update(data).digest('hex')});
     await new Promise(r=>{const done=()=>{res.removeListener('finish',done);res.removeListener('close',done);r();};res.once('finish',done);res.once('close',done);res.end(data);});return;
    }
    const body=JSON.stringify(report);
    if(Buffer.byteLength(body)>2*1024*1024)throw Error('report capacity exceeded');
    if(res.destroyed)return;
    const headers={'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store, private','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'none'; sandbox; frame-ancestors 'none'",'X-Frame-Options':'DENY','Cross-Origin-Resource-Policy':'same-origin','Content-Length':Buffer.byteLength(body),'X-Report-SHA256':createHash('sha256').update(body).digest('hex')};
    if(op==='report-download')headers['Content-Disposition']='attachment; filename="verification-'+projectId+'.json"';
    res.writeHead(200,headers);return res.end(body);
   }
   if(op==='directory')return send(res,200,{items:await workflow.directory(scope)});
   if(['shares','share-issue','share-revoke'].includes(op)&&!sharingEnabled)return bad(res,404);
   if(op==='shares')return send(res,200,{items:await workflow.shares(scope)});
   let input;try{input=await read(req,op);}catch{return bad(res,400);}
   if(res.destroyed)return;
   const args={...input,...scope};
   if(op==='archive')return send(res,200,await workflow.archiveProject(args));
   if(op==='create')return send(res,200,{id:await workflow.createProject(args)});
   if(op==='access')return send(res,200,{generation:await workflow.changeAccess(args)});
   if(op==='share-issue')return send(res,200,{shareId:input.shareId,expiresAt:await workflow.createShare(args)});
   return send(res,200,{revoked:await workflow.revokeRecipient(args)});
  }catch(e){return bad(res,e instanceof ReleaseDenied?404:e instanceof ReleaseConflict?409:503);}
  finally{active--;}
 };
}
