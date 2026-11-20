import {digestShareToken} from './share-token.mjs';
import {verifyIdentityToken} from './verify-identity.mjs';
import {decodeStrictJson} from './provider-identity.mjs';
import {TenantDenied,TenantConflict} from './tenant-administration.mjs';
const U='([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',route=new RegExp('^/api/v1/tenants/'+U+'/administration/(directory|enrollments|transfers|enroll|access|transfer-request|transfer-accept|invite-redeem|invite-cancel)$'),uuid=new RegExp('^'+U+'$'),v4=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const reads=['directory','enrollments','transfers'];
const shapes={enroll:['requestId','subjectDigest','role'],access:['requestId','targetId','role','generation'],'transfer-request':['requestId','targetId','generation'],'transfer-accept':['requestId'],'invite-redeem':['requestId','code'],'invite-cancel':['requestId']};
function match(req){return typeof req.url==='string'?route.exec(req.url):null;}
export function isTenantAdminRequest(req){return !!match(req);}
export function isTenantAdminMutation(req){const m=match(req);return !!m&&req.method==='POST'&&!reads.includes(m[2]);}
function send(res,status,payload){
 if(res.destroyed||res.writableEnded)return;
 const body=JSON.stringify(payload);if(Buffer.byteLength(body)>512*1024)throw Error('response limit');
 res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store, private','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'",'Cross-Origin-Resource-Policy':'same-origin','Connection':'close','Content-Length':Buffer.byteLength(body)});res.end(body);
}
const bad=(res,status)=>send(res,status,{error:status===401?'authentication_required':status===404?'not_found':status===409?'conflict':status===429?'rate_limited':status===503?'temporarily_unavailable':'request_denied'});
async function read(req,action){
 const parts=[];let n=0;const timer=setTimeout(()=>req.destroy(),3000);timer.unref();
 try{
  for await(const b of req){n+=b.length;if(n>2048||n>Number(req.headers['content-length']))throw Error('invalid body');parts.push(b);}
  if(n!==Number(req.headers['content-length']))throw Error('invalid body');
  const v=decodeStrictJson(Buffer.concat(parts).toString('base64url')),keys=shapes[action];
  if(Object.keys(v).length!==keys.length||keys.some(k=>!Object.hasOwn(v,k)||typeof v[k]!=='string')||!v4.test(v.requestId))throw Error('invalid fields');
  if(action==='enroll'&&(!/^[a-f0-9]{64}$/.test(v.subjectDigest)||!['viewer','contributor','reviewer'].includes(v.role)))throw Error('invalid enrollment');
  if(['access','transfer-request'].includes(action)&&(!uuid.test(v.targetId)||!uuid.test(v.generation)))throw Error('invalid member');
  if(action==='access'&&!['viewer','contributor','reviewer','revoke'].includes(v.role))throw Error('invalid member role');
  if(action==='invite-redeem')digestShareToken(v.code);
  return v;
 }finally{clearTimeout(timer);for(const p of parts)p.fill(0);}
}
export function createTenantAdminApi({origin,verifier,admission,resolveSession,administration}){
 const u=new URL(origin);if(u.protocol!=='https:'||u.href!==u.origin+'/'||typeof resolveSession!=='function'||typeof admission?.peer!=='function'||typeof admission?.actor!=='function'||!['directory','enrollments','transfers','requestEnrollment','access','requestTransfer','acceptTransfer','redeemInvitation','cancelInvitation'].every(k=>typeof administration?.[k]==='function'))throw Error('invalid tenant administration API');
 let active=0;
 return async function handle(req,res){
  const m=match(req);if(!m)return bad(res,404);
  const [,tenantId,action]=m,mutation=!reads.includes(action),h=req.headers,seen=new Set();
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
   const scope={tenantId,token};
   if(!mutation)return send(res,200,{items:await administration[action](scope)});
   let input;try{input=await read(req,action);}catch{return bad(res,400);}
   if(res.destroyed)return;
   const args={...input,...scope};
   if(action==='enroll')return send(res,200,{requestId:await administration.requestEnrollment(args)});
   if(action==='access')return send(res,200,{generation:await administration.access(args)});
   if(action==='transfer-request')return send(res,200,{requestId:await administration.requestTransfer(args)});
   if(action==='invite-redeem')return send(res,200,{generation:await administration.redeemInvitation(args)});
   if(action==='invite-cancel')return send(res,200,{cancelled:await administration.cancelInvitation(args)});
   const accepted=await administration.acceptTransfer(args);if(!accepted)return bad(res,409);return send(res,200,{accepted});
  }catch(e){return bad(res,e instanceof TenantDenied?404:e instanceof TenantConflict?409:503);}
  finally{active--;}
 };
}
