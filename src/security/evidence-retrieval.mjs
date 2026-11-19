import {assertServiceLogin,validateServiceIdentity} from './service-login.mjs';
import {signDatabaseContext} from './sign-database-context.mjs';
import {openEvidence,validateEvidence} from './evidence-objects.mjs';
import {verifyIdentityToken} from './verify-identity.mjs';
const role='verivaro_evidence_reader',id='([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',route=new RegExp('^/api/v1/tenants/'+id+'/projects/'+id+'/evidence/'+id+'/download$');
export class EvidenceAccessDenied extends Error{}
export function createEvidenceReader(pool,{expectedLogin,verifier,contextKey,readKey}){
 validateServiceIdentity(role,expectedLogin);
 if(typeof pool?.connect!=='function'||!verifier||!Buffer.isBuffer(contextKey)||contextKey.length!==32||typeof readKey!=='function')throw Error('invalid evidence reader');
 const key=Buffer.from(contextKey);
 return async function retrieve({token,tenantId,projectId,evidenceId,grantId=null}){
  const c=await pool.connect();let tx=false,clean=false,row,clear;
  try{
   await c.query('DISCARD ALL');await assertServiceLogin(c,role,expectedLogin);await c.query('SET ROLE '+role);
   await c.query('BEGIN ISOLATION LEVEL READ COMMITTED');tx=true;
   await c.query("SET LOCAL statement_timeout='5s'");await c.query("SET LOCAL lock_timeout='2s'");await c.query("SET LOCAL idle_in_transaction_session_timeout='10s'");
   const r=await c.query('SELECT pg_backend_pid() AS pid, pg_current_xact_id()::text AS xid');
   const context=signDatabaseContext({token,tenantId,challenge:r.rows[0]},{verifier,key});
   await c.query("SELECT set_config('verivaro.signed_context',$1,true)",[context]);
   const result=grantId===null?await c.query('SELECT * FROM verivaro_ingestion.fetch_object($1,$2,$3)',[tenantId,projectId,evidenceId]):await c.query('SELECT * FROM verivaro_ingestion.fetch_customer_package_object($1,$2,$3,$4)',[tenantId,projectId,grantId,evidenceId]);
   if(result.rows.length!==1||result.rows[0].id!==evidenceId)throw new EvidenceAccessDenied();
   row=result.rows[0];
   await c.query('COMMIT');tx=false;await c.query('DISCARD ALL');clean=true;
   clear=openEvidence({id:evidenceId,tenantId,projectId,sha256:row.sha256,bytes:row.bytes,keyId:row.key_id,mediaType:row.media_type,envelope:row.envelope,cipherDigest:row.cipher_digest},await readKey(row.key_id));
   validateEvidence(clear,row.media_type);
   return {data:clear,mediaType:row.media_type,sha256:row.sha256};
  }catch(e){clear?.fill(0);if(tx)try{await c.query('ROLLBACK');}catch{}
   if(e instanceof EvidenceAccessDenied||e.code==='42501')throw new EvidenceAccessDenied('evidence access denied');
   throw Error('evidence retrieval unavailable');
  }finally{row?.envelope.fill(0);c.release(clean?undefined:new Error('discard evidence reader lease'));}
 };
}
export function isEvidenceDownload(req){return req.method==='GET'&&typeof req.url==='string'&&route.test(req.url);}
const base={'Cache-Control':'no-store, private','Content-Type':'application/octet-stream','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'none'; sandbox; frame-ancestors 'none'",'Cross-Origin-Resource-Policy':'same-origin','Connection':'close'};
function deny(res,status){if(!res.destroyed&&!res.writableEnded){res.writeHead(status,{...base,'Content-Length':0});res.end();}}
export function createEvidenceDownloadHandler({origin,verifier,admission,resolveSession,retrieve,maxConcurrent=4}){
 const u=new URL(origin);
 if(u.protocol!=='https:'||u.href!==u.origin+'/'||typeof retrieve!=='function'||typeof resolveSession!=='function'||typeof admission?.peer!=='function'||typeof admission?.actor!=='function'||!Number.isInteger(maxConcurrent)||maxConcurrent<1||maxConcurrent>8)throw Error('invalid download configuration');
 let active=0;
 return async function download(req,res){
  if(!isEvidenceDownload(req))return deny(res,404);
  const h=req.headers,seen=new Set();
  for(let i=0;i<req.rawHeaders.length;i+=2){const k=req.rawHeaders[i].toLowerCase();if(seen.has(k))return deny(res,400);seen.add(k);}
  if(h.host!==u.host||h.authorization!==undefined||h['transfer-encoding']!==undefined||h['content-encoding']!==undefined||h.range!==undefined||h.expect!==undefined||(h['content-length']!==undefined&&h['content-length']!=='0'))return deny(res,400);
  if(h.origin!==undefined&&h.origin!==u.origin||['same-site','cross-site'].includes(h['sec-fetch-site']))return deny(res,403);
  if(active>=maxConcurrent)return deny(res,429);active++;
  let result;
  try{
   if(!await admission.peer(req.socket.remoteAddress))return deny(res,429);
   const token=await resolveSession(req);if(!token)return deny(res,401);
   let p;try{p=verifyIdentityToken(token,verifier);}catch{return deny(res,401);}
   if(!await admission.actor(p.actorId))return deny(res,429);
   if(res.destroyed)return;
   const [,tenantId,projectId,evidenceId]=route.exec(req.url);
   result=await retrieve({token,tenantId,projectId,evidenceId});
   if(res.destroyed)return;
   const ext=result.mediaType==='image/png'?'png':result.mediaType==='application/pdf'?'pdf':'txt';
   // Attachment only: never embed or render uploaded content.
   res.writeHead(200,{...base,'Content-Disposition':'attachment; filename="evidence-'+evidenceId+'.'+ext+'"','Content-Length':result.data.length,'X-Evidence-SHA256':result.sha256});
   const data=result.data;
   await new Promise(r=>{const done=()=>{res.removeListener('finish',done);res.removeListener('close',done);r();};res.once('finish',done);res.once('close',done);res.end(data);});
  }catch(e){if(!res.headersSent)deny(res,e instanceof EvidenceAccessDenied?404:503);else res.destroy();}
  finally{result?.data.fill(0);active--;}
 };
}
