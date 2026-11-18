import {verifyAccessToken} from '../security/oidc.mjs';
import {quarantineUpload} from '../security/quarantine.mjs';
import {randomUUID} from 'node:crypto';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MIME=new Set(['application/pdf','image/jpeg','image/png','text/plain']);
export class ServiceError extends Error {constructor(status,code){super(code);this.status=status;this.code=code;}}
const bad=()=>new ServiceError(400,'invalid_request');
const deny=()=>new ServiceError(404,'resource_unavailable');
const unavailable=()=>new ServiceError(503,'service_unavailable');
const uuid=x=>{if(typeof x!=='string'||!UUID.test(x))throw bad();return x;};
function exact(x,keys){if(!x||typeof x!=='object'||Array.isArray(x)||Object.keys(x).length!==keys.length||keys.some(k=>!Object.hasOwn(x,k)))throw bad();}
function one(r){if(!r||!Array.isArray(r.rows)||r.rows.length!==1)throw unavailable();return r.rows[0];}
function normalize(e){if(e instanceof ServiceError)return e;if(e?.code==='42501')return deny();if(e?.code==='23505')return new ServiceError(409,'idempotency_conflict');if(['22023','22P02','23514'].includes(e?.code))return bad();return unavailable();}
const metadata=r=>{
 const bytes=typeof r.bytes==='string'&&/^[1-9][0-9]{0,8}$/.test(r.bytes)?Number(r.bytes):r.bytes;
 if(typeof r.sha256!=='string'||!/^[a-f0-9]{64}$/.test(r.sha256)||!Number.isSafeInteger(bytes)||bytes<1||bytes>52428800||!MIME.has(r.media_type)||typeof r.received!=='boolean')throw unavailable();
 return Object.freeze({sha256:r.sha256,bytes,mediaType:r.media_type,received:r.received});
};
export const SQL=Object.freeze({
 tx:'SELECT pg_current_xact_id()::text AS tx',
 sign:'SELECT context,signature FROM vv_api.issue_context($1,$2,$3,$4,$5,$6,$7)',
 claims:"SELECT set_config('verivaro.context',$1,true),set_config('verivaro.signature',$2,true)",
 project:'SELECT id,name,timezone FROM vv_app.project WHERE tenant_id=$1 AND id=$2',
 document:'SELECT vv_api.create_document($1,$2,$3,$4) AS id',
 intent:'SELECT vv_api.request_upload($1,$2,$3,$4,$5,$6,$7) AS id',
 status:'SELECT * FROM vv_api.upload_status($1,$2,$3)',
 receipt:'SELECT vv_api.record_quarantine($1,$2,$3,$4,$5,$6,$7) AS id'
});
/** Pool contract compatible with node-postgres. No driver, live IdP, or production listener bundled.
 * Pools must be separately provisioned, genuinely distinct restricted DB identities.
 * Never feed client-controlled SQL, claim fields, role, or pool configuration into this service.
 */
export function createService({runtimePool,signerPool,workerPool,issuerConfig,keyId,quarantineRoot,now=()=>Math.floor(Date.now()/1000)}){
 if(!runtimePool?.connect||!signerPool?.query||!workerPool?.query||new Set([runtimePool,signerPool,workerPool]).size!==3||typeof quarantineRoot!=='string'||!quarantineRoot)throw Error('separate trusted service pools required');
 uuid(keyId);
 const config=structuredClone(issuerConfig);
 function identity(bearer){
 if(typeof bearer!=='string'||bearer.length>16400||!/^Bearer [A-Za-z0-9_.-]+$/.test(bearer))throw new ServiceError(401,'authentication_required');
 try{return verifyAccessToken(bearer.slice(7),config,now());}catch{throw new ServiceError(401,'authentication_required');}
 }
 async function scoped(bearer,t,p,operation){
 const who=identity(bearer);uuid(t);uuid(p);
 let c;let began=false;let destroy=false;
 try{
 c=await runtimePool.connect();
 await c.query('BEGIN ISOLATION LEVEL READ COMMITTED');began=true;
 await c.query("SET LOCAL statement_timeout = '10000ms'");
 await c.query("SET LOCAL idle_in_transaction_session_timeout = '15000ms'");
 const {tx}=one(await c.query(SQL.tx));
 if(typeof tx!=='string'||!/^[1-9][0-9]{0,19}$/.test(tx))throw unavailable();
 const signed=one(await signerPool.query(SQL.sign,[who.issuer,who.subject,t,p,tx,keyId,who.expiresAt]));
 if(typeof signed.context!=='string'||signed.context.length>2048||typeof signed.signature!=='string'||!/^[a-f0-9]{64}$/.test(signed.signature))throw unavailable();
 await c.query(SQL.claims,[signed.context,signed.signature]);
 const out=await operation(c);
 await c.query('COMMIT');began=false;return out;
 }catch(e){
 if(c&&began){try{await c.query('ROLLBACK');}catch{destroy=true;}}
 // Destroy on uncertain COMMIT / connection failure rather than return dirty connections.
 if(!(e instanceof ServiceError)&&!['42501','23505','22023','22P02','23514'].includes(e?.code))destroy=true;
 throw normalize(e);
 }finally{if(c)c.release(destroy);}
 }
 async function getStatus(b,t,p,u){uuid(u);return scoped(b,t,p,async c=>metadata(one(await c.query(SQL.status,[t,p,u]))));}
 return Object.freeze({
 async project(b,t,p){return scoped(b,t,p,async c=>{const r=await c.query(SQL.project,[t,p]);if(r.rows.length!==1)throw deny();const {id,name,timezone}=r.rows[0];return {id,name,timezone};});},
 async createDocument(b,t,p,body){
 exact(body,['id','title']);uuid(body.id);if(typeof body.title!=='string'||!body.title.trim()||body.title.length>250||body.title.includes('\0'))throw bad();
 return scoped(b,t,p,async c=>({id:one(await c.query(SQL.document,[t,p,body.id,body.title])).id}));
 },
 async requestUpload(b,t,p,d,body){
 uuid(d);exact(body,['id','sha256','bytes','mediaType']);uuid(body.id);
 if(typeof body.sha256!=='string'||!/^[a-f0-9]{64}$/.test(body.sha256)||!Number.isSafeInteger(body.bytes)||body.bytes<1||body.bytes>52428800||!MIME.has(body.mediaType))throw bad();
 return scoped(b,t,p,async c=>({id:one(await c.query(SQL.intent,[t,p,d,body.id,body.sha256,body.bytes,body.mediaType])).id,state:'pending'}));
 },
 async status(b,t,p,u){const m=await getStatus(b,t,p,u);return {id:u,state:m.received?'quarantined':'pending'};},
 async upload(b,t,p,u,body){
 // Reauthorise before writing a single byte. No open DB transaction during streaming.
 const m=await getStatus(b,t,p,u);
 if(m.received)return {id:u,state:'quarantined',replayed:true};
 let receipt;
 try{receipt=await quarantineUpload(quarantineRoot,m,body);}catch{throw new ServiceError(422,'upload_rejected');}
 // Recheck identity, membership, ownership and metadata after receiving bytes.
 // capture_actor holds membership share locks until final commit.
 // Do NOT delete a persisted file on ambiguous database outcomes: reconciliation is required.
 try{return await scoped(b,t,p,async c=>{
 const current=metadata(one(await c.query(SQL.status,[t,p,u])));
 if(current.received)return {id:u,state:'quarantined',replayed:true};
 if(current.sha256!==receipt.sha256||current.bytes!==receipt.bytes||current.mediaType!==receipt.mediaType)throw new ServiceError(409,'intent_changed');
 await workerPool.query(SQL.receipt,[t,p,u,receipt.objectKey,receipt.sha256,receipt.bytes,receipt.mediaType]);
 return {id:u,state:'quarantined',replayed:false};
 });}catch(e){if(e instanceof ServiceError&&e.status===409){const s=await getStatus(b,t,p,u);if(s.received)return {id:u,state:'quarantined',replayed:true};}throw e;}
 }
 });
}
