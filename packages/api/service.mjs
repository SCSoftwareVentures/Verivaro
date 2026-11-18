import {verifyAccessToken} from '../security/oidc.mjs';
import {quarantineUpload} from '../security/quarantine.mjs';
import {proposeRequirements,suggestMatches} from '../domain/proposals.mjs';
import {evaluateGraph,reviewDigest} from '../domain/graph.mjs';
import {evaluateWorkspace,handoverManifest} from '../domain/workspace.mjs';
import {evaluateFinance,disputePack} from '../domain/finance.mjs';
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
function normalize(e){if(e instanceof ServiceError)return e;if(e?.code==='42501')return deny();if(e?.code==='23505')return new ServiceError(409,'idempotency_conflict');if(['22023','22P02','23514','22007','22008'].includes(e?.code))return bad();return unavailable();}
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
 reviewPages:'SELECT * FROM vv_api.review_pages($1,$2,$3)',
 decision:'SELECT vv_api.decide_requirement($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) AS id',
 promoteDoc:'SELECT vv_api.promote_document($1,$2,$3,$4,$5,$6,$7) AS id',
 promoteReq:'SELECT vv_api.promote_requirement($1,$2,$3,$4,$5,$6,$7) AS id',
 linkEvidence:'SELECT vv_api.link_evidence($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) AS id',
 retireEvidence:'SELECT vv_api.retire_evidence($1,$2,$3,$4) AS id',
 confirmScope:'SELECT vv_api.confirm_scope($1,$2,$3) AS generation',
 workspace:'SELECT vv_api.workspace($1,$2) AS workspace',
 milestone:'SELECT vv_api.save_prooflock($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) AS revision',
 rejection:'SELECT vv_api.save_rejection($1,$2,$3,$4,$5,$6,$7) AS revision',
 createHandover:'SELECT vv_api.create_handover($1,$2,$3,$4) AS id',
 readHandover:'SELECT vv_api.read_handover($1,$2,$3) AS draft',
 financial:'SELECT vv_api.financial_workspace($1,$2) AS financial',
 financeWrite:'SELECT vv_api.save_finance($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17::uuid[]) AS revision',
 disputeWrite:'SELECT vv_api.record_dispute($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) AS id',
 graph:'SELECT vv_api.graph($1,$2) AS graph',
 reserve:'SELECT vv_api.reserve_file($1,$2,$3,$4) AS id',
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
 async reviewDraft(b,t,p,u){uuid(u);return scoped(b,t,p,async c=>{const {rows}=await c.query(SQL.reviewPages,[t,p,u]);return {pages:rows,textDigest:reviewDigest(rows),...proposeRequirements(rows)};});},
 async matchDraft(b,t,p,u,body){uuid(u);exact(body,['expected']);if(typeof body.expected!=='string'||!body.expected.trim()||body.expected.length>500)throw bad();return scoped(b,t,p,async c=>suggestMatches((await c.query(SQL.reviewPages,[t,p,u])).rows,body.expected));},
 async decideRequirement(b,t,p,u,body){
 uuid(u);exact(body,['id','page','start','end','quote','textSha256','decision','kind','expected','mandatory']);uuid(body.id);
 if(!Number.isSafeInteger(body.page)||body.page<1||body.page>20||!Number.isSafeInteger(body.start)||!Number.isSafeInteger(body.end)||body.start<0||body.end<=body.start||body.end-body.start>2000||typeof body.quote!=='string'||typeof body.textSha256!=='string'||!/^[a-f0-9]{64}$/.test(body.textSha256)||!['approved','rejected'].includes(body.decision))throw bad();
 if(body.decision==='approved'&&(typeof body.kind!=='string'||typeof body.expected!=='string'||typeof body.mandatory!=='boolean'))throw bad();
 if(body.decision==='rejected'&&(body.kind!==null||body.expected!==null||body.mandatory!==null))throw bad();
 return scoped(b,t,p,async c=>({id:one(await c.query(SQL.decision,[t,p,u,body.id,body.page,body.start,body.end,body.quote,body.textSha256,body.decision,body.kind,body.expected,body.mandatory])).id,state:body.decision+'-proposal'}));
 },
 async promoteDocument(b,t,p,u,body){
 uuid(u);exact(body,['id','priorRevision','sourceSha256','textDigest']);uuid(body.id);
 if(!Number.isSafeInteger(body.priorRevision)||body.priorRevision<0||body.priorRevision>=2147483647||![body.sourceSha256,body.textDigest].every(x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x)))throw bad();
 return scoped(b,t,p,async c=>({id:one(await c.query(SQL.promoteDoc,[t,p,u,body.id,body.priorRevision,body.sourceSha256,body.textDigest])).id}));
 },
 async promoteRequirement(b,t,p,d,body){
 uuid(d);exact(body,['requirementId','versionId','priorRevision','spanId']);[body.requirementId,body.versionId,body.spanId].forEach(uuid);
 if(!Number.isSafeInteger(body.priorRevision)||body.priorRevision<0||body.priorRevision>=2147483647)throw bad();
 return scoped(b,t,p,async c=>({id:one(await c.query(SQL.promoteReq,[t,p,d,body.requirementId,body.versionId,body.priorRevision,body.spanId])).id}));
 },
 async linkEvidence(b,t,p,body){
 exact(body,['id','requirementVersionId','spanId','documentVersionId','page','start','end','quote','textSha256','decision']);[body.id,body.requirementVersionId,body.spanId,body.documentVersionId].forEach(uuid);
 if(!Number.isSafeInteger(body.page)||body.page<1||body.page>20||!Number.isSafeInteger(body.start)||!Number.isSafeInteger(body.end)||body.start<0||body.end<=body.start||body.end-body.start>500||typeof body.quote!=='string'||typeof body.textSha256!=='string'||!/^[a-f0-9]{64}$/.test(body.textSha256)||!['approved','rejected'].includes(body.decision))throw bad();
 return scoped(b,t,p,async c=>({id:one(await c.query(SQL.linkEvidence,[t,p,body.id,body.requirementVersionId,body.spanId,body.documentVersionId,body.page,body.start,body.end,body.quote,body.textSha256,body.decision])).id}));
 },
 async retireEvidence(b,t,p,e,body){uuid(e);exact(body,['reason']);if(typeof body.reason!=='string'||!body.reason.trim()||body.reason.length>500)throw bad();return scoped(b,t,p,async c=>({id:one(await c.query(SQL.retireEvidence,[t,p,e,body.reason])).id}));},
 async readiness(b,t,p){return scoped(b,t,p,async c=>evaluateWorkspace({tenantId:t,projectId:p},one(await c.query(SQL.workspace,[t,p])).workspace));},
 async saveMilestone(b,t,p,body){
 exact(body,['id','priorRevision','requirementVersionId','title','milestone','confirmed','leadMinutes','irreversibility']);uuid(body.id);uuid(body.requirementVersionId);
 if(!Number.isSafeInteger(body.priorRevision)||body.priorRevision<0||body.priorRevision>=2147483647||typeof body.title!=='string'||!body.title.trim()||body.title.length>200||typeof body.confirmed!=='boolean'||!Number.isSafeInteger(body.leadMinutes)||body.leadMinutes<0||body.leadMinutes>525600||!['reversible','costly','irreversible'].includes(body.irreversibility))throw bad();
 if(body.confirmed){if(typeof body.milestone!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(body.milestone)||!Number.isFinite(Date.parse(body.milestone))||new Date(body.milestone).toISOString()!==body.milestone)throw bad();}else if(body.milestone!==null)throw bad();
 return scoped(b,t,p,async c=>({id:body.id,revision:one(await c.query(SQL.milestone,[t,p,body.id,body.priorRevision,body.requirementVersionId,body.title,body.milestone,body.confirmed,body.leadMinutes,body.irreversibility])).revision}));
 },
 async saveRejection(b,t,p,body){
 exact(body,['id','priorRevision','requirementVersionId','state','note']);uuid(body.id);uuid(body.requirementVersionId);
 if(!Number.isSafeInteger(body.priorRevision)||body.priorRevision<0||body.priorRevision>=2147483647||!['open','resolution-recorded'].includes(body.state)||typeof body.note!=='string'||!body.note.trim()||body.note.length>1000)throw bad();
 return scoped(b,t,p,async c=>({id:body.id,revision:one(await c.query(SQL.rejection,[t,p,body.id,body.priorRevision,body.requirementVersionId,body.state,body.note])).revision}));
 },
 async createHandover(b,t,p,body){
 exact(body,['id','generation']);uuid(body.id);if(typeof body.generation!=='string'||!/^\d{1,18}$/.test(body.generation))throw bad();
 return scoped(b,t,p,async c=>{await c.query(SQL.createHandover,[t,p,body.id,body.generation]);return handoverManifest({tenantId:t,projectId:p},one(await c.query(SQL.readHandover,[t,p,body.id])).draft);});
 },
 async readHandover(b,t,p,h){uuid(h);return scoped(b,t,p,async c=>handoverManifest({tenantId:t,projectId:p},one(await c.query(SQL.readHandover,[t,p,h])).draft));},
 async financial(b,t,p){return scoped(b,t,p,async c=>evaluateFinance({tenantId:t,projectId:p},one(await c.query(SQL.financial,[t,p])).financial));},
 async saveFinance(b,t,p,body){
 exact(body,['id','priorRevision','category','title','amount','taxBasis','spanId','documentVersionId','page','start','end','quote','textSha256','releaseOn','conditionVersionIds']);
 [body.id,body.spanId,body.documentVersionId].forEach(uuid);
 if(!Number.isSafeInteger(body.priorRevision)||body.priorRevision<0||body.priorRevision>=2147483647||!['milestone','retention'].includes(body.category)||typeof body.title!=='string'||!body.title.trim()||body.title.length>200||typeof body.amount!=='string'||!/^(0|[1-9]\d{0,11})\.\d{2}$/.test(body.amount)||!['inclusive','exclusive'].includes(body.taxBasis)||body.quote!=='AUD '+body.amount||!Number.isSafeInteger(body.page)||body.page<1||body.page>20||!Number.isSafeInteger(body.start)||!Number.isSafeInteger(body.end)||body.start<0||body.end-body.start!==body.quote.length||typeof body.textSha256!=='string'||!/^[a-f0-9]{64}$/.test(body.textSha256)||!Array.isArray(body.conditionVersionIds)||body.conditionVersionIds.length>100||new Set(body.conditionVersionIds).size!==body.conditionVersionIds.length)throw bad();
 body.conditionVersionIds.forEach(uuid);
 if(body.releaseOn!==null){if(body.category!=='retention'||typeof body.releaseOn!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(body.releaseOn)||!Number.isFinite(Date.parse(body.releaseOn))||new Date(body.releaseOn).toISOString().slice(0,10)!==body.releaseOn)throw bad();}
 return scoped(b,t,p,async c=>({id:body.id,revision:one(await c.query(SQL.financeWrite,[t,p,body.id,body.priorRevision,body.category,body.title,body.amount,body.taxBasis,body.spanId,body.documentVersionId,body.page,body.start,body.end,body.quote,body.textSha256,body.releaseOn,body.conditionVersionIds])).revision}));
 },
 async recordDispute(b,t,p,body){
 exact(body,['id','financeId','financeRevision','type','occurredAt','note','documentVersionId','handoverId']);[body.id,body.financeId].forEach(uuid);
 if(body.documentVersionId!==null)uuid(body.documentVersionId);if(body.handoverId!==null)uuid(body.handoverId);
 if(!Number.isSafeInteger(body.financeRevision)||body.financeRevision<1||body.financeRevision>=2147483647||!['submission-asserted','delivery-asserted','receipt-asserted','acceptance-asserted','rejection-asserted','disputed','correction','payment-asserted','note'].includes(body.type)||typeof body.note!=='string'||!body.note.trim()||body.note.length>2000)throw bad();
 if(body.occurredAt!==null&&(typeof body.occurredAt!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(body.occurredAt)||!Number.isFinite(Date.parse(body.occurredAt))||new Date(body.occurredAt).toISOString()!==body.occurredAt))throw bad();
 return scoped(b,t,p,async c=>({id:one(await c.query(SQL.disputeWrite,[t,p,body.id,body.financeId,body.financeRevision,body.type,body.occurredAt,body.note,body.documentVersionId,body.handoverId])).id,verification:'member-asserted'}));
 },
 async disputePack(b,t,p,f){uuid(f);return scoped(b,t,p,async c=>{const scope={tenantId:t,projectId:p};const finance=evaluateFinance(scope,one(await c.query(SQL.financial,[t,p])).financial);const pack=disputePack(scope,finance,f);if(!pack)throw deny();return pack;});},
 async confirmScope(b,t,p,body){exact(body,['generation']);if(typeof body.generation!=='string'||!/^\d{1,18}$/.test(body.generation))throw bad();return scoped(b,t,p,async c=>({generation:one(await c.query(SQL.confirmScope,[t,p,body.generation])).generation}));},
 async status(b,t,p,u){const m=await getStatus(b,t,p,u);return {id:u,state:m.received?'quarantined':'pending'};},
 async upload(b,t,p,u,body){
 // Reauthorise before writing a single byte. No open DB transaction during streaming.
 uuid(u);const key=randomUUID();
 const m=await scoped(b,t,p,async c=>{const m=metadata(one(await c.query(SQL.status,[t,p,u])));if(!m.received)await c.query(SQL.reserve,[t,p,u,key]);return m;});
 if(m.received)return {id:u,state:'quarantined',replayed:true};
 let receipt;
 try{receipt=await quarantineUpload(quarantineRoot,m,body,{objectKey:key});}catch{throw new ServiceError(422,'upload_rejected');}
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
