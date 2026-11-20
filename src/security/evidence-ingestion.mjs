import {assertServiceLogin,validateServiceIdentity} from './service-login.mjs';
import {signDatabaseContext} from './sign-database-context.mjs';
import {validateEvidence,sealEvidence,openEvidence} from './evidence-objects.mjs';
const role='verivaro_evidence_ingestor';
export class IngestionDenied extends Error{}
export class IngestionConflict extends Error{}
export class IngestionRejected extends Error{}
export class IngestionQuota extends Error{}
export function createIngestionDatabase(pool,{expectedLogin,verifier,contextKey}){
 validateServiceIdentity(role,expectedLogin);
 if(typeof pool?.connect!=='function'||!verifier||!Buffer.isBuffer(contextKey)||contextKey.length!==32)throw Error('invalid ingestion database');
 const key=Buffer.from(contextKey);
 async function run(token,tenantId,sql,values){
  const c=await pool.connect();let tx=false,clean=false;
  try{
   await c.query('DISCARD ALL');await assertServiceLogin(c,role,expectedLogin);await c.query('SET ROLE '+role);
   await c.query('BEGIN ISOLATION LEVEL READ COMMITTED');tx=true;
   await c.query("SET LOCAL statement_timeout='5s'");await c.query("SET LOCAL lock_timeout='2s'");await c.query("SET LOCAL idle_in_transaction_session_timeout='10s'");
   const r=await c.query('SELECT pg_backend_pid() AS pid, pg_current_xact_id()::text AS xid');
   const context=signDatabaseContext({token,tenantId,challenge:r.rows[0]},{verifier,key});
   await c.query("SELECT set_config('verivaro.signed_context',$1,true)",[context]);
   const result=await c.query(sql,values);
   if(result.rows.length!==1)throw Error('invalid ingestion result');
   await c.query('COMMIT');tx=false;await c.query('DISCARD ALL');clean=true;return result.rows[0];
  }catch(e){if(tx)try{await c.query('ROLLBACK');}catch{}
   if(e.code==='42501')throw new IngestionDenied('ingestion denied');
   if(e.code==='23505')throw new IngestionConflict('ingestion conflict');
   if(e.code==='54000')throw new IngestionQuota('evidence storage quota exhausted');
   throw Error('ingestion unavailable');
  }finally{c.release(clean?undefined:new Error('discard ingestion lease'));}
 }
 return Object.freeze({
  async authorizeCapture({token,tenantId,projectId,requestId,capture:{windowId,versionId,milestoneRevisionId}}){return (await run(token,tenantId,'SELECT verivaro_ingestion.authorize_capture($1,$2,$3,$4,$5,$6) AS ok',[tenantId,projectId,windowId,versionId,milestoneRevisionId,requestId])).ok===true;},
  async commitCapture({token,tenantId,projectId,requestId,object,capture:{windowId,versionId,milestoneRevisionId}}){return run(token,tenantId,'SELECT * FROM verivaro_ingestion.commit_capture($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)',[tenantId,projectId,requestId,object.id,object.sha256,object.bytes,object.keyId,object.envelope,object.mediaType,windowId,versionId,milestoneRevisionId]);},
  async authorize({token,tenantId,projectId}){return (await run(token,tenantId,'SELECT verivaro_ingestion.authorize_upload($1,$2) AS ok',[tenantId,projectId])).ok===true;},
  async commit({token,tenantId,projectId,requestId,object}){return run(token,tenantId,'SELECT * FROM verivaro_ingestion.commit_upload_v2($1,$2,$3,$4,$5,$6,$7,$8,$9)',[tenantId,projectId,requestId,object.id,object.sha256,object.bytes,object.keyId,object.envelope,object.mediaType]);}
 });
}
export function createEvidenceIngestion({db,scan,key,keyId,maxConcurrent=4}){
 if(typeof db?.authorize!=='function'||typeof db?.commit!=='function'||typeof scan!=='function'||!Buffer.isBuffer(key)||key.length!==32||!/^[a-z][a-z0-9_-]{0,31}$/.test(keyId)||!Number.isInteger(maxConcurrent)||maxConcurrent<1||maxConcurrent>8)throw Error('invalid evidence ingestion');
 const secret=Buffer.from(key);let active=0;
 return async function ingest({data,token,tenantId,projectId,requestId,signal,capture,mediaType='text/plain; charset=utf-8'}){
  if(active>=maxConcurrent)throw Error('ingestion busy');active++;
  let clear,object;
  try{
   signal.throwIfAborted();
   try{validateEvidence(data,mediaType);}catch{throw new IngestionRejected('invalid evidence');}
   if(capture){if(typeof db.authorizeCapture!=='function'||typeof db.commitCapture!=='function'||!await db.authorizeCapture({token,tenantId,projectId,requestId,capture}))throw new IngestionDenied('capture denied');}
   else if(!await db.authorize({token,tenantId,projectId}))throw new IngestionDenied('ingestion denied');
   // Quarantined only in memory; no named plaintext file or rejected payload retained.
   object=sealEvidence(data,{tenantId,projectId,key:secret,keyId,mediaType});
   clear=openEvidence(object,secret);
   const verdict=await scan(clear,signal);
   if(verdict==='infected')throw new IngestionRejected('evidence rejected');
   if(verdict!=='clean')throw Error('scanner unavailable');
   signal.throwIfAborted();
   return capture?await db.commitCapture({token,tenantId,projectId,requestId,object,capture}):await db.commit({token,tenantId,projectId,requestId,object});
  }finally{clear?.fill(0);object?.envelope.fill(0);active--;}
 };
}
