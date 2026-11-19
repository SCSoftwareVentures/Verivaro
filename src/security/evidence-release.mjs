import {assertServiceLogin,validateServiceIdentity} from './service-login.mjs';
import {signDatabaseContext} from './sign-database-context.mjs';
import {createHash,randomUUID} from 'node:crypto';
import {open,link,unlink,stat} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join,isAbsolute} from 'node:path';
import {isArtifactId} from './private-file-store.mjs';
const hash=/^[a-f0-9]{64}$/;
export class ReleaseDenied extends Error{}
export class ReleaseConflict extends Error{}
export function createEvidenceReleaseDatabase(pool,{expectedLogin,verifier,contextKey,mode}){
 const role=mode==='workflow'?'verivaro_runtime':mode==='publish'?'verivaro_release_service':null;
 validateServiceIdentity(role,expectedLogin);
 if(typeof pool?.connect!=='function'||!verifier||!Buffer.isBuffer(contextKey)||contextKey.length!==32)throw Error('invalid release database');
 const key=Buffer.from(contextKey);
 async function run(token,tenantId,sql,values){
  const c=await pool.connect();let tx=false,clean=false;
  try{
   await c.query('DISCARD ALL');await assertServiceLogin(c,role,expectedLogin);await c.query('SET ROLE '+role);
   await c.query('BEGIN ISOLATION LEVEL READ COMMITTED');tx=true;
   await c.query("SET LOCAL statement_timeout='5s'");await c.query("SET LOCAL lock_timeout='2s'");await c.query("SET LOCAL idle_in_transaction_session_timeout='10s'");
   const challenge=(await c.query('SELECT pg_backend_pid() AS pid, pg_current_xact_id()::text AS xid')).rows[0];
   await c.query("SELECT set_config('verivaro.signed_context',$1,true)",[signDatabaseContext({token,tenantId,challenge},{verifier,key})]);
   const r=await c.query(sql,values);if(r.rows.length!==1)throw Error('invalid release result');
   await c.query('COMMIT');tx=false;await c.query('DISCARD ALL');clean=true;return r.rows[0];
  }catch(e){if(tx)try{await c.query('ROLLBACK');}catch{}
   if(e.code==='42501')throw new ReleaseDenied('release denied');
   if(e.code==='23505')throw new ReleaseConflict('release conflict');
   throw Error('release unavailable');
  }finally{c.release(clean?undefined:new Error('discard release connection'));}
 }
 if(mode==='workflow')return Object.freeze({
  async request({token,tenantId,projectId,evidenceId,requestId,sha256}){return (await run(token,tenantId,'SELECT verivaro_sharing.request_evidence_release($1,$2,$3,$4,$5) AS id',[tenantId,projectId,evidenceId,requestId,sha256])).id;},
  async review({token,tenantId,projectId,requestId,sha256,decision,reason}){return (await run(token,tenantId,'SELECT verivaro_sharing.review_evidence_release($1,$2,$3,$4,$5,$6) AS ok',[tenantId,projectId,requestId,sha256,decision,reason])).ok===true;}
 });
 return Object.freeze({
  async publish({token,tenantId,projectId,requestId,sha256}){return (await run(token,tenantId,'SELECT verivaro_sharing.register_approved_export($1,$2,$3,$4) AS id',[tenantId,projectId,requestId,sha256])).id;}
 });
}
