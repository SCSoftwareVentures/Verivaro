import {assertServiceLogin,validateServiceIdentity} from './service-login.mjs';
import {signDatabaseContext} from './sign-database-context.mjs';
import {createHash,randomUUID} from 'node:crypto';
import {open,link,unlink,lstat} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join,isAbsolute} from 'node:path';
import {isArtifactId} from './private-file-store.mjs';
import {buildProofLockPlan,resolveLocalMilestone} from './prooflock-planner.mjs';
import {buildFinancialSummary} from './financial-intelligence.mjs';
import {buildProjectIntelligence} from './project-intelligence.mjs';
import {verifyTrustProofPage} from './trustproof.mjs';
import {buildProofLockInsights,validateAlertPolicy} from './prooflock-insights.mjs';
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
  }catch(e){if(tx&&e.message!=='Query read timeout')try{await c.query('ROLLBACK');}catch{}
   if(e.code==='42501')throw new ReleaseDenied('release denied');
   if(e.code==='23505')throw new ReleaseConflict('release conflict');
   throw Error('release unavailable');
  }finally{c.release(clean?undefined:new Error('discard release connection'));}
 }
 if(mode==='workflow')return Object.freeze({
  async prepareSubmission({token,tenantId,projectId,submissionId}){return (await run(token,tenantId,'SELECT verivaro_verification.prepare_submission($1,$2,$3) AS data',[tenantId,projectId,submissionId])).data;},
  async reviewSubmission({token,tenantId,projectId,submissionId,sha256,decision,reason}){return (await run(token,tenantId,'SELECT verivaro_verification.review_submission($1,$2,$3,$4,$5,$6) AS ok',[tenantId,projectId,submissionId,sha256,decision,reason])).ok===true;},
  async authorizeSubmission({token,tenantId,projectId,submissionId,sha256}){return (await run(token,tenantId,'SELECT verivaro_verification.authorize_submission($1,$2,$3,$4) AS ok',[tenantId,projectId,submissionId,sha256])).ok===true;},
  async trustproofPage({token,tenantId,projectId,afterSequence,pageSize}){const page=(await run(token,tenantId,'SELECT verivaro_verification.trustproof_page($1,$2,$3,$4) AS data',[tenantId,projectId,afterSequence,pageSize])).data;let verified;try{verified=verifyTrustProofPage(page,page);}catch{throw new ReleaseConflict('audit integrity conflict');}return {...page,verification:verified};},
  async grantCustomerPackage({token,tenantId,projectId,grantId,submissionId,sha256,recipientId,minutes}){return (await run(token,tenantId,'SELECT verivaro_verification.grant_customer_package($1,$2,$3,$4,$5,$6,$7) AS id',[tenantId,projectId,grantId,submissionId,sha256,recipientId,minutes])).id;},
  async revokeCustomerPackage({token,tenantId,projectId,grantId}){return (await run(token,tenantId,'SELECT verivaro_verification.revoke_customer_package($1,$2,$3) AS ok',[tenantId,projectId,grantId])).ok;},
  async previewCustomerPackage({token,tenantId,projectId,grantId}){return (await run(token,tenantId,'SELECT verivaro_verification.preview_customer_package($1,$2,$3) AS data',[tenantId,projectId,grantId])).data;},
  async readCustomerPackage({token,tenantId,projectId,grantId,submissionId,sha256}){return (await run(token,tenantId,'SELECT verivaro_verification.read_customer_package($1,$2,$3,$4,$5) AS data',[tenantId,projectId,grantId,submissionId,sha256])).data;},
  async customerPackageList({token,tenantId,projectId}){return (await run(token,tenantId,'SELECT verivaro_verification.customer_package_list($1,$2) AS data',[tenantId,projectId])).data;},
  async readSubmission({token,tenantId,projectId,submissionId,sha256}){return (await run(token,tenantId,'SELECT verivaro_verification.read_submission($1,$2,$3,$4) AS data',[tenantId,projectId,submissionId,sha256])).data;},
  async listSubmissions({token,tenantId,projectId}){return (await run(token,tenantId,'SELECT verivaro_verification.submission_list($1,$2) AS data',[tenantId,projectId])).data;},
  async inspectSubmission({token,tenantId,projectId,submissionId}){return (await run(token,tenantId,'SELECT verivaro_verification.inspect_submission($1,$2,$3) AS data',[tenantId,projectId,submissionId])).data;},
  async importSourceLine({token,tenantId,projectId,requirementId,versionId,evidenceId,sha256,line,page,quote,quoteSha256,applicability}){return (await run(token,tenantId,'SELECT verivaro_verification.import_source_line($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) AS data',[tenantId,projectId,requirementId,versionId,evidenceId,sha256,line,page,quote,quoteSha256,applicability])).data;},
  async writeRequirement({token,tenantId,projectId,requirementId,versionId,expectedRevision,title,criterion,applicability}){return (await run(token,tenantId,'SELECT verivaro_verification.write_requirement($1,$2,$3,$4,$5,$6,$7,$8) AS data',[tenantId,projectId,requirementId,versionId,expectedRevision,title,criterion,applicability])).data;},
  async reviewRequirement({token,tenantId,projectId,versionId,decision,reason}){return (await run(token,tenantId,'SELECT verivaro_verification.review_requirement($1,$2,$3,$4,$5) AS ok',[tenantId,projectId,versionId,decision,reason])).ok===true;},
  async linkEvidence({token,tenantId,projectId,versionId,linkId,evidenceId,sha256}){return (await run(token,tenantId,'SELECT verivaro_verification.link_evidence($1,$2,$3,$4,$5,$6) AS id',[tenantId,projectId,versionId,linkId,evidenceId,sha256])).id;},
  async reviewLink({token,tenantId,projectId,linkId,decision,reason}){return (await run(token,tenantId,'SELECT verivaro_verification.review_link($1,$2,$3,$4,$5) AS ok',[tenantId,projectId,linkId,decision,reason])).ok===true;},
  async proposeDependency({token,tenantId,projectId,versionId,edgeId,prerequisiteId}){return (await run(token,tenantId,'SELECT verivaro_verification.propose_dependency($1,$2,$3,$4,$5) AS id',[tenantId,projectId,versionId,edgeId,prerequisiteId])).id;},
  async reviewDependency({token,tenantId,projectId,edgeId,decision,reason}){return (await run(token,tenantId,'SELECT verivaro_verification.review_dependency($1,$2,$3,$4,$5) AS ok',[tenantId,projectId,edgeId,decision,reason])).ok===true;},
  async proposeDependencyRemoval({token,tenantId,projectId,versionId,removalId,prerequisiteId,reason}){return (await run(token,tenantId,'SELECT verivaro_verification.propose_dependency_removal($1,$2,$3,$4,$5,$6) AS id',[tenantId,projectId,versionId,removalId,prerequisiteId,reason])).id;},
  async reviewDependencyRemoval({token,tenantId,projectId,removalId,decision,reason}){return (await run(token,tenantId,'SELECT verivaro_verification.review_dependency_removal($1,$2,$3,$4,$5) AS ok',[tenantId,projectId,removalId,decision,reason])).ok===true;},
  async dependencyRemovalCandidates({token,tenantId,projectId}){return (await run(token,tenantId,'SELECT verivaro_verification.dependency_removal_candidates($1,$2) AS data',[tenantId,projectId])).data;},
  async writeMilestone({token,tenantId,projectId,milestoneId,revisionId,expectedRevision,title,confirmed,localTime,timezone,offsetMinutes}){
   if(confirmed===true)resolveLocalMilestone(localTime,timezone,offsetMinutes);
   return (await run(token,tenantId,'SELECT verivaro_verification.write_milestone($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) AS data',[tenantId,projectId,milestoneId,revisionId,expectedRevision,title,confirmed,localTime,timezone,offsetMinutes])).data;
  },
  async proposeEvidenceWindow({token,tenantId,projectId,versionId,windowId,milestoneId,leadMinutes,irreversibility,reason}){return (await run(token,tenantId,'SELECT verivaro_verification.propose_evidence_window($1,$2,$3,$4,$5,$6,$7,$8) AS id',[tenantId,projectId,versionId,windowId,milestoneId,leadMinutes,irreversibility,reason])).id;},
  async reviewEvidenceWindow({token,tenantId,projectId,windowId,decision,reason}){return (await run(token,tenantId,'SELECT verivaro_verification.review_evidence_window($1,$2,$3,$4,$5) AS ok',[tenantId,projectId,windowId,decision,reason])).ok===true;},
  async writeProofLockAlertPolicy({token,tenantId,projectId,policyId,expectedRevision,timezone,quietStart,quietEnd,criticalOverride}){
   validateAlertPolicy({revision:expectedRevision,timezone,quietStart,quietEnd,criticalOverride});
   return (await run(token,tenantId,'SELECT verivaro_verification.write_prooflock_alert_policy($1,$2,$3,$4,$5,$6,$7,$8) AS data',[tenantId,projectId,policyId,expectedRevision,timezone,quietStart,quietEnd,criticalOverride])).data;
  },
  async acknowledgementList({token,tenantId,projectId}){return (await run(token,tenantId,'SELECT verivaro_verification.acknowledgement_list($1,$2) AS data',[tenantId,projectId])).data;},
  async grantAcknowledgement({token,tenantId,projectId,grantId,submissionId,sha256,recipientId,hours}){return (await run(token,tenantId,'SELECT verivaro_verification.grant_acknowledgement($1,$2,$3,$4,$5,$6,$7) AS id',[tenantId,projectId,grantId,submissionId,sha256,recipientId,hours])).id;},
  async revokeAcknowledgement({token,tenantId,projectId,grantId}){return (await run(token,tenantId,'SELECT verivaro_verification.revoke_acknowledgement($1,$2,$3) AS ok',[tenantId,projectId,grantId])).ok;},
  async recordAcknowledgement({token,tenantId,projectId,grantId,eventId,sha256,kind,reason}){return (await run(token,tenantId,'SELECT verivaro_verification.record_acknowledgement($1,$2,$3,$4,$5,$6,$7) AS id',[tenantId,projectId,grantId,eventId,sha256,kind,reason])).id;},
  async resolutionList({token,tenantId,projectId}){return (await run(token,tenantId,'SELECT verivaro_verification.resolution_list($1,$2) AS data',[tenantId,projectId])).data;},
  async assignResolution({token,tenantId,projectId,taskId,versionId,assigneeId,reason}){return (await run(token,tenantId,'SELECT verivaro_verification.assign_resolution($1,$2,$3,$4,$5,$6) AS id',[tenantId,projectId,taskId,versionId,assigneeId,reason])).id;},
  async advanceResolution({token,tenantId,projectId,taskId,eventId,expectedRevision,kind,reason}){return (await run(token,tenantId,'SELECT verivaro_verification.advance_resolution($1,$2,$3,$4,$5,$6,$7) AS ok',[tenantId,projectId,taskId,eventId,expectedRevision,kind,reason])).ok;},
  async recordChronology({token,tenantId,projectId,eventId,submissionId,submissionSha256,type,description,assertedAt,sourceEvidenceId,sourceSha256}){return (await run(token,tenantId,'SELECT verivaro_verification.record_chronology($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) AS id',[tenantId,projectId,eventId,submissionId,submissionSha256,type,description,assertedAt,sourceEvidenceId,sourceSha256])).id;},
  async reviewChronology({token,tenantId,projectId,eventId,decision,reason}){return (await run(token,tenantId,'SELECT verivaro_verification.review_chronology($1,$2,$3,$4,$5) AS ok',[tenantId,projectId,eventId,decision,reason])).ok===true;},
  async projectIntelligence({token,tenantId,projectId}){const d=(await run(token,tenantId,'SELECT verivaro_verification.project_archive_records($1,$2) AS data',[tenantId,projectId])).data;return buildProjectIntelligence(d);},
  async writeFinancialRecord({token,tenantId,projectId,recordId,versionId,expectedRevision,reference,kind,title,currency,taxBasis,amount,dueAt,sourceEvidenceId,sourceSha256,conditionVersions}){return (await run(token,tenantId,'SELECT verivaro_verification.write_financial_record($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::uuid[]) AS data',[tenantId,projectId,recordId,versionId,expectedRevision,reference,kind,title,currency,taxBasis,amount,dueAt,sourceEvidenceId,sourceSha256,conditionVersions])).data;},
  async reviewFinancialRecord({token,tenantId,projectId,versionId,decision,reason}){return (await run(token,tenantId,'SELECT verivaro_verification.review_financial_record($1,$2,$3,$4,$5) AS ok',[tenantId,projectId,versionId,decision,reason])).ok===true;},
  async financialSummary({token,tenantId,projectId}){const d=(await run(token,tenantId,'SELECT verivaro_verification.financial_records($1,$2) AS data',[tenantId,projectId])).data;return {...d,summary:buildFinancialSummary(d)};},
  async proposeRecovery({token,tenantId,projectId,recoveryId,windowId,revisionId,versionId,evidenceId,sha256,approach,reason}){return (await run(token,tenantId,'SELECT verivaro_verification.propose_recovery($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) AS id',[tenantId,projectId,recoveryId,windowId,revisionId,versionId,evidenceId,sha256,approach,reason])).id;},
  async reviewRecovery({token,tenantId,projectId,recoveryId,decision,reason}){return (await run(token,tenantId,'SELECT verivaro_verification.review_recovery($1,$2,$3,$4,$5) AS ok',[tenantId,projectId,recoveryId,decision,reason])).ok===true;},
  async proofLock({token,tenantId,projectId}){
   const data=(await run(token,tenantId,'SELECT verivaro_verification.prooflock_recovery_records($1,$2) AS data',[tenantId,projectId])).data;
   return {...data,plan:buildProofLockPlan(data),insights:buildProofLockInsights(data)};
  },
  async assessment({token,tenantId,projectId}){return (await run(token,tenantId,'SELECT verivaro_verification.assessment($1,$2) AS data',[tenantId,projectId])).data;},
  async archiveProject({token,tenantId,projectId,requestId,revision}){return (await run(token,tenantId,'SELECT verivaro_mutation.archive_project($1,$2,$3,$4) AS data',[tenantId,projectId,requestId,revision])).data;},
  async report({token,tenantId,projectId}){return (await run(token,tenantId,'SELECT verivaro_mutation.project_report($1,$2) AS data',[tenantId,projectId])).data;},
  async createProject({token,tenantId,requestId,name}){return (await run(token,tenantId,'SELECT verivaro_mutation.create_project($1,$2,$3) AS id',[tenantId,requestId,name])).id;},
  async directory({token,tenantId,projectId}){return (await run(token,tenantId,'SELECT verivaro_mutation.project_directory($1,$2) AS data',[tenantId,projectId])).data;},
  async changeAccess({token,tenantId,projectId,requestId,targetId,role,generation}){return (await run(token,tenantId,'SELECT verivaro_mutation.change_project_access($1,$2,$3,$4,$5,$6) AS generation',[tenantId,projectId,requestId,targetId,role,generation])).generation;},
  async shares({token,tenantId,projectId}){return (await run(token,tenantId,'SELECT verivaro_sharing.workspace_shares($1,$2) AS data',[tenantId,projectId])).data;},
  async createShare({token,tenantId,projectId,exportId,shareId,digest,recipientId}){return (await run(token,tenantId,'SELECT verivaro_sharing.workspace_issue_recipient($1,$2,$3,$4,$5,$6) AS expiry',[tenantId,projectId,exportId,shareId,digest,recipientId])).expiry;},
  async revokeRecipient({token,tenantId,projectId,shareId}){return (await run(token,tenantId,'SELECT verivaro_sharing.workspace_revoke_recipient($1,$2,$3) AS ok',[tenantId,projectId,shareId])).ok===true;},
  async tenants({token}){return (await run(token,'00000000-0000-0000-0000-000000000000','SELECT verivaro_sharing.workspace_tenants() AS data',[])).data;},
  async workspace({token,tenantId,projectId}){return (await run(token,tenantId,'SELECT verivaro_sharing.release_workspace($1,$2) AS data',[tenantId,projectId])).data;},
  async request({token,tenantId,projectId,evidenceId,requestId,sha256}){return (await run(token,tenantId,'SELECT verivaro_sharing.request_evidence_release($1,$2,$3,$4,$5) AS id',[tenantId,projectId,evidenceId,requestId,sha256])).id;},
  async issueRecipient({token,tenantId,exportId,shareId,digest,expiry,recipientId}){await run(token,tenantId,'SELECT verivaro_sharing.issue_recipient_share($1,$2,$3,$4,$5) AS ok',[exportId,shareId,digest,expiry,recipientId]);return shareId;},
  async review({token,tenantId,projectId,requestId,sha256,decision,reason}){return (await run(token,tenantId,'SELECT verivaro_sharing.review_evidence_release($1,$2,$3,$4,$5,$6) AS ok',[tenantId,projectId,requestId,sha256,decision,reason])).ok===true;}
 });
 return Object.freeze({
  async preflight({token,tenantId,projectId,requestId,evidenceId,sha256}){return (await run(token,tenantId,'SELECT verivaro_sharing.preflight_approved_export($1,$2,$3,$4,$5) AS ok',[tenantId,projectId,requestId,evidenceId,sha256])).ok===true;},
  async publish({token,tenantId,projectId,requestId,evidenceId,sha256}){return (await run(token,tenantId,'SELECT verivaro_sharing.register_approved_export($1,$2,$3,$4,$5) AS id',[tenantId,projectId,requestId,evidenceId,sha256])).id;}
 });
}

// Store only verified bytes, under a private dedicated directory on an
// encrypted volume. A filesystem failure never registers an export.
// A failed database commit can leave an inaccessible orphan, never a share.
export function createEvidencePublisher({root,retrieve,release}){
 if(typeof root!=='string'||!isAbsolute(root)||typeof retrieve!=='function'||typeof release?.publish!=='function'||typeof release?.preflight!=='function')throw Error('invalid release publisher');
 async function verifyExisting(path,expected){
  const handle=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{
   const s=await handle.stat();
   if(!s.isFile()||(s.mode&0o077)!==0||s.size!==expected.length||(typeof process.getuid==='function'&&s.uid!==process.getuid()))throw Error('unsafe export file');
   const b=await handle.readFile();try{if(!b.equals(expected))throw Error('export content mismatch');}finally{b.fill(0);}
  }finally{await handle.close();}
 }
 return async function publish(input,{signal}){
  if(!isArtifactId(input.evidenceId)||!isArtifactId(input.requestId)||!hash.test(input.sha256))throw Error('invalid release input');
  signal.throwIfAborted();
  const s=await lstat(root);if(!s.isDirectory()||(s.mode&0o077)!==0||(typeof process.getuid==='function'&&s.uid!==process.getuid()))throw Error('unsafe export root');
  if(!await release.preflight(input))throw new ReleaseDenied('release denied');
  signal.throwIfAborted();
  const evidence=await retrieve(input);let temporary;
  try{
   if(!Buffer.isBuffer(evidence.data)||evidence.data.length<1||evidence.data.length>262144||evidence.sha256!==input.sha256||createHash('sha256').update(evidence.data).digest('hex')!==input.sha256)throw Error('release content mismatch');
   signal.throwIfAborted();
   temporary=join(root,'.release-'+randomUUID());
   const handle=await open(temporary,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY|constants.O_NOFOLLOW,0o600);
   try{await handle.writeFile(evidence.data);await handle.sync();}finally{await handle.close();}
   const destination=join(root,input.evidenceId);
   try{await link(temporary,destination);}catch(e){if(e.code!=='EEXIST')throw e;await verifyExisting(destination,evidence.data);}
   await unlink(temporary);temporary=undefined;
   const directory=await open(root,constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);
   try{await directory.sync();}finally{await directory.close();}
   signal.throwIfAborted();
   return await release.publish(input);
  }finally{evidence?.data?.fill(0);if(temporary)await unlink(temporary).catch(()=>{});}
 };
}
