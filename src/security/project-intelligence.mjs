import {buildRejectionPreflight} from './rejection-preflight.mjs';
import {buildFinancialSummary} from './financial-intelligence.mjs';
import {buildProofLockPlan} from './prooflock-planner.mjs';
const uid=x=>typeof x==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(x);
const hash=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const date=x=>typeof x==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(x)&&Number.isFinite(Date.parse(x))&&new Date(x).toISOString()===x;
const fail=()=>{throw Error('invalid project intelligence records');};
const eventTypes=['submission_asserted','delivery_asserted','receipt_asserted','acceptance_asserted','rejection_asserted','dispute_asserted','response_asserted','correspondence','correction_asserted'];
const urgency={critical:0,high:1,soon:2,clarify:3,routine:4,review:5};
const effort={INTEGRITY_FAILURE:'specialist_investigation',DEPENDENCY_BLOCKED:'dependency_rework',CONFLICTING_EVIDENCE:'independent_reassessment',FAILED_EVIDENCE:'correction_and_review',RULE_REJECTED:'revision_and_review',UNKNOWN_APPLICABILITY:'source_clarification',RULE_REVIEW_REQUIRED:'independent_review',EVIDENCE_REVIEW_REQUIRED:'independent_review',MISSING_EVIDENCE:'capture_and_review'};
const effortRank={'independent_review':0,'source_clarification':1,'capture_and_review':2,'revision_and_review':3,'independent_reassessment':4,'correction_and_review':5,'dependency_rework':6,'specialist_investigation':7};
export function rankDeficiencies(assessment,plan,financial){
 const pre=buildRejectionPreflight(assessment),reqs=new Map(assessment.requirements.map(q=>[q.requirementId,q])),priorities=new Map();
 for(const t of plan.tasks){if(['verified_now','stale_rule'].includes(t.status))continue;const old=priorities.get(t.requirementId);if(!old||urgency[t.urgency]<urgency[old.urgency])priorities.set(t.requirementId,t);}
 return pre.issues.map(issue=>{
  const q=reqs.get(issue.requirementId),t=priorities.get(issue.requirementId),related=financial.entries.filter(r=>r.decision==='approved'&&r.sourceIntact&&r.amountMinor!==null&&r.conditions.some(c=>c.requirementId===q.requirementId&&c.versionId===q.versionId&&c.status==='blocked')).map(r=>({recordId:r.recordId,kind:r.kind,currency:r.currency,taxBasis:r.taxBasis,amountMinor:r.amountMinor}));
  const repair=effort[issue.code];if(!repair)fail();
  return {...issue,title:q.title,versionId:q.versionId,urgency:t?.urgency??'routine',deadline:t?.deadline??null,financialReferences:related,repairCategory:repair};
 }).sort((a,b)=>Number(b.level==='blocker')-Number(a.level==='blocker')||urgency[a.urgency]-urgency[b.urgency]||Number(b.financialReferences.length>0)-Number(a.financialReferences.length>0)||a.rank-b.rank||effortRank[a.repairCategory]-effortRank[b.repairCategory]||a.requirementId.localeCompare(b.requirementId));
}
export function buildProjectIntelligence(d){
 if(!d||!uid(d.scope?.tenantId)||!uid(d.scope?.projectId)||!date(d.asOf)||!Array.isArray(d.events)||d.events.length>128||!Array.isArray(d.submissions)||d.submissions.length>256||d.financial?.asOf!==d.asOf||d.prooflock?.asOf!==d.asOf)fail();
 for(const part of [d.financial,d.prooflock])if(part.scope.tenantId!==d.scope.tenantId||part.scope.projectId!==d.scope.projectId)fail();
 const financial=buildFinancialSummary(d.financial),plan=buildProofLockPlan(d.prooflock),submissions=new Map(),seen=new Set(),timeline=[];
 for(const s of d.submissions){
  if(!uid(s.submissionId)||submissions.has(s.submissionId)||!hash(s.sha256)||!date(s.preparedAt)||typeof s.manifestIntact!=='boolean'||![null,'approved','rejected'].includes(s.decision)||(s.reviewedAt!==null&&!date(s.reviewedAt))||(s.authorizedAt!==null&&!date(s.authorizedAt)))fail();
  submissions.set(s.submissionId,s);
  timeline.push({type:'snapshot_prepared',at:s.preparedAt,submissionId:s.submissionId,sha256:s.sha256,classification:'system_recorded',manifestIntact:s.manifestIntact});
  if(s.reviewedAt)timeline.push({type:'snapshot_reviewed',at:s.reviewedAt,submissionId:s.submissionId,sha256:s.sha256,decision:s.decision,reason:s.reason,classification:'system_recorded'});
  if(s.authorizedAt)timeline.push({type:'export_authorized',at:s.authorizedAt,submissionId:s.submissionId,sha256:s.sha256,classification:'system_recorded'});
 }
 for(const e of d.events){
  const s=submissions.get(e.submissionId);
  if(!uid(e.eventId)||seen.has(e.eventId)||!eventTypes.includes(e.type)||typeof e.description!=='string'||!e.description.length||e.description.length>2048||!date(e.recordedAt)||(e.assertedAt!==null&&(!date(e.assertedAt)||e.assertedAt>e.recordedAt))||!uid(e.sourceEvidenceId)||!hash(e.sourceSha256)||typeof e.sourceIntact!=='boolean'||!['pending','source_supports','source_does_not_support','inconclusive'].includes(e.decision)||(e.submissionId!==null&&(!s||s.sha256!==e.submissionSha256))||(e.submissionId===null&&e.submissionSha256!==null))fail();
  seen.add(e.eventId);
  timeline.push({...e,at:e.assertedAt??e.recordedAt,timeBasis:e.assertedAt===null?'recorded_time_only':'asserted_event_time',classification:!e.sourceIntact?'source_integrity_failure':e.decision==='source_supports'?'independently_reviewed_source_support':e.decision==='source_does_not_support'?'reviewed_source_does_not_support':e.decision==='inconclusive'?'review_inconclusive':'unreviewed_assertion'});
 }
 const conflictHints=[];
 for(const s of submissions.values()){
  const events=d.events.filter(e=>e.submissionId===s.submissionId),accepts=events.filter(e=>e.type==='acceptance_asserted'),rejects=events.filter(e=>e.type==='rejection_asserted');
  if(accepts.length&&rejects.length)conflictHints.push({submissionId:s.submissionId,eventIds:[...accepts,...rejects].map(e=>e.eventId).sort(),message:'Both acceptance and rejection assertions exist. Review source, sequencing and scope; no automatic resolution.'});
 }
 timeline.sort((a,b)=>a.at.localeCompare(b.at)||(a.recordedAt??a.at).localeCompare(b.recordedAt??b.at)||(a.eventId??a.submissionId).localeCompare(b.eventId??b.submissionId)||a.type.localeCompare(b.type));
 return {version:1,scope:d.scope,asOf:d.asOf,canWrite:d.financial.canWrite,canReview:d.financial.canReview,submissions:d.submissions,events:d.events,timeline,conflictHints,financialRecords:d.financial.records,financialSummary:financial,deficiencies:rankDeficiencies(d.financial.assessment,plan,financial),limitations:['Source review is not independent verification of delivery, receipt, acceptance, liability or payment entitlement. Authorised export is not proof of delivery.','Contradictory assertions are preserved. Financial references are not additive across deficiencies; use deduplicated financial record totals.','This is a bounded metadata archive with source digests, not a complete original-file export or signed custody checkpoint.']};
}
