import {createHash} from 'node:crypto';
import {buildRejectionPreflight} from './rejection-preflight.mjs';
const uuid=x=>typeof x==='string'&&x.length===36&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(x);
const digest=x=>typeof x==='string'&&x.length===64&&/^[a-f0-9]{64}$/.test(x);
const fail=()=>{throw Error('invalid change impact input');};
const stable=x=>Array.isArray(x)?x.map(stable):x&&typeof x==='object'?Object.fromEntries(Object.keys(x).sort().map(k=>[k,stable(x[k])])):x;
const equal=(a,b)=>JSON.stringify(stable(a))===JSON.stringify(stable(b));
function inventory(g){
 buildRejectionPreflight(g);
 const result=new Map(),links=new Set();
 for(const q of g.requirements){
  if(!uuid(q.versionId)||!Number.isInteger(q.revision)||q.revision<1||q.revision>16||
   typeof q.title!=='string'||!['approved','rejected','pending'].includes(q.ruleDecision)||
   !['manual','source-line-v1'].includes(q.provenance))fail();
  if(q.source!==null&&(!q.source||!uuid(q.source.evidenceId)||!digest(q.source.sha256)||!digest(q.source.quoteSha256)))fail();
  const evidence=q.links.map(l=>{
   if(!uuid(l.linkId)||links.has(l.linkId)||!uuid(l.evidenceId)||!digest(l.sha256)||typeof l.integrity!=='boolean'||!['pending','pass','fail','unknown'].includes(l.decision))fail();
   links.add(l.linkId);
   return {linkId:l.linkId,evidenceId:l.evidenceId,sha256:l.sha256,decision:l.decision,reason:l.reason,integrity:l.integrity};
  }).sort((a,b)=>a.linkId.localeCompare(b.linkId));
  result.set(q.requirementId,{versionId:q.versionId,revision:q.revision,title:q.title,criterion:q.criterion,applicability:q.applicability,provenance:q.provenance,source:q.source,ruleDecision:q.ruleDecision,ruleReason:q.ruleReason,state:q.state,evidence,dependencyPins:q.dependencyPins??[]});
 }
 return result;
}
// Read-only comparison against an immutable scoped submission. Ignores live
// role hints and timestamps. Never grants authorization or mutates decisions.
export function compareSubmissionGraph(baseline,current,scope){
 if(!scope||!uuid(scope.tenantId)||!uuid(scope.projectId)||!uuid(scope.submissionId)||
 !baseline||baseline.submissionId!==scope.submissionId||!digest(baseline.sha256)||typeof baseline.manifest!=='string'||
 Buffer.byteLength(baseline.manifest)>2097152||createHash('sha256').update(baseline.manifest).digest('hex')!==baseline.sha256)fail();
 let previous;try{previous=JSON.parse(baseline.manifest);}catch{fail();}
 if(!previous||!current||previous.tenantId!==scope.tenantId||previous.projectId!==scope.projectId||current.tenantId!==scope.tenantId||current.projectId!==scope.projectId||
 previous.summary?.status!=='criteria_satisfied')fail();
 const before=inventory({...previous,archived:false}),after=inventory(current);
 const changes=[],ids=[...new Set([...before.keys(),...after.keys()])].sort();
 for(const requirementId of ids){
  const old=before.get(requirementId),now=after.get(requirementId),reasons=[];
  if(!old)reasons.push('requirement_added');
  else if(!now)reasons.push('requirement_missing');
  else{
   if(!equal([old.versionId,old.revision,old.title,old.criterion,old.applicability,old.provenance],[now.versionId,now.revision,now.title,now.criterion,now.applicability,now.provenance]))reasons.push('criterion_revision_changed');
   if(!equal(old.source,now.source))reasons.push('source_changed');
   if(!equal([old.ruleDecision,old.ruleReason],[now.ruleDecision,now.ruleReason]))reasons.push('rule_review_changed');
   const identity=r=>r.evidence.map(({linkId,evidenceId,sha256})=>[linkId,evidenceId,sha256]);
   if(!equal(identity(old),identity(now)))reasons.push('evidence_links_changed');
   const prior=new Map(old.evidence.map(x=>[x.linkId,x]));
   if(now.evidence.some(x=>prior.has(x.linkId)&&!equal([x.decision,x.reason],[prior.get(x.linkId).decision,prior.get(x.linkId).reason])))reasons.push('evidence_review_changed');
   if(now.evidence.some(x=>prior.has(x.linkId)&&x.integrity!==prior.get(x.linkId).integrity))reasons.push('evidence_integrity_changed');
   if(!equal(old.dependencyPins,now.dependencyPins))reasons.push('dependencies_changed');
   if(old.state!==now.state)reasons.push('readiness_state_changed');
  }
  if(reasons.length)changes.push({requirementId,previousVersionId:old?.versionId??null,currentVersionId:now?.versionId??null,previousState:old?.state??null,currentState:now?.state??null,reasons,
   affectedEvidenceIds:[...new Set([...(old?.evidence??[]).map(x=>x.evidenceId),...(now?.evidence??[]).map(x=>x.evidenceId),...[old?.source?.evidenceId,now?.source?.evidenceId].filter(Boolean)])].sort()});
 }
 return {version:1,submissionId:scope.submissionId,baselineSha256:baseline.sha256,changedCount:changes.length,unchangedCount:ids.length-changes.length,changes,
  currentStatus:current.summary.status,currentBlockers:current.summary.blockers,archived:current.archived,
  scope:'requirement graph comparison only; current package authorization and project metadata are not verified'};
}
