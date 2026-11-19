// Deterministic remediation for a scoped assessment; no inferred legal
// obligations, semantic contradiction detection, or release permission.
const states=new Set(['awaiting_rule_review','rule_rejected','unknown_applicability','not_applicable','conflict','failed','unresolved_evidence','satisfied','missing_evidence','integrity_failure']);
const apps=new Set(['required','optional','not_applicable','unknown']);
const safety=new Set(['awaiting_rule_review','rule_rejected','unknown_applicability','integrity_failure']);
const guidance={
 integrity_failure:['INTEGRITY_FAILURE','Stop use of affected evidence; have an authorized operator investigate source and storage integrity before any further assessment.','operator',0],
 conflict:['CONFLICTING_EVIDENCE','Resolve contradictory evidence with an independent reviewer. Record a new criterion revision and reassess relevant evidence; do not discard the historical conflict.','reviewer',1],
 failed:['FAILED_EVIDENCE','Correct the underlying deficiency and submit fresh evidence on a new reviewed revision; prior failed assessments remain in history.','contributor',2],
 rule_rejected:['RULE_REJECTED','Address the reviewer reason and draft a corrected criterion revision for independent review.','contributor',3],
 unknown_applicability:['UNKNOWN_APPLICABILITY','Confirm applicability against the full authoritative source and draft a new revision for independent review.','contributor',4],
 awaiting_rule_review:['RULE_REVIEW_REQUIRED','Request an independent reviewer to confirm the exact criterion and its applicability.','reviewer',5],
 unresolved_evidence:['EVIDENCE_REVIEW_REQUIRED','Complete outstanding independent assessments. An unknown terminal decision requires a revised criterion and reassessment.','reviewer',6],
 missing_evidence:['MISSING_EVIDENCE','Attach relevant, trustworthy supporting evidence and request an independent assessment.','contributor',7]
};
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
function invalid(){throw Error('invalid preflight assessment');}
export function buildRejectionPreflight(g){
 if(!g||g.version!==1||!g.summary||!Array.isArray(g.requirements)||g.requirements.length>128||typeof g.archived!=='boolean')invalid();
 const issues=[],warnings=[],groups=new Map(),ids=new Set();let required=0,verified=0,blockers=0;
 for(const q of g.requirements){
  if(!q||typeof q.requirementId!=='string'||q.requirementId.length!==36||!uuid.test(q.requirementId)||ids.has(q.requirementId)||!states.has(q.state)||!apps.has(q.applicability)||typeof q.criterion!=='string'||[...q.criterion].length>1024||!Array.isArray(q.links)||q.links.length>8)invalid();
  ids.add(q.requirementId);
  if(q.applicability==='required'){required++;if(q.state==='satisfied')verified++;}
  const mandatory=safety.has(q.state)||(q.applicability==='required'&&q.state!=='satisfied');
  if(mandatory)blockers++;
  const item=guidance[q.state];
  if(item){const [code,action,responsible,rank]=item;issues.push({requirementId:q.requirementId,code,level:mandatory?'blocker':'advisory',action,responsible,rank});}
  else if(mandatory)invalid();
  // Exact whitespace-normalized, case-folded text only. This is a duplicate
  // hint, not a claim of semantic equality or legal incompatibility.
  const key=q.criterion.normalize('NFC').trim().replace(/\s+/gu,' ').toLowerCase(),group=groups.get(key)??[];group.push({id:q.requirementId,app:q.applicability});groups.set(key,group);
  const hashes=new Set();let repeated=false,sourceUsed=false;
  for(const l of q.links){if(typeof l.sha256!=='string'||! /^[a-f0-9]{64}$/.test(l.sha256)||l.sha256.length!==64)invalid();if(hashes.has(l.sha256))repeated=true;hashes.add(l.sha256);if(q.source&&l.evidenceId===q.source.evidenceId)sourceUsed=true;}
  if(repeated)warnings.push({requirementId:q.requirementId,code:'DUPLICATE_EVIDENCE_BYTES',action:'Identical hashes do not establish independent corroboration. Check whether the copies add any relevant proof.'});
  if(sourceUsed)warnings.push({requirementId:q.requirementId,code:'SOURCE_USED_AS_EVIDENCE',action:'The obligation source may describe what is required without proving completion. Check the relevance of this linked source.'});
 }
 for(const group of groups.values())if(group.length>1)warnings.push({requirementId:group[0].id,related:group.slice(1).map(x=>x.id),code:new Set(group.map(x=>x.app)).size>1?'DUPLICATE_CRITERION_DIFFERENT_APPLICABILITY':'DUPLICATE_CRITERION',action:'Review repeated criterion text and applicability against the complete source; no automatic merge or deletion.'});
 const status=blockers?'blocked':required===0?'not_assessed':'criteria_satisfied';
 if(g.summary.requirements!==ids.size||g.summary.required!==required||g.summary.verifiedRequired!==verified||g.summary.blockers!==blockers||g.summary.status!==status)invalid();
 issues.sort((a,b)=>Number(b.level==='blocker')-Number(a.level==='blocker')||a.rank-b.rank||a.requirementId.localeCompare(b.requirementId));
 return {version:1,status,mandatoryCoveragePercent:required?Math.floor(100*verified/required):null,blockers,advisories:issues.length-blockers+warnings.length,issues,warnings,archived:g.archived,limitations:['Coverage measures reviewed mandatory criteria only, not the completeness of the contract or submission.','Source extraction is heuristic and may omit obligations. Full-document review and recipient-specific checks are required.','This is not release authorization, legal certification or a prediction of acceptance.']};
}
