// Advisory only: explicit human-reviewed fields, exact matching, no automatic approval.
const uid=x=>typeof x==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(x);
const sha=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x),date=x=>typeof x==='string'&&/^\d{4}-\d{2}-\d{2}$/.test(x)&&Number.isFinite(Date.parse(x+'T00:00:00Z'))&&new Date(x+'T00:00:00Z').toISOString().slice(0,10)===x;
const kinds=['certificate','warranty','inspection','manual','photo','other'];
const text=x=>typeof x==='string'&&x===x.trim()&&[...x].length>=1&&[...x].length<=128&&!/[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\ud800-\udfff]/u.test(x);
const fail=()=>{throw Error('invalid evidence intelligence');};
export function assessEvidenceMetadata(q,asOf){
 if(!date(asOf)||!uid(q.evidenceId)||!uid(q.versionId)||!sha(q.sha256)||!kinds.includes(q.kind)||![q.identifier,q.equipment,q.issuer].every(text)||![null,q.issuedOn].every(x=>x===null||date(x))||![null,q.expiresOn].every(x=>x===null||date(x))||!['pending','approved','rejected'].includes(q.decision)||typeof q.sourceIntact!=='boolean'||q.issuedOn&&q.expiresOn&&q.expiresOn<q.issuedOn)fail();
 let status=!q.sourceIntact?'integrity_failure':q.decision!=='approved'?'review_required':q.issuedOn&&q.issuedOn>asOf?'future_issue_date':q.expiresOn&&q.expiresOn<asOf?'expired':q.expiresOn===null?'expiry_unknown':q.issuedOn===null?'issue_date_unknown':'recorded_dates_current';
 return {...q,status,issuerVerified:false};
}
export function matchReviewedEvidence(records,expected,asOf){
 if(!expected||!kinds.includes(expected.kind)||!text(expected.identifier)||!text(expected.equipment)||!text(expected.issuer)||!Array.isArray(records)||records.length>256)fail();
 // Exact strings intentionally distinguish similar identifiers, including case.
 const relevant=records.map(x=>assessEvidenceMetadata(x,asOf)).filter(x=>x.kind===expected.kind&&x.identifier===expected.identifier&&x.equipment===expected.equipment&&x.issuer===expected.issuer);
 const usable=relevant.filter(x=>x.status==='recorded_dates_current');
 return {status:usable.length===1&&relevant.length===1?'single_reviewed_candidate':relevant.length>1?'ambiguous':relevant.length===1?'candidate_needs_review':'no_exact_match',candidates:relevant.map(x=>({evidenceId:x.evidenceId,versionId:x.versionId,sha256:x.sha256,status:x.status})),automaticApproval:false};
}
export function buildEvidenceIntelligence(d){
 if(!d||d.version!==1||!uid(d.tenantId)||!uid(d.projectId)||!date(d.asOfDate)||d.assessment?.tenantId!==d.tenantId||d.assessment?.projectId!==d.projectId||!Array.isArray(d.assessment.requirements)||!Array.isArray(d.inventory)||d.inventory.length>4096||!Array.isArray(d.metadata)||d.metadata.length>256||!Array.isArray(d.reviewHistory)||d.reviewHistory.length>2048)fail();
 const groups=new Map(),ids=new Map();
 for(const x of d.inventory){if(!uid(x.evidenceId)||!sha(x.sha256)||ids.has(x.evidenceId))fail();ids.set(x.evidenceId,x.sha256);const group=groups.get(x.sha256)??[];group.push(x.evidenceId);groups.set(x.sha256,group);}
 const seen=new Set(),metadata=d.metadata.map(q=>{if(seen.has(q.evidenceId)||ids.get(q.evidenceId)!==q.sha256)fail();seen.add(q.evidenceId);return assessEvidenceMetadata(q,d.asOfDate);});
 const history=new Map(),versions=new Set(),reqs=new Map(d.assessment.requirements.map(q=>[q.requirementId,q]));
 for(const r of d.reviewHistory){if(!reqs.has(r.requirementId)||!uid(r.versionId)||versions.has(r.versionId)||!Number.isInteger(r.revision)||r.revision<1||r.revision>16||![null,true,false].includes(r.ruleRejected)||![r.failedLinks,r.unknownLinks].every(x=>Number.isInteger(x)&&x>=0&&x<=8))fail();versions.add(r.versionId);const h=history.get(r.requirementId)??[];h.push(r);history.set(r.requirementId,h);}
 const rejectionRisk=d.assessment.requirements.map(q=>{const prior=(history.get(q.requirementId)??[]).filter(x=>x.revision<q.revision&&(x.ruleRejected||x.failedLinks||x.unknownLinks));return {requirementId:q.requirementId,versionId:q.versionId,currentState:q.state,priorAdverseReviews:prior.map(x=>({versionId:x.versionId,revision:x.revision,ruleRejected:x.ruleRejected===true,failedLinks:x.failedLinks,unknownLinks:x.unknownLinks})),basis:prior.length?'rule_plus_project_review_history':'rule_only',action:prior.length?'Review the prior adverse decisions before submitting this revision.':'Use the current rule and independent source review.'};});
 return {...d,metadata,duplicateGroups:[...groups].filter(([,a])=>a.length>1).map(([sha256,evidenceIds])=>({sha256,evidenceIds:evidenceIds.sort()})),rejectionRisk,limitations:['Exact reviewed metadata is an advisory candidate, never a criterion pass or issuer authentication.','Dates reflect documented fields; expiry uses UTC calendar date inclusive. Missing date is unknown.','Prior internal adverse reviews do not establish customer rejection or a probability. Duplicate bytes are not independent proof.']};
}
