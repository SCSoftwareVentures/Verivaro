// Documentary readiness only. Supported currency subset is intentionally
// explicit; there is no conversion, payment instruction or legal inference.
const decimals=Object.freeze({AUD:2,USD:2,NZD:2,GBP:2,EUR:2,CAD:2,SGD:2,JPY:0,KWD:3,BHD:3});
const MAX=999999999999999n,UID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const id=v=>typeof v==='string'&&UID.test(v);
const basis=['tax_inclusive','tax_exclusive','tax_not_applicable'];
const kind=['milestone','retention','disputed'];
const invalid=()=>{throw Error('invalid financial record');};
const scale=c=>{if(typeof c!=='string'||!Object.hasOwn(decimals,c))invalid();return decimals[c];};
export function decimalToMinor(amount,currency){
 const n=scale(currency);
 if(typeof amount!=='string'||amount.length>20||!/^(0|[1-9]\d*)(\.\d+)?$/.test(amount))invalid();
 const [whole,fraction='']=amount.split('.');
 if(fraction.length>n)invalid();
 const result=BigInt(whole)*10n**BigInt(n)+BigInt(fraction.padEnd(n,'0')||'0');
 if(result>MAX)invalid();
 return result.toString();
}
export function minorToDecimal(amount,currency){
 const n=scale(currency);
 if(typeof amount!=='string'||!/^(0|[1-9]\d{0,17})$/.test(amount))invalid();
 if(!n)return amount;
 const s=amount.padStart(n+1,'0');return s.slice(0,-n)+'.'+s.slice(-n);
}
const timestamp=s=>{if(typeof s!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(s)||!Number.isFinite(Date.parse(s))||new Date(s).toISOString()!==s)invalid();return Date.parse(s);};
const validText=(v,max)=>typeof v==='string'&&v.trim()===v&&v.length>=1&&v.length<=max&&!/[\x00-\x1f\x7f-\x9f]/.test(v);
export function buildFinancialSummary({scope,assessment,records,asOf}={}){
 if(!scope||!id(scope.tenantId)||!id(scope.projectId)||!assessment||assessment.tenantId!==scope.tenantId||assessment.projectId!==scope.projectId||!Array.isArray(assessment.requirements)||assessment.requirements.length>128||!Array.isArray(records)||records.length>256)invalid();
 const now=timestamp(asOf),reqs=new Map(),seen=new Set(),groups=new Map(),entries=[];
 for(const q of assessment.requirements){if(!q||!id(q.requirementId)||!id(q.versionId)||reqs.has(q.requirementId)||!['awaiting_rule_review','rule_rejected','unknown_applicability','not_applicable','conflict','failed','unresolved_evidence','satisfied','missing_evidence','integrity_failure','dependency_blocked'].includes(q.state)||!['approved','pending','rejected'].includes(q.ruleDecision))invalid();reqs.set(q.requirementId,q);}
 for(const r of records){
  if(!r||r.tenantId!==scope.tenantId||r.projectId!==scope.projectId||!id(r.recordId)||seen.has(r.recordId)||!id(r.versionId)||!kind.includes(r.kind)||!basis.includes(r.taxBasis)||!validText(r.title,128)||!['approved','pending','rejected'].includes(r.decision)||!['confirmed','unknown'].includes(r.amountStatus)||!['confirmed','unknown'].includes(r.dueStatus)||!id(r.sourceEvidenceId)||typeof r.sourceSha256!=='string'||!/^[a-f0-9]{64}$/.test(r.sourceSha256)||typeof r.sourceIntact!=='boolean'||!Array.isArray(r.conditions)||r.conditions.length>32)invalid();
  seen.add(r.recordId);scale(r.currency);
  const amount=r.amountStatus==='confirmed'?decimalToMinor(r.amount,r.currency):null;
  if(r.amountStatus==='unknown'&&r.amount!==null)invalid();
  if(r.dueStatus==='unknown'&&r.dueAt!==null)invalid();
  const due=r.dueStatus==='confirmed'?timestamp(r.dueAt):null;
  const pins=new Set(),conditions=[];
  for(const c of r.conditions){
   if(!c||!id(c.requirementId)||!id(c.versionId)||pins.has(c.requirementId))invalid();pins.add(c.requirementId);
   const q=reqs.get(c.requirementId);if(!q)invalid();
   const status=q.versionId!==c.versionId?'stale':q.ruleDecision==='approved'&&q.state==='satisfied'?'satisfied':'blocked';
   conditions.push({requirementId:c.requirementId,versionId:c.versionId,status});
  }
  conditions.sort((a,b)=>a.requirementId.localeCompare(b.requirementId));
  const confirmed=r.decision==='approved'&&r.sourceIntact&&amount!==null;
  const ready=confirmed&&conditions.length>0&&conditions.every(c=>c.status==='satisfied');
  const status=!confirmed?'review_required':!conditions.length?'no_reviewed_conditions':ready?'documentary_conditions_satisfied':'documentary_blockers';
  const entry={recordId:r.recordId,versionId:r.versionId,title:r.title,kind:r.kind,currency:r.currency,taxBasis:r.taxBasis,amountMinor:amount,amountStatus:r.amountStatus,sourceEvidenceId:r.sourceEvidenceId,sourceSha256:r.sourceSha256,sourceIntact:r.sourceIntact,decision:r.decision,status,conditions,dueStatus:r.dueStatus,dueAt:r.dueAt,reminder:due===null?'date_unknown':due<=now?'recorded_date_elapsed':due-now<=604800000?'recorded_date_within_7_days':'recorded_date_upcoming',paymentEntitlement:'not_determined'};
  entries.push(entry);
  if(!confirmed)continue;
  const key=JSON.stringify([r.kind,r.currency,r.taxBasis]),g=groups.get(key)??{kind:r.kind,currency:r.currency,taxBasis:r.taxBasis,count:0,total:0n,ready:0n,blocked:0n,unassessed:0n};
  const a=BigInt(amount);g.count++;g.total+=a;if(ready)g.ready+=a;else if(conditions.length)g.blocked+=a;else g.unassessed+=a;groups.set(key,g);
 }
 return {version:1,asOf,entries:entries.sort((a,b)=>a.recordId.localeCompare(b.recordId)),groups:[...groups.values()].sort((a,b)=>JSON.stringify([a.kind,a.currency,a.taxBasis]).localeCompare(JSON.stringify([b.kind,b.currency,b.taxBasis]))).map(g=>({kind:g.kind,currency:g.currency,taxBasis:g.taxBasis,count:g.count,totalMinor:g.total.toString(),documentaryReadyMinor:g.ready.toString(),documentaryBlockedMinor:g.blocked.toString(),unassessedMinor:g.unassessed.toString()})),limitations:['Documentary readiness only; no payment entitlement, cash collection, lawful withholding or statutory deadline determination.','Amounts are counted once per independently reviewed record; currency, tax basis, retention and dispute categories never combine. Unknown amounts are not zero.','The date is a recorded reminder, not a legal payment or retention release date.']};
}
