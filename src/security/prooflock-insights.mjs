import {createHash} from 'node:crypto';
import {buildProofLockPlan} from './prooflock-planner.mjs';
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const id=x=>typeof x==='string'&&uuid.test(x);
const iso=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const time=x=>{if(typeof x!=='string'||!iso.test(x)||!Number.isFinite(Date.parse(x))||new Date(x).toISOString()!==x)throw Error('invalid insights timestamp');return Date.parse(x);};
const invalid=()=>{throw Error('invalid ProofLock insights');};
const minutes=x=>Number.isInteger(x)&&x>=0&&x<=1439;
const stableKey=parts=>createHash('sha256').update(JSON.stringify(parts)).digest('hex');
const zonePattern=/^(?:UTC|[A-Za-z][A-Za-z0-9_+.-]*(?:\/[A-Za-z0-9_+.-]+)+)$/;
export function validateAlertPolicy(p){
 if(!p||!Number.isInteger(p.revision)||p.revision<0||p.revision>32||typeof p.timezone!=='string'||p.timezone.length>80||!zonePattern.test(p.timezone)||typeof p.criticalOverride!=='boolean'||!((p.quietStart===null&&p.quietEnd===null)||(minutes(p.quietStart)&&minutes(p.quietEnd)&&p.quietStart!==p.quietEnd)))invalid();
 try{new Intl.DateTimeFormat('en',{timeZone:p.timezone});}catch{invalid();}
 return p;
}
export function buildProofLockInsights(data){
 const plan=buildProofLockPlan(data),now=time(data.asOf),policy=validateAlertPolicy(data.alertPolicy),receipts=data.captureReceipts;
 if(!Array.isArray(receipts)||receipts.length>256)invalid();
 const windows=new Map(data.windows.map(w=>[w.windowId,w])),revisions=new Map(),receiptGroups=new Map(),links=new Set();
 for(const m of data.milestones){
  if(!id(m.revisionId)||revisions.has(m.revisionId))invalid();
  revisions.set(m.revisionId,m);
 }
 for(const r of receipts){
  const m=revisions.get(r?.milestoneRevisionId),w=windows.get(r?.windowId);
  if(!m||!w||m.milestoneId!==w.milestoneId||r.versionId!==w.versionId||!id(r.linkId)||!id(r.evidenceId)||links.has(r.linkId)||!['pending','pass','fail','unknown'].includes(r.decision)||time(r.receivedAt)>now)invalid();
  const expected=m.stage===null?null:new Date(time(m.stage)-w.leadMinutes*60000).toISOString();
  if(r.deadline!==expected)invalid();
  links.add(r.linkId);const key=w.windowId+':'+m.revisionId;
  const group=receiptGroups.get(key)??[];group.push(r);receiptGroups.set(key,group);
 }
 const parts=Object.fromEntries(new Intl.DateTimeFormat('en-GB',{timeZone:policy.timezone,hour:'2-digit',minute:'2-digit',hourCycle:'h23'}).formatToParts(new Date(now)).map(x=>[x.type,x.value])),localMinute=Number(parts.hour)*60+Number(parts.minute);
 const quiet=policy.quietStart!==null&&(policy.quietStart<policy.quietEnd?localMinute>=policy.quietStart&&localMinute<policy.quietEnd:localMinute>=policy.quietStart||localMinute<policy.quietEnd);
 const alerts=[],recovery=[],receiptTimeline=[];
 const archived=data.assessment.archived===true;
 for(const task of plan.tasks){
  const w=windows.get(task.windowId),history=data.milestones.filter(m=>m.milestoneId===task.milestoneId).sort((a,b)=>a.revision-b.revision),current=history.at(-1);
  if(!archived&&!['verified_now','stale_rule'].includes(task.status)){
   const bucket=task.urgency==='critical'?'critical':task.urgency==='high'?'high':task.urgency==='clarify'?'clarify':'digest';
   const key=stableKey([data.scope.tenantId,data.scope.projectId,task.requirementId,task.versionId,w.windowId,current?.revisionId??null,bucket,task.status==='overdue'?'overdue':task.status==='due_now'?'due_now':'planned','in_app']);
   alerts.push({key,windowId:w.windowId,requirementId:task.requirementId,urgency:task.urgency,bucket,status:task.status,deadline:task.deadline,action:task.action,delivery:'in_app_only',quietSuppressed:quiet&&!(bucket==='critical'&&policy.criticalOverride)});
  }
  for(const m of history){
   const rr=(receiptGroups.get(w.windowId+':'+m.revisionId)??[]).slice().sort((a,b)=>a.receivedAt.localeCompare(b.receivedAt)||a.linkId.localeCompare(b.linkId));
   const deadline=m.stage===null?null:new Date(time(m.stage)-w.leadMinutes*60000).toISOString();
   const superseded=m!==current,until=history[m.revision]?.recordedAt??data.asOf;
   const elapsed=deadline!==null&&time(deadline)<=time(until),effective=w.ruleDecision==='approved'&&w.reviewedAt!==null&&time(w.reviewedAt)<=time(until);
   const timely=rr.filter(r=>deadline!==null&&time(r.receivedAt)<=time(deadline));
   const reviewed=timely.filter(r=>r.decision==='pass');
   if(rr.length)receiptTimeline.push({windowId:w.windowId,revisionId:m.revisionId,revision:m.revision,deadline,superseded,receipts:rr.map(r=>({...r,timing:deadline===null?'unknown_deadline':time(r.receivedAt)<=time(deadline)?'received_by_deadline':'received_after_deadline'}))});
   if(!elapsed||!effective||reviewed.length)continue;
   const afterApproval=time(w.reviewedAt)>time(deadline);
   recovery.push({key:stableKey([w.windowId,m.revisionId,'receipt_gap']),windowId:w.windowId,requirementId:task.requirementId,revisionId:m.revisionId,deadline,superseded,
    classification:afterApproval?'retrospective_schedule':timely.length?'timely_receipt_needs_review':'no_verified_timely_receipt',
    guidance:afterApproval?'Rule was approved after the deadline. Confirm actual site status; do not infer a missed obligation.':w.irreversibility==='irreversible'?'Confirm actual site status. Seek original inspection or contemporaneous records if the confirmed rule permits. A later photograph is not an automatic substitute. Request separately authorised review of exceptions.':'Check for contemporaneous records permitted by the approved criterion. If none, obtain independent approval of a recovery approach before treating it as evidence.',
    requiresIndependentReview:true,waiverGranted:false});
  }
 }
 const active=alerts.filter(a=>!a.quietSuppressed),suppressed=alerts.length-active.length;
 return {version:1,policy,quiet,alerts,summary:{critical:active.filter(a=>a.bucket==='critical').length,high:active.filter(a=>a.bucket==='high').length,clarify:active.filter(a=>a.bucket==='clarify').length,digest:active.filter(a=>a.bucket==='digest').length,quietSuppressed:suppressed,recovery:recovery.length},recovery,receiptTimeline,limitations:['In-app advisory view only; no push, email, scheduled delivery or automatic escalation. Quiet hours suppress prioritised presentation, not access to task records.','Server receipt time is not original capture time, actual work status or proof of timely inspection.','Recovery guidance does not approve alternative evidence, change the criterion, waive obligations or authorise release.']};
}
