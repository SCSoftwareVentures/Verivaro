// Pure advisory planner. Inputs must originate from a scoped authenticated
// service; this module never confers permission or changes release readiness.
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const ISO=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const LOCAL=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/;
const riskValues=['reversible','costly','irreversible'];
const states=['awaiting_rule_review','rule_rejected','unknown_applicability','not_applicable','conflict','failed','unresolved_evidence','satisfied','missing_evidence','integrity_failure','dependency_blocked'];
const fail=()=>{throw Error('invalid ProofLock schedule input');};
const uid=v=>typeof v==='string'&&v.length===36&&UUID.test(v);
const int=(v,min,max)=>Number.isSafeInteger(v)&&v>=min&&v<=max;
const instant=s=>{if(typeof s!=='string'||!ISO.test(s))fail();const n=Date.parse(s);if(!Number.isFinite(n)||new Date(n).toISOString()!==s)fail();return n;};
const iso=n=>{const s=new Date(n).toISOString();if(!ISO.test(s))fail();return s;};
const scopeMatch=(r,s)=>r&&r.tenantId===s.tenantId&&r.projectId===s.projectId;
const formatter=zone=>{
 if(typeof zone!=='string'||zone.length>80||!/^(?:UTC|[A-Za-z][A-Za-z0-9_+.-]*(?:\/[A-Za-z0-9_+.-]+)+)$/.test(zone))fail();
 try{return new Intl.DateTimeFormat('en-CA',{timeZone:zone,calendar:'iso8601',numberingSystem:'latn',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hourCycle:'h23'});}catch{fail();}
};
// A local wall-clock timestamp requires an explicit offset. Round-trip through
// IANA zone rules: nonexistent spring times and wrong offsets are rejected;
// the two valid offsets of an autumn fold map to distinct instants.
export function resolveLocalMilestone(localTime,timezone,offsetMinutes){
 if(typeof localTime!=='string'||!LOCAL.test(localTime)||!int(offsetMinutes,-840,840))fail();
 const wall=instant(localTime+':00.000Z'),n=wall-offsetMinutes*60000;
 const p=Object.fromEntries(formatter(timezone).formatToParts(new Date(n)).map(x=>[x.type,x.value]));
 if(p.year+'-'+p.month+'-'+p.day+'T'+p.hour+':'+p.minute!==localTime)fail();
 return iso(n);
}
export function buildProofLockPlan({scope,asOf,milestones,windows,assessment}={}){
 if(!scope||!uid(scope.tenantId)||!uid(scope.projectId)||!Array.isArray(milestones)||milestones.length>2048||!Array.isArray(windows)||windows.length>256||!scopeMatch(assessment,scope)||!Array.isArray(assessment.requirements)||assessment.requirements.length>128)fail();
 const now=instant(asOf),groups=new Map(),requirements=new Map(),windowIds=new Set(),pairs=new Set();
 for(const q of assessment.requirements){
  if(!q||!uid(q.requirementId)||!uid(q.versionId)||requirements.has(q.requirementId)||!states.includes(q.state)||!['approved','pending','rejected'].includes(q.ruleDecision)||!['required','optional','unknown','not_applicable'].includes(q.applicability))fail();
  requirements.set(q.requirementId,q);
 }
 for(const m of milestones){
  if(!scopeMatch(m,scope)||!uid(m.milestoneId)||!int(m.revision,1,16)||typeof m.confirmed!=='boolean')fail();
  const recorded=instant(m.recordedAt);if(recorded>now)fail();
  formatter(m.timezone);
  if(!m.confirmed&&(m.localTime!==null||m.offsetMinutes!==null))fail();
  const stage=m.confirmed?resolveLocalMilestone(m.localTime,m.timezone,m.offsetMinutes):null;
  const group=groups.get(m.milestoneId)??[];
  group.push({revision:m.revision,recordedAt:m.recordedAt,recorded,stage,localTime:m.localTime,timezone:m.timezone,offsetMinutes:m.offsetMinutes});groups.set(m.milestoneId,group);
 }
 if(groups.size>128)fail();
 for(const group of groups.values()){
  group.sort((a,b)=>a.revision-b.revision);
  if(group.some((m,i)=>m.revision!==i+1||(i>0&&m.recorded<=group[i-1].recorded)))fail();
 }
 const tasks=[];
 for(const w of windows){
  if(!scopeMatch(w,scope)||!uid(w.windowId)||windowIds.has(w.windowId)||!uid(w.requirementId)||!uid(w.versionId)||!uid(w.milestoneId)||!int(w.leadMinutes,0,525600)||!riskValues.includes(w.irreversibility)||!['approved','pending','rejected'].includes(w.ruleDecision))fail();
  const pair=w.versionId+':'+w.milestoneId;if(pairs.has(pair))fail();pairs.add(pair);windowIds.add(w.windowId);
  const q=requirements.get(w.requirementId),versions=groups.get(w.milestoneId)??[],latest=versions.at(-1);
  if(!q)fail();
  if(w.versionId!==q.versionId){
   tasks.push({windowId:w.windowId,requirementId:w.requirementId,versionId:w.versionId,milestoneId:w.milestoneId,status:'stale_rule',deadline:null,stage:null,history:[],risk:w.irreversibility,urgency:'clarify',mandatory:q.applicability==='required',action:'Review a window against the current criterion revision.'});continue;
  }
  const approved=w.ruleDecision==='approved'&&q.ruleDecision==='approved'&&['required','optional'].includes(q.applicability);
  // History derives from the supplied immutable schedule revisions, not a
  // fabricated event log. A superseded deadline that elapsed is preserved;
  // there is no inference that equipment installation or capture occurred.
  const history=approved?versions.map((m,i)=>{
   const until=versions[i+1]?.recorded??now,deadline=m.stage===null?null:iso(instant(m.stage)-w.leadMinutes*60000);
   return {revision:m.revision,recordedAt:m.recordedAt,stage:m.stage,deadline,timezone:m.timezone,localTime:m.localTime,offsetMinutes:m.offsetMinutes,superseded:i<versions.length-1,deadlineElapsedBeforeSupersessionOrAsOf:deadline===null?null:instant(deadline)<=until};
  }):[];
  const deadline=approved?history.at(-1)?.deadline??null:null,stage=approved?latest?.stage??null:null;
  let status,urgency,action;
  if(!approved){status='unapproved_rule';urgency='clarify';action='Confirm applicability and independently approve the exact capture rule.';}
  else if(deadline===null){status='unknown_schedule';urgency='clarify';action='Confirm a milestone date, timezone and offset; no date has been inferred.';}
  else if(q.state==='satisfied'){status='verified_now';urgency='review';action='Current evidence is satisfied; verify historical capture timing separately.';}
  else{
   const remaining=instant(deadline)-now,stageRemaining=instant(stage)-now;
   status=remaining<0?'overdue':remaining===0?'due_now':'upcoming';
   if(w.irreversibility==='irreversible'&&(remaining<=86400000||stageRemaining<=86400000))urgency='critical';
   else if(remaining<=0||remaining<=86400000&&w.irreversibility==='costly')urgency='high';
   else if(remaining<=86400000)urgency='soon';else urgency='routine';
   action=stageRemaining<=0&&w.irreversibility==='irreversible'?'Planned stage time has elapsed; confirm actual site status and obtain independent review of permitted recovery evidence. Do not assume the stage occurred.':w.irreversibility==='irreversible'?'Capture and independently assess required evidence before the planned irreversible stage.':'Capture relevant evidence and request independent review.';
  }
  tasks.push({windowId:w.windowId,requirementId:w.requirementId,versionId:w.versionId,milestoneId:w.milestoneId,milestoneRevision:latest?.revision??null,status,deadline,stage,history,risk:w.irreversibility,urgency,mandatory:q.applicability==='required',action});
 }
 const ranks={critical:0,high:1,soon:2,clarify:3,routine:4,review:5};
 tasks.sort((a,b)=>ranks[a.urgency]-ranks[b.urgency]||Number(b.mandatory)-Number(a.mandatory)||(a.deadline??'~').localeCompare(b.deadline??'~')||a.windowId.localeCompare(b.windowId));
 return {version:1,asOf,tasks,summary:{total:tasks.length,overdue:tasks.filter(x=>x.status==='overdue').length,dueNow:tasks.filter(x=>x.status==='due_now').length,critical:tasks.filter(x=>x.urgency==='critical').length,clarification:tasks.filter(x=>x.urgency==='clarify').length},limitations:['Elapsed-minute lead times only; no business calendar or legal deadline calculation.','Scheduled time is not proof of work, capture, or timely review. A satisfied requirement now is not proof of historic timeliness.','Advisory planning only; no release authority, notifications, or automatic evidence substitution.']};
}
