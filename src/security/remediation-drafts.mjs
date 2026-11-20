// Local, reviewable drafts only. No automatic edit, approval, messaging or
// recipient inference. Uses the current authoritative preflight and explicit
// active assignments supplied by the scoped workspace.
export function buildRemediationDrafts(g,tasks=[]){
 const fail=()=>{throw Error('invalid remediation input');},id=x=>typeof x==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(x),valid=(x,n)=>typeof x==='string'&&[...x].length<=n&&!/[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/u.test(x);
 if(!g||!id(g.tenantId)||!id(g.projectId)||typeof g.archived!=='boolean'||!Array.isArray(g.requirements)||g.requirements.length>128||!Array.isArray(g.preflight?.issues)||g.preflight.issues.length>128||!Array.isArray(tasks)||tasks.length>128)fail();
 const reqs=new Map(),issues=new Set(),assigned=new Map(),corrections=[],groups=new Map(),ambiguous=[];
 for(const q of g.requirements){if(!id(q.requirementId)||!id(q.versionId)||reqs.has(q.requirementId)||!valid(q.title,128))fail();reqs.set(q.requirementId,q);}
 for(const t of tasks){if(!id(t.taskId)||!id(t.requirementId)||!id(t.versionId)||!id(t.assigneeId)||typeof t.current!=='boolean'||!['assigned','submitted','returned','closed'].includes(t.state))fail();if(t.current&&['assigned','returned'].includes(t.state)){const set=assigned.get(t.requirementId)??new Map();set.set(t.assigneeId,t.versionId);assigned.set(t.requirementId,set);}}
 for(const issue of g.preflight.issues){
  const q=reqs.get(issue.requirementId);
  if(!q||issues.has(issue.requirementId)||!valid(issue.action,1024)||!valid(issue.code,64)||!['blocker','advisory'].includes(issue.level)||!['operator','reviewer','contributor'].includes(issue.responsible))fail();
  issues.add(issue.requirementId);
  const c={requirementId:q.requirementId,versionId:q.versionId,title:q.title,code:issue.code,level:issue.level,role:issue.responsible,action:issue.action};
  corrections.push(c);
  if(g.archived)continue;
  const matches=[...(assigned.get(q.requirementId)??new Map())].filter(([,v])=>v===q.versionId);
  // Never route operator/reviewer remediation to a generic correction assignee.
  const recipient=issue.responsible==='contributor'&&matches.length===1?matches[0][0]:null;
  if(!recipient){ambiguous.push(c);continue;}
  const group=groups.get(recipient)??[];group.push(c);groups.set(recipient,group);
 }
 const drafts=[...groups].sort(([a],[b])=>a.localeCompare(b)).map(([assigneeId,items])=>({assigneeId,requirementIds:items.map(x=>x.requirementId),subject:'Draft evidence follow-up — project '+g.projectId,body:['Please review the following current assigned items.','Project: '+g.projectId,...items.flatMap((x,i)=>[(i+1)+'. '+x.title,'Criterion version: '+x.versionId,'Requested action: '+x.action]),'Please confirm the proposed correction or supply relevant evidence through the authorised workspace. Independent review remains required.'].join('\n')}));
 return {version:1,archived:g.archived,corrections,drafts,unassigned:ambiguous,limitations:['Draft only. Verify current recipient, scope and content before any external use. No message has been sent.','No signed evidence or issued certificate is modified; no evidence or criterion is automatically approved.']};
}
