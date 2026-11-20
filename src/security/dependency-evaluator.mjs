import {createHash} from 'node:crypto';
const uuid=x=>typeof x==='string'&&x.length===36&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(x);
const digest=x=>typeof x==='string'&&x.length===64&&/^[a-f0-9]{64}$/.test(x);
const states=new Set(['awaiting_rule_review','rule_rejected','unknown_applicability','not_applicable','conflict','failed','unresolved_evidence','satisfied','missing_evidence','integrity_failure']);
const hash=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const fail=()=>{throw Error('invalid dependency graph');};
const idsort=(a,b)=>a<b?-1:a>b?1:0;
const scoped=(x,s)=>x&&x.tenantId===s.tenantId&&x.projectId===s.projectId;

// Edges bind a dependent version to the exact effective fingerprint of its
// prerequisite. All records are trusted, scoped server inputs, NOT browser
// assertions. This module performs no authentication or persistent writes.
function graph(input){
 const s=input?.scope;
 if(!uuid(s?.tenantId)||!uuid(s?.projectId)||!Array.isArray(input.nodes)||input.nodes.length>128||
 !Array.isArray(input.edges)||input.edges.length>1024)fail();
 const nodes=new Map(),incoming=new Map(),outgoing=new Map(),versions=new Set();
 for(const n of input.nodes){
  if(!scoped(n,s)||!uuid(n.requirementId)||!uuid(n.versionId)||!digest(n.localDigest)||
   !states.has(n.localState)||nodes.has(n.requirementId)||versions.has(n.versionId))fail();
  versions.add(n.versionId);
  nodes.set(n.requirementId,{versionId:n.versionId,localDigest:n.localDigest,localState:n.localState});
  incoming.set(n.requirementId,[]);outgoing.set(n.requirementId,[]);
 }
 const seen=new Set();
 for(const e of input.edges){
  if(!scoped(e,s)||!nodes.has(e.dependentId)||!nodes.has(e.prerequisiteId)||e.dependentId===e.prerequisiteId||
   e.dependentVersionId!==nodes.get(e.dependentId).versionId||!digest(e.prerequisiteFingerprint))fail();
  const key=e.dependentId+':'+e.prerequisiteId;
  if(seen.has(key)||incoming.get(e.dependentId).length>=8)fail();seen.add(key);
  incoming.get(e.dependentId).push({prerequisiteId:e.prerequisiteId,prerequisiteFingerprint:e.prerequisiteFingerprint});
  outgoing.get(e.prerequisiteId).push(e.dependentId);
 }
 for(const v of incoming.values())v.sort((a,b)=>idsort(a.prerequisiteId,b.prerequisiteId));
 for(const v of outgoing.values())v.sort(idsort);
 const ids=[...nodes.keys()].sort(idsort),degrees=new Map(ids.map(id=>[id,incoming.get(id).length]));
 const ready=ids.filter(id=>degrees.get(id)===0),order=[];
 while(ready.length){
  const id=ready.shift();order.push(id);
  for(const child of outgoing.get(id)){const degree=degrees.get(child)-1;degrees.set(child,degree);if(degree===0){ready.push(child);ready.sort(idsort);}}
 }
 if(order.length!==nodes.size)fail();
 const signatures=new Map(ids.map(id=>[id,hash([nodes.get(id),incoming.get(id)])]));
 return {scope:{tenantId:s.tenantId,projectId:s.projectId},nodes,incoming,outgoing,ids,order,signatures};
}
function compute(g,id,results){
 const n=g.nodes.get(id),parents=g.incoming.get(id),issues=[],upstream=[];
 for(const e of parents){
  const p=results.get(e.prerequisiteId);
  if(!p)fail();
  upstream.push([e.prerequisiteId,e.prerequisiteFingerprint,p.fingerprint,p.effectiveState]);
  if(p.effectiveState!=='satisfied')issues.push(Object.freeze({prerequisiteId:e.prerequisiteId,reason:'prerequisite_not_satisfied'}));
  if(p.fingerprint!==e.prerequisiteFingerprint)issues.push(Object.freeze({prerequisiteId:e.prerequisiteId,reason:'prerequisite_fingerprint_changed'}));
 }
 const effectiveState=issues.length?'dependency_blocked':n.localState;
 const fingerprint=hash([g.scope.tenantId,g.scope.projectId,id,n.versionId,n.localDigest,n.localState,upstream]);
 return Object.freeze({requirementId:id,versionId:n.versionId,localState:n.localState,effectiveState,fingerprint,issues:Object.freeze(issues)});
}
function run(g,prior,dirty){
 const results=new Map(),recomputed=[];
 for(const id of g.order){
  if(!dirty.has(id)&&prior?.has(id))results.set(id,prior.get(id));
  else {results.set(id,compute(g,id,results));recomputed.push(id);}
 }
 return {results,recomputed};
}
function snapshot(g,results,recomputed){
 const rows=Object.freeze(g.ids.map(id=>results.get(id)));
 return Object.freeze({scope:Object.freeze({...g.scope}),results:rows,
  dependencyBlockers:rows.filter(r=>r.effectiveState==='dependency_blocked').length,
  recomputedIds:Object.freeze([...recomputed].sort(idsort))});
}
export function evaluateDependencyGraph(input){
 const g=graph(input),{results,recomputed}=run(g,null,new Set(g.ids));
 return snapshot(g,results,recomputed);
}

// Private retained state: callers cannot inject a previous result or mutate
// its cached findings. Dirty roots are derived by comparing graph inputs,
// not from a caller-supplied list. Removed edges/nodes traverse both graphs.
export function createDependencyEvaluator(initial){
 let g=graph(initial),state=run(g,null,new Set(g.ids));
 return Object.freeze({
  current(){return snapshot(g,state.results,state.recomputed);},
  update(input){
   const next=graph(input);
   if(!scoped(next.scope,g.scope))fail();
   const all=new Set([...g.ids,...next.ids]),dirty=new Set();
   for(const id of all)if(g.signatures.get(id)!==next.signatures.get(id))dirty.add(id);
   const queue=[...dirty];
   for(let i=0;i<queue.length;i++){
    for(const child of [...(g.outgoing.get(queue[i])??[]),...(next.outgoing.get(queue[i])??[])])
     if(!dirty.has(child)){dirty.add(child);queue.push(child);}
   }
   const nextState=run(next,state.results,dirty);
   // Commit only after all validation and recomputation succeed.
   g=next;state=nextState;
   return snapshot(g,state.results,state.recomputed);
  }
 });
}
