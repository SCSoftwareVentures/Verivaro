import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {evaluateDependencyGraph,createDependencyEvaluator} from '../../src/security/dependency-evaluator.mjs';
const h=s=>createHash('sha256').update(s).digest('hex');
const by=(v,id)=>v.results.find(x=>x.requirementId===id);
function fixture(){
 const scope={tenantId:randomUUID(),projectId:randomUUID()};
 const nodes=Array.from({length:5},(_,i)=>({...scope,requirementId:randomUUID(),versionId:randomUUID(),localDigest:h(String(i)),localState:'satisfied'}));
 const input={scope,nodes,edges:[]};
 const connect=(p,d)=>{const fp=by(evaluateDependencyGraph(input),p.requirementId).fingerprint;input.edges.push({...scope,dependentId:d.requirementId,dependentVersionId:d.versionId,prerequisiteId:p.requirementId,prerequisiteFingerprint:fp});};
 const [a,b,c,d,e]=nodes;
 connect(a,b);connect(a,c);connect(b,d);connect(c,d);
 return {input,a,b,c,d,e,connect};
}
const equivalent=(input,s)=>{const full=evaluateDependencyGraph(input);assert.deepEqual(s.results,full.results);assert.equal(s.dependencyBlockers,full.dependencyBlockers);};
test('diamond DAG supports transitive invalidation and deduplicates affected nodes',()=>{
 const f=fixture(),engine=createDependencyEvaluator(f.input),before=engine.current();assert.equal(before.dependencyBlockers,0);
 f.a.localDigest=h('revised upstream evidence');const after=engine.update(f.input);
 assert.deepEqual(new Set(after.recomputedIds),new Set([f.a,f.b,f.c,f.d].map(x=>x.requirementId)));
 for(const n of [f.b,f.c,f.d])assert.equal(by(after,n.requirementId).effectiveState,'dependency_blocked');
 assert.equal(after.dependencyBlockers,3);assert.strictEqual(by(before,f.e.requirementId),by(after,f.e.requirementId));equivalent(f.input,after);
});
test('unsatisfied and not-applicable prerequisite cannot validate a dependent',()=>{
 for(const localState of ['failed','not_applicable','integrity_failure']){
  const f=fixture();f.a.localState=localState;const v=evaluateDependencyGraph(f.input);
  assert.equal(v.dependencyBlockers,3);assert.ok(by(v,f.b.requirementId).issues.some(x=>x.reason==='prerequisite_not_satisfied'));
 }
});
test('edge repinning alone cannot repair transitive stale pins',()=>{
 const f=fixture(),engine=createDependencyEvaluator(f.input);f.a.localDigest=h('changed');let v=engine.update(f.input);
 for(const edge of f.input.edges.filter(e=>e.prerequisiteId===f.a.requirementId))edge.prerequisiteFingerprint=by(v,f.a.requirementId).fingerprint;
 v=engine.update(f.input);assert.equal(v.dependencyBlockers,1);assert.equal(by(v,f.d.requirementId).effectiveState,'dependency_blocked');equivalent(f.input,v);
 for(const edge of f.input.edges.filter(e=>e.dependentId===f.d.requirementId))edge.prerequisiteFingerprint=by(v,edge.prerequisiteId).fingerprint;
 v=engine.update(f.input);assert.equal(v.dependencyBlockers,0);equivalent(f.input,v);
});
test('rejects cycles, self edges, duplicates, cross-tenant, missing node and stale dependent versions',()=>{
 const f=fixture(),edge=f.input.edges[0],bad=[
 [...f.input.edges,{...edge,dependentId:f.a.requirementId,dependentVersionId:f.a.versionId,prerequisiteId:f.d.requirementId}],
 [{...edge,dependentId:edge.prerequisiteId,dependentVersionId:f.a.versionId}],
 [...f.input.edges,edge],[{...edge,tenantId:randomUUID()}],[{...edge,prerequisiteId:randomUUID()}],[{...edge,dependentVersionId:randomUUID()}]
 ];
 const engine=createDependencyEvaluator(f.input),before=engine.current();
 for(const edges of bad){assert.throws(()=>engine.update({...f.input,edges}),/invalid dependency graph/);assert.deepEqual(engine.current(),before);}
});
test('deterministic order, immutable cached results and no-op updates',()=>{
 const f=fixture(),engine=createDependencyEvaluator(f.input),before=engine.current();
 f.input.nodes.reverse();f.input.edges.reverse();const after=engine.update(f.input);
 assert.deepEqual(after.recomputedIds,[]);assert.deepEqual(after.results,before.results);assert.throws(()=>after.results[0].fingerprint='forged',TypeError);equivalent(f.input,after);
});
test('edge removal, node removal and revision changes correctly recompute affected closure',()=>{
 const f=fixture(),engine=createDependencyEvaluator(f.input);
 f.input.edges=f.input.edges.filter(x=>x.prerequisiteId!==f.a.requirementId);f.input.nodes=f.input.nodes.filter(x=>x!==f.a);
 let v=engine.update(f.input);assert.equal(v.results.length,4);assert.equal(v.dependencyBlockers,1);equivalent(f.input,v);
 f.b.versionId=randomUUID();v=engine.update(f.input);assert.equal(by(v,f.d.requirementId).effectiveState,'dependency_blocked');equivalent(f.input,v);
});
test('capacity limits and cross-project evaluator reuse fail closed',()=>{
 const f=fixture(),engine=createDependencyEvaluator(f.input);
 assert.throws(()=>engine.update({...f.input,scope:{...f.input.scope,projectId:randomUUID()}}),/invalid dependency graph/);
 const nodes=Array.from({length:129},()=>({...f.a,requirementId:randomUUID()}));
 assert.throws(()=>evaluateDependencyGraph({...f.input,nodes,edges:[]}),/invalid dependency graph/);
});
test('incremental and full recomputation agree through 80 deterministic edit iterations',()=>{
 const f=fixture(),engine=createDependencyEvaluator(f.input);
 for(let i=0;i<80;i++){const n=f.input.nodes[i%5];n.localDigest=h('edit '+i);n.localState=i%3===0?'failed':'satisfied';const v=engine.update(f.input);equivalent(f.input,v);}
});
