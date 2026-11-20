import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {buildRejectionPreflight} from '../../src/security/rejection-preflight.mjs';
const row=(state,applicability='required',extra={})=>({requirementId:randomUUID(),criterion:randomUUID(),state,applicability,links:[],...extra});
function graph(requirements){
 const required=requirements.filter(x=>x.applicability==='required').length,verifiedRequired=requirements.filter(x=>x.applicability==='required'&&x.state==='satisfied').length;
 const blockers=requirements.filter(x=>['integrity_failure','rule_rejected','awaiting_rule_review','unknown_applicability'].includes(x.state)||x.applicability==='required'&&x.state!=='satisfied').length;
 return {version:1,archived:false,requirements,summary:{requirements:requirements.length,required,verifiedRequired,blockers,status:blockers?'blocked':required?'criteria_satisfied':'not_assessed'}};
}
test('zero requirements never indicates readiness; coverage is scoped and floored',()=>{
 const no=buildRejectionPreflight(graph([]));assert.equal(no.status,'not_assessed');assert.equal(no.mandatoryCoveragePercent,null);
 const partial=buildRejectionPreflight(graph([row('satisfied'),row('satisfied'),row('missing_evidence')]));assert.equal(partial.mandatoryCoveragePercent,66);assert.equal(partial.blockers,1);
});
test('security risks outrank workflow deficiencies and optional warnings',()=>{
 const result=buildRejectionPreflight(graph([row('missing_evidence'),row('integrity_failure','optional'),row('failed','optional'),row('conflict'),row('rule_rejected','not_applicable'),row('unknown_applicability','unknown'),row('unresolved_evidence')]));
 assert.equal(result.status,'blocked');assert.equal(result.blockers,6);assert.equal(result.advisories,1);assert.equal(result.issues[0].code,'INTEGRITY_FAILURE');assert.equal(result.issues.at(-1).level,'advisory');
});
test('duplicate criteria and bytes and source use are advisory not independent evidence',()=>{
 const id=randomUUID(),sha256='a'.repeat(64),rows=[row('satisfied','required',{criterion:'Must comply.',source:{evidenceId:id},links:[{evidenceId:id,sha256},{evidenceId:randomUUID(),sha256}]}),row('not_applicable','not_applicable',{criterion:' MUST  COMPLY. '})];
 const r=buildRejectionPreflight(graph(rows));assert.equal(r.blockers,0);assert.equal(r.advisories,3);assert.ok(r.warnings.some(x=>x.code==='DUPLICATE_CRITERION_DIFFERENT_APPLICABILITY'));assert.ok(r.warnings.some(x=>x.code==='SOURCE_USED_AS_EVIDENCE'));assert.ok(r.warnings.some(x=>x.code==='DUPLICATE_EVIDENCE_BYTES'));
});
test('inconsistent snapshot or unsupported state fails closed',()=>{
 const g=graph([row('missing_evidence')]);assert.throws(()=>buildRejectionPreflight({...g,summary:{...g.summary,blockers:0,status:'criteria_satisfied'}}));assert.throws(()=>buildRejectionPreflight(graph([row('invented')])));assert.throws(()=>buildRejectionPreflight(graph([row('not_applicable')])));
});
