import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {compareSubmissionGraph} from '../../src/security/change-impact.mjs';
const hash=s=>createHash('sha256').update(s).digest('hex');
function fixture(){
 const scope={tenantId:randomUUID(),projectId:randomUUID(),submissionId:randomUUID()};
 const q=()=>({requirementId:randomUUID(),versionId:randomUUID(),revision:1,title:'Report',criterion:'Reviewed report',applicability:'required',provenance:'manual',source:null,ruleDecision:'approved',ruleReason:'Reviewed',state:'satisfied',links:[{linkId:randomUUID(),evidenceId:randomUUID(),sha256:hash('proof'),decision:'pass',reason:'Verified',integrity:true}]});
 const g={version:1,tenantId:scope.tenantId,projectId:scope.projectId,archived:false,summary:{requirements:2,required:2,verifiedRequired:2,blockers:0,status:'criteria_satisfied'},requirements:[q(),q()]};
 const manifest=JSON.stringify(g),baseline={submissionId:scope.submissionId,manifest,sha256:hash(manifest)};
 return {scope,baseline,g,compare:()=>compareSubmissionGraph(baseline,g,scope)};
}
test('ignores view hints, timestamps, and order; historical manifest remains unchanged',()=>{
 const f=fixture(),before=f.baseline.manifest;
 f.g.requirements.reverse();f.g.evaluatedAt='now';f.g.requirements[0].canReview=true;f.g.requirements[1].links[0].canReview=false;
 assert.equal(f.compare().changedCount,0);assert.equal(f.compare().unchangedCount,2);assert.equal(f.baseline.manifest,before);
});
test('revision change resets proof on affected requirement without attributing impact to unrelated requirements',()=>{
 const f=fixture(),q=f.g.requirements[0];
 q.versionId=randomUUID();q.revision++;q.criterion='New report';q.ruleDecision='pending';q.ruleReason=null;q.links=[];q.state='awaiting_rule_review';
 Object.assign(f.g.summary,{verifiedRequired:1,blockers:1,status:'blocked'});
 const d=f.compare();assert.equal(d.changedCount,1);assert.equal(d.unchangedCount,1);assert.equal(d.currentStatus,'blocked');assert.equal(d.changes[0].requirementId,q.requirementId);
 assert.ok(d.changes[0].reasons.includes('criterion_revision_changed'));assert.ok(d.changes[0].reasons.includes('evidence_links_changed'));assert.equal(d.changes[0].affectedEvidenceIds.length,1);
});
test('integrity or review change is reported even when version is unchanged',()=>{
 const f=fixture(),q=f.g.requirements[0];q.links[0].integrity=false;q.state='integrity_failure';q.links[0].decision='fail';
 Object.assign(f.g.summary,{verifiedRequired:1,blockers:1,status:'blocked'});
 const d=f.compare();assert.ok(d.changes[0].reasons.includes('evidence_integrity_changed'));assert.ok(d.changes[0].reasons.includes('evidence_review_changed'));
});
test('detects added and missing requirements and rejects inconsistent summary or scope',()=>{
 const f=fixture(),old=f.g.requirements.pop();let fresh=structuredClone(old);fresh.requirementId=randomUUID();fresh.versionId=randomUUID();f.g.requirements.push(fresh);
 const d=f.compare();assert.equal(d.changedCount,2);assert.ok(d.changes.some(x=>x.reasons[0]==='requirement_missing'));assert.ok(d.changes.some(x=>x.reasons[0]==='requirement_added'));
 f.g.summary.blockers=10;assert.throws(f.compare);f.g.summary.blockers=0;
 assert.throws(()=>compareSubmissionGraph(f.baseline,f.g,{...f.scope,tenantId:randomUUID()}));
 assert.throws(()=>compareSubmissionGraph({...f.baseline,manifest:f.baseline.manifest+' '},f.g,f.scope));
});
