import test from 'node:test';
import assert from 'node:assert/strict';
import {buildRemediationDrafts} from '../../src/security/remediation-drafts.mjs';
const id=n=>'00000000-0000-4000-8000-'+String(n).padStart(12,'0');
const fixture=()=>({tenantId:id(1),projectId:id(2),archived:false,requirements:[{requirementId:id(3),versionId:id(4),title:'A'},{requirementId:id(5),versionId:id(6),title:'B'}],preflight:{issues:[{requirementId:id(3),action:'Capture evidence',code:'MISSING_EVIDENCE',level:'blocker',responsible:'contributor'},{requirementId:id(5),action:'Collect proof',code:'MISSING_EVIDENCE',level:'blocker',responsible:'contributor'}]}});
const task=(n,v,r,a=10)=>({taskId:id(n),requirementId:id(r),versionId:id(v),assigneeId:id(a),current:true,state:'assigned'});
test('consolidate exact assignments without automatic action',()=>{const d=buildRemediationDrafts(fixture(),[task(11,4,3),task(12,6,5)]);assert.equal(d.drafts.length,1);assert.deepEqual(d.drafts[0].requirementIds,[id(3),id(5)]);assert.equal(d.corrections.length,2);});
test('ambiguous, stale and reviewer actions never get automatic recipient',()=>{const f=fixture();f.preflight.issues[1].responsible='reviewer';const d=buildRemediationDrafts(f,[task(11,4,3),task(12,4,3,13),task(14,6,5)]);assert.equal(d.drafts.length,0);assert.equal(d.unassigned.length,2);f.archived=true;assert.equal(buildRemediationDrafts(f,[task(11,4,3)]).drafts.length,0);});
