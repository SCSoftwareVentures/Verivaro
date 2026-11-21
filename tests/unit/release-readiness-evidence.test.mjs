import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync,readFileSync} from 'node:fs';
import {resolve} from 'node:path';
const root=process.cwd();
const file=path=>resolve(root,path);
const manifest=JSON.parse(readFileSync(file('docs/engineering/G1_BUYER_EVIDENCE_MANIFEST_20261121.json'),'utf8'));
const statuses=new Set(['PARTIAL_CI','REFERENCE_ONLY','NOT_VERIFIED','NOT_CLEARED','NOT_VALIDATED','INDEPENDENTLY_VERIFIED']);
test('buyer evidence register uses an exact, explicit, non-certified release decision',()=>{
 assert.equal(manifest.schemaVersion,1);
 assert.equal(manifest.productReleaseApproved,false);
 assert.equal(manifest.productionSecurityCertified,false);
 assert.equal(manifest.commercialDemandValidated,false);
 assert.equal(manifest.approvedForAutomaticRecovery,false);
 assert.match(manifest.evidenceClass,/synthetic-CI/);
 assert.equal(manifest.subject,'Verivaro engineering review branch; PR #4');
});
test('every buyer-readiness gate has a unique identifier, grounded source and unresolved justification',()=>{
 assert.ok(manifest.states.length>=8);
 const ids=new Set();
 for(const gate of manifest.states){
  assert.match(gate.id,/^[A-Z][A-Z0-9_]+$/);
  assert.ok(!ids.has(gate.id));ids.add(gate.id);
  assert.ok(statuses.has(gate.status));
  assert.ok(Array.isArray(gate.sources)&&gate.sources.length>0);
  assert.ok(typeof gate.blocker==='string'&&gate.blocker.length>=35);
  for(const path of gate.sources){
   assert.match(path,/^[\w.][\w./-]+$/);
   assert.ok(!path.includes('..'));
   assert.ok(existsSync(file(path)), 'Missing buyer evidence path: '+path);
  }
 }
});
test('P0-D buyer handover claims only scoped historical CI, never production clearance',()=>{
 const gate=manifest.states.find(x=>x.id==='G1_P0D_HANDOVER');
 assert.ok(gate,'Missing G1 handover gate');
 assert.equal(gate.status,'PARTIAL_CI');
 for(const name of [
  'tests/unit/buyer-portable-bundle.test.mjs',
  'tests/browser/offline-buyer-browser.test.mjs',
  'tests/integration/live-requirement-graph.test.mjs',
  'docs/engineering/G1_P0D_HANDOVER_OFFLINE_GATE_20261121.md',
  '.github/workflows/buyer-bundle.yml'
 ]){
  assert.ok(gate.sources.includes(name),'Missing P0-D evidence path '+name);
 }
 assert.match(gate.blocker,/86b9977f|Requalification is required/i);
 assert.equal(manifest.productReleaseApproved,false);
 assert.equal(manifest.commercialDemandValidated,false);
});

test('IP and license inventory remain explicitly NOT_CLEARED',()=>{
 const gate=manifest.states.find(x=>x.id==='BUYER_IP');
 assert.equal(gate.status,'NOT_CLEARED');
 assert.ok(gate.sources.includes('src/security/buyer-ip-inventory.mjs'));
 assert.ok(gate.sources.includes('tests/unit/buyer-ip-inventory.test.mjs'));
 assert.ok(gate.sources.includes('docs/engineering/G1_P0E_IP_DUE_DILIGENCE_20261121.md'));
 assert.match(gate.blocker,/legal|licence|ownership|trademark/i);
});
test('production, sale and automated recovery claims are blocked while unresolved gates remain',()=>{
 const unresolved=manifest.states.filter(x=>x.status!=='INDEPENDENTLY_VERIFIED');
 assert.ok(unresolved.length>0);
 if(unresolved.length){
  assert.equal(manifest.productReleaseApproved,false);
  assert.equal(manifest.productionSecurityCertified,false);
  assert.equal(manifest.commercialDemandValidated,false);
  assert.equal(manifest.approvedForAutomaticRecovery,false);
 }
});
test('release-facing README and status link the audited evidence register and accurate cautions',()=>{
 const readme=readFileSync(file('README.md'),'utf8');
 const status=readFileSync(file('docs/engineering/STATUS.md'),'utf8');
 const audit=readFileSync(file('docs/engineering/G1_PRODUCTION_TRUST_BOUNDARY_BUYER_AUDIT_20261121.md'),'utf8');
 assert.match(readme,/G1_BUYER_EVIDENCE_MANIFEST_20261121\.json/);
 assert.match(readme,/not a production-ready or sale-validated application/i);
 assert.match(status,/Release status: NOT APPROVED/);
 assert.match(audit,/no independently evidenced demand or valuation range/i);
});
test('maximum recovery capacity CI includes the active unmerged audit branch',()=>{
 const workflow=readFileSync(file('.github/workflows/recovery-capacity.yml'),'utf8');
 assert.match(workflow,/audit\/g1-restore-catalog-verification-20261121/);
 assert.match(workflow,/matrix:\s*\n\s*capacity:\s*\[database, evidence\]/);
 assert.match(workflow,/tests\/stress\/maximum-recovery\.test\.mjs/);
});
