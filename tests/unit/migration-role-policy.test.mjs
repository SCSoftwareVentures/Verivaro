import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {inventoryPrivilegedMigrations,PRODUCTION_ROLES,validateRoleSnapshot}
 from '../../src/security/migration-role-policy.mjs';

const source='BEGIN;\nCREATE ROLE scoped_reader NOLOGIN;\nCOMMIT;';
test('privileged role changes are excluded from automatic least privilege rollout',()=>{
 const report=inventoryPrivilegedMigrations([{path:'db/migrations/0001_sample.sql',source}]);
 assert.equal(report.requiresSeparatelyApprovedBootstrap,true);
 assert.equal(report.productionAutomaticApplyApproved,false);
 assert.deepEqual(report.privilegedFiles[0].classes,['ROLE_DDL']);
});
test('pure schema changes require further review but have no detected role bootstrap commands',()=>{
 const report=inventoryPrivilegedMigrations([
  {path:'db/migrations/0001_sample.sql',source:'BEGIN;\nCREATE TABLE test(id integer);\nCOMMIT;'}]);
 assert.equal(report.requiresSeparatelyApprovedBootstrap,false);
 assert.equal(report.productionAutomaticApplyApproved,false);
});
test('actual registered migration chain retains privileged role DDL, proving restricted first install cannot be falsely approved',async()=>{
 const lock=JSON.parse(await readFile('db/migration-lock.json','utf8'));
 const files=await Promise.all(lock.migrations.map(async row=>({
  path:row.path,source:await readFile(row.path,'utf8')
 })));
 const report=inventoryPrivilegedMigrations(files);
 assert.equal(report.fileCount,63);
 assert.equal(report.requiresSeparatelyApprovedBootstrap,true);
 assert.ok(report.privilegedFiles.some(f=>f.path==='db/migrations/0007_dual_recovery.sql'&&f.classes.includes('ROLE_DDL')));
});
const owner={name:PRODUCTION_ROLES.schemaOwner,superuser:false,createRole:false,createDb:false,
 bypassRls:false,replication:false,canLogin:false};
const executor={name:PRODUCTION_ROLES.executor,superuser:false,createRole:false,createDb:false,
 bypassRls:false,replication:false,canLogin:false,inherit:false};
const application={name:'verivaro_runtime',superuser:false,createRole:false,createDb:false,
 bypassRls:false,replication:false,canSetOwner:false,isOwnerMember:false};
const good={owner,executor,application,canExecutorSetOwner:true};
test('production role policy enforces owner/executor/service separation and disabled initial login',()=>{
 assert.equal(validateRoleSnapshot(good).roleSeparationVerified,true);
 for(const changed of [
  {owner:{...owner,canLogin:true}},
  {executor:{...executor,createRole:true}},
  {executor:{...executor,inherit:true}},
  {executor:{...executor,canLogin:true}},
  {application:{...application,isOwnerMember:true}},
  {canExecutorSetOwner:false}
 ]){
  assert.throws(()=>validateRoleSnapshot({...good,...changed}),/migration role policy rejected/);
 }
});
