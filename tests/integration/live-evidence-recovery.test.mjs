import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {resolve,join} from 'node:path';
import {randomUUID,randomBytes,generateKeyPairSync,createHash} from 'node:crypto';
import {mkdtemp,mkdir,writeFile,readFile,readdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {readRecoveryInventory,createEvidenceBackup,restoreEvidenceBackup} from '../../src/security/evidence-recovery.mjs';
import {verifyAndStageBackup} from '../../src/security/encrypted-database-backup.mjs';
if(process.env.VV_LIVE_TEST!=='1'||process.env.PGDATABASE!=='verivaro_test'||!process.env.VV_TEST_DRIVER_DIR||!process.env.VV_CI_BACKUP_PATH)throw Error('disposable CI only');
const {Pool}=createRequire(resolve(process.env.VV_TEST_DRIVER_DIR,'package.json'))('pg');
const config={host:process.env.PGHOST,port:Number(process.env.PGPORT),user:process.env.PGUSER,password:process.env.PGPASSWORD,database:'verivaro_restore_ci',max:2};
const sha=x=>createHash('sha256').update(x).digest('hex');
test('real restored database inventory rejects missing legacy evidence and subset receipts',{timeout:30000},async()=>{
 const db=new Pool(config);
 const dir=await mkdtemp(join(tmpdir(),'vv-live-evidence-'));
 const root=join(dir,'backup'),sourceRoot=join(dir,'source'),destinationRoot=join(dir,'restore'),spoolDirectory=join(dir,'spool');
 for(const p of [root,sourceRoot,destinationRoot,spoolDirectory])await mkdir(p,{mode:0o700});
 const {privateKey:signingKey,publicKey:verificationKey}=generateKeyPairSync('ed25519');
 const cfg={root,sourceRoot,destinationRoot,spoolDirectory,key:Buffer.from(process.env.VV_BACKUP_KEY,'base64url'),installationId:process.env.VV_INSTALLATION_ID,database:'verivaro_test',signal:new AbortController().signal,sequence:1,previousDigest:null,signingKey,verificationKey};
 try{
  const inventory=await readRecoveryInventory(db);assert.ok(inventory.length>0);
  const staged=await verifyAndStageBackup({...cfg,path:process.env.VV_CI_BACKUP_PATH});
  const databaseBackup={backupId:staged.backupId,sha256:staged.sha256,createdAt:staged.createdAt};await staged.close();
  // The earlier adversarial suite deliberately uses placeholder digests and
  // fictitious objects. A complete restore MUST reject those absent objects.
  await assert.rejects(createEvidenceBackup({...cfg,inventory,databaseBackup}));assert.deepEqual(await readdir(root),[]);
  // Actual object roundtrip: separate SQL-backed synthetic inventory, not a
  // claim that the earlier placeholder database has complete real evidence.
  const c=await db.connect();
  try{
   await c.query('CREATE TEMP TABLE recovery_fixture(id uuid PRIMARY KEY,sha256 text NOT NULL)');
   const items=[Buffer.from('synthetic evidence bytes'),Buffer.alloc(1024*1024,0x41)].map(data=>({id:randomUUID(),data,sha256:sha(data)}));
   for(const o of items){await c.query('INSERT INTO recovery_fixture VALUES($1,$2)',[o.id,o.sha256]);await writeFile(join(sourceRoot,o.id),o.data,{mode:0o600});}
   const full=(await c.query('SELECT id,sha256 FROM recovery_fixture ORDER BY id')).rows;
   const b=await createEvidenceBackup({...cfg,inventory:full,databaseBackup});
   await assert.rejects(restoreEvidenceBackup({...cfg,inventory,databaseBackup,path:b.path,checkpoint:b.checkpoint}));
   const receipt=await restoreEvidenceBackup({...cfg,inventory:full,databaseBackup,path:b.path,checkpoint:b.checkpoint});
   for(const o of items)assert.deepEqual(await readFile(join(receipt.path,o.id)),o.data);
   await assert.rejects(c.query('INSERT INTO verivaro_private.restoration_evidence_receipt(backup_id,catalogue_sha256,inventory_sha256) VALUES($1,$2,$3)',[receipt.backupId,receipt.catalogSha256,receipt.inventorySha256]),e=>e.code==='42501');
  }finally{c.release(true);}
 }finally{await db.end();await rm(dir,{recursive:true,force:true});}
});

const exec=promisify(execFile);
test('complete real PostgreSQL and evidence bundle restore with independent review gate',{timeout:60000},async()=>{
 const sourceDb='verivaro_bundle_ci',targetDb='verivaro_restore_bundle_ci';
 const source=new Pool({...config,database:sourceDb});
 const dir=await mkdtemp(join(tmpdir(),'vv-full-recovery-'));
 const root=join(dir,'backup'),sourceRoot=join(dir,'source'),destinationRoot=join(dir,'restore'),spoolDirectory=join(dir,'spool');
 for(const p of [root,sourceRoot,destinationRoot,spoolDirectory])await mkdir(p,{mode:0o700});
 const {privateKey:signingKey,publicKey:verificationKey}=generateKeyPairSync('ed25519');
 const key=randomBytes(32),installationId=randomUUID();
 const cfg={root,sourceRoot,destinationRoot,spoolDirectory,key,installationId,database:sourceDb,signal:new AbortController().signal,sequence:1,previousDigest:null,signingKey,verificationKey};
 let target;
 try{
  const tenant=randomUUID(),project=randomUUID(),actor=randomUUID();
  const items=[Buffer.from('actual evidence fixture'),Buffer.alloc(1024*1024+17,0x53)].map(data=>({id:randomUUID(),data,sha256:sha(data)}));
  await source.query('INSERT INTO verivaro.tenants(id,name) VALUES($1,$2)',[tenant,'Synthetic recovery tenant']);
  await source.query('INSERT INTO verivaro.projects(id,tenant_id,name) VALUES($1,$2,$3)',[project,tenant,'Synthetic project']);
  await source.query("INSERT INTO verivaro.memberships(tenant_id,actor_id,role) VALUES($1,$2,'owner')",[tenant,actor]);
  await source.query("INSERT INTO verivaro.project_members(tenant_id,project_id,actor_id,role) VALUES($1,$2,$3,'owner')",[tenant,project,actor]);
  await source.query('INSERT INTO verivaro_private.context_key(key_bytes) VALUES(verivaro_private.gen_random_bytes(32))');
  await source.query('INSERT INTO verivaro_private.monitor_state(singleton) VALUES(true)');
  await source.query("INSERT INTO verivaro.evidence(id,tenant_id,project_id,sha256,storage_ref,created_by) VALUES($1,$2,$3,$4,$5,$6)",[items[0].id,tenant,project,items[0].sha256,'private://'+items[0].id,actor]);
  await source.query('SELECT verivaro_sharing.register_export($1,$2,$3,$4,$5,false)',[randomUUID(),tenant,project,items[1].id,items[1].sha256]);
  for(const item of items)await writeFile(join(sourceRoot,item.id),item.data,{mode:0o600});
  const env={...process.env,PGDATABASE:sourceDb,VV_BACKUP_KEY:key.toString('base64url'),VV_INSTALLATION_ID:installationId};
  const started=performance.now();
  const {stdout}=await exec(process.execPath,['services/database-recovery/main.mjs','backup',root],{env,timeout:30000});
  const databaseBackup=JSON.parse(stdout.trim()),inventory=await readRecoveryInventory(source);
  assert.equal(inventory.length,2);
  const b=await createEvidenceBackup({...cfg,inventory,databaseBackup});
  await exec(process.execPath,['services/database-recovery/main.mjs','restore',databaseBackup.path,targetDb],{env:{...env,VV_RESTORE_APPROVED:'1',VV_RESTORE_SPOOL:spoolDirectory},timeout:30000});
  target=new Pool({...config,database:targetDb});
  const restoredInventory=await readRecoveryInventory(target);
  assert.deepEqual(restoredInventory,inventory);
  const receipt=await restoreEvidenceBackup({...cfg,inventory:restoredInventory,databaseBackup,path:b.path,checkpoint:b.checkpoint});
  for(const item of items)assert.deepEqual(await readFile(join(receipt.path,item.id)),item.data);
  const c=await target.connect();
  try{
   await c.query('BEGIN');
   await c.query('CREATE ROLE vv_ci_restore_a LOGIN NOINHERIT');
   await c.query('CREATE ROLE vv_ci_restore_b LOGIN NOINHERIT');
   await c.query('GRANT verivaro_restore_reviewer TO vv_ci_restore_a,vv_ci_restore_b');
   const as=async user=>{await c.query('RESET ROLE');await c.query('RESET SESSION AUTHORIZATION');await c.query('SET SESSION AUTHORIZATION '+user);await c.query('SET ROLE verivaro_restore_reviewer');};
   const reset=async()=>{await c.query('RESET ROLE');await c.query('RESET SESSION AUTHORIZATION');};
   const review=()=>c.query('SELECT verivaro_recovery.attest_review($1,$2,$3,$4) AS ok',[receipt.backupId,receipt.catalogSha256,receipt.inventorySha256,randomUUID()]);
   await as('vv_ci_restore_a');assert.equal((await review()).rows[0].ok,false);await reset();
   await c.query('INSERT INTO verivaro_private.restoration_evidence_receipt(backup_id,catalogue_sha256,inventory_sha256) VALUES($1,$2,$3)',[receipt.backupId,receipt.catalogSha256,receipt.inventorySha256]);
   await as('vv_ci_restore_a');assert.equal((await review()).rows[0].ok,true);assert.equal((await review()).rows[0].ok,false);
   assert.equal((await c.query('SELECT * FROM verivaro_recovery.review_status()')).rows[0].review_ready,false);
   await as('vv_ci_restore_b');assert.equal((await review()).rows[0].ok,true);
   assert.equal((await c.query('SELECT * FROM verivaro_recovery.review_status()')).rows[0].review_ready,true);
   await reset();
   await c.query('REVOKE verivaro_restore_reviewer FROM vv_ci_restore_a');
   assert.equal((await c.query('SELECT * FROM verivaro_recovery.review_status()')).rows[0].review_ready,false);
   assert.equal((await c.query("SELECT has_database_privilege('verivaro_runtime',current_database(),'CONNECT') AS ok")).rows[0].ok,false);
   assert.equal((await c.query('SELECT count(*)::int AS n FROM verivaro_private.disabled_actors WHERE actor_id=$1',[actor])).rows[0].n,1);
   await c.query('ROLLBACK');
  }finally{c.release(true);}
  console.log('complete_database_evidence_restore_ms='+Math.round(performance.now()-started)+' objects='+receipt.objects+' evidence_bytes='+receipt.bytes);
 }finally{await target?.end();await source.end();await rm(dir,{recursive:true,force:true});key.fill(0);}
});
