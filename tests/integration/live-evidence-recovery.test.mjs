import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
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
test('real restored database inventory rejects missing legacy evidence; review requires matching receipt and distinct reviewers',{timeout:30000},async()=>{
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
   // Review fixture: simulated administrator receipt, never a real approval of
   // the incomplete legacy inventory. All changes rolled back.
   await c.query('BEGIN');
   try{
    await c.query('CREATE ROLE vv_ci_restore_a LOGIN NOINHERIT');
    await c.query('CREATE ROLE vv_ci_restore_b LOGIN NOINHERIT');
    await c.query('GRANT verivaro_restore_reviewer TO vv_ci_restore_a,vv_ci_restore_b');
    await c.query('SET SESSION AUTHORIZATION vv_ci_restore_a');
    await c.query('SET ROLE verivaro_restore_reviewer');
    const review=(ref)=>c.query('SELECT verivaro_recovery.attest_review($1,$2,$3,$4) AS ok',[receipt.backupId,receipt.catalogSha256,receipt.inventorySha256,ref]);
    assert.equal((await review(randomUUID())).rows[0].ok,false);
    await c.query('RESET ROLE');await c.query('RESET SESSION AUTHORIZATION');
    await c.query('INSERT INTO verivaro_private.restoration_evidence_receipt(backup_id,catalogue_sha256,inventory_sha256) VALUES($1,$2,$3)',[receipt.backupId,receipt.catalogSha256,receipt.inventorySha256]);
    await c.query('SET SESSION AUTHORIZATION vv_ci_restore_a');await c.query('SET ROLE verivaro_restore_reviewer');
    assert.equal((await review(randomUUID())).rows[0].ok,true);assert.equal((await review(randomUUID())).rows[0].ok,false);
    assert.equal((await c.query('SELECT * FROM verivaro_recovery.review_status()')).rows[0].review_ready,false);
    await c.query('RESET ROLE');await c.query('RESET SESSION AUTHORIZATION');
    await c.query('SET SESSION AUTHORIZATION vv_ci_restore_b');await c.query('SET ROLE verivaro_restore_reviewer');
    assert.equal((await review(randomUUID())).rows[0].ok,true);
    assert.equal((await c.query('SELECT * FROM verivaro_recovery.review_status()')).rows[0].review_ready,true);
    await c.query('RESET ROLE');await c.query('RESET SESSION AUTHORIZATION');
    assert.equal((await c.query("SELECT has_database_privilege('verivaro_runtime',current_database(),'CONNECT') AS ok")).rows[0].ok,false);
    await c.query('ROLLBACK');
   }catch(e){await c.query('ROLLBACK');throw e;}
  }finally{c.release(true);}
 }finally{await db.end();await rm(dir,{recursive:true,force:true});}
});
