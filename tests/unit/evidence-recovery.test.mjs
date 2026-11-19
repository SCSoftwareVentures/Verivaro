import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,randomBytes,randomUUID} from 'node:crypto';
import {mkdtemp,mkdir,writeFile,readFile,readdir,rm,symlink} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createEvidenceBackup,restoreEvidenceBackup,normalizeRecoveryInventory} from '../../src/security/evidence-recovery.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
async function fixture(t){
 const dir=await mkdtemp(join(tmpdir(),'vv-bundle-'));t.after(()=>rm(dir,{recursive:true,force:true}));
 const root=join(dir,'backup'),sourceRoot=join(dir,'source'),destinationRoot=join(dir,'restore'),spoolDirectory=join(dir,'spool');
 for(const p of [root,sourceRoot,destinationRoot,spoolDirectory])await mkdir(p,{mode:0o700});
 const objects=[Buffer.from('private evidence A'),Buffer.alloc(1024*1024+7,0x42)].map(data=>({id:randomUUID(),data,sha256:sha(data)}));
 for(const o of objects)await writeFile(join(sourceRoot,o.id),o.data,{mode:0o600});
 const {privateKey:signingKey,publicKey:verificationKey}=generateKeyPairSync('ed25519');
 const cfg={root,sourceRoot,destinationRoot,spoolDirectory,inventory:objects.map(({id,sha256})=>({id,sha256})),databaseBackup:{backupId:randomUUID(),sha256:sha('database'),createdAt:new Date().toISOString()},sequence:1,previousDigest:null,signingKey,verificationKey,key:randomBytes(32),installationId:randomUUID(),database:'verivaro_test',signal:new AbortController().signal};
 return {cfg,objects};
}
test('complete evidence bundle restores only exact database inventory under signed trusted checkpoint',async t=>{
 const {cfg,objects}=await fixture(t);const b=await createEvidenceBackup(cfg);
 const restored=await restoreEvidenceBackup({...cfg,path:b.path,checkpoint:b.checkpoint});
 assert.equal(restored.objects,2);for(const o of objects)assert.deepEqual(await readFile(join(restored.path,o.id)),o.data);
 assert.equal((await readdir(cfg.spoolDirectory)).length,0);
});
test('missing, changed and conflicting objects fail closed without publishing a partial bundle',async t=>{
 const {cfg,objects}=await fixture(t);
 assert.throws(()=>normalizeRecoveryInventory([...cfg.inventory,{id:objects[0].id,sha256:'f'.repeat(64)}]));
 await rm(join(cfg.sourceRoot,objects[0].id));await assert.rejects(createEvidenceBackup(cfg));assert.deepEqual(await readdir(cfg.root),[]);
 await symlink(join(cfg.sourceRoot,objects[1].id),join(cfg.sourceRoot,objects[0].id));await assert.rejects(createEvidenceBackup(cfg));assert.deepEqual(await readdir(cfg.root),[]);
});
test('rollback, stale, wrong database, missing inventory and corrupt object rejected before publishing',async t=>{
 const {cfg}=await fixture(t);const b=await createEvidenceBackup(cfg),args={...cfg,path:b.path,checkpoint:b.checkpoint};
 for(const override of [{checkpoint:{...b.checkpoint,sequence:2}},{checkpoint:{...b.checkpoint,catalogSha256:'a'.repeat(64)}},{now:Date.now()+2*86400000},{databaseBackup:{...cfg.databaseBackup,backupId:randomUUID()}},{inventory:cfg.inventory.slice(0,1)},{verificationKey:generateKeyPairSync('ed25519').publicKey}])await assert.rejects(restoreEvidenceBackup({...args,...override}));
 const catalog=JSON.parse(await readFile(join(b.path,'catalog.json'),'utf8'));
 const file=join(b.path,'backup-'+catalog.objects[1].backupId,'archive.enc'),bytes=await readFile(file);bytes[0]^=1;await writeFile(file,bytes);
 await assert.rejects(restoreEvidenceBackup(args));assert.deepEqual(await readdir(cfg.destinationRoot),[]);
});
