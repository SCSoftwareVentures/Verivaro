import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
import {mkdtemp,readFile,writeFile,readdir,rm,chmod} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Readable} from 'node:stream';
import {createEncryptedBackup,verifyAndStageBackup} from '../../src/security/encrypted-database-backup.mjs';
const signal=()=>new AbortController().signal;
async function setup(t){
 const root=await mkdtemp(join(tmpdir(),'vv-backup-'));t.after(()=>rm(root,{recursive:true,force:true}));
 return {root,spoolDirectory:root,key:randomBytes(32),installationId:randomUUID(),database:'verivaro_test',signal:signal()};
}
test('authenticated backup, no plaintext artifact, exact restoration and scope binding',async t=>{
 const cfg=await setup(t),data=Buffer.from('synthetic database evidence '.repeat(20000));
 const b=await createEncryptedBackup(Readable.from([data]),cfg);
 const cipher=await readFile(join(b.path,'archive.enc'));
 assert.notDeepEqual(cipher,data);assert.equal(cipher.includes(Buffer.from('synthetic database evidence')),false);
 const s=await verifyAndStageBackup({...cfg,path:b.path});
 try{const chunks=[];for await(const c of s.read())chunks.push(c);assert.deepEqual(Buffer.concat(chunks),data);}finally{await s.close();}
 for(const override of [{key:randomBytes(32)},{installationId:randomUUID()},{database:'other_db'},{maxBytes:1}])await assert.rejects(verifyAndStageBackup({...cfg,path:b.path,...override}));
});
test('modified manifest, ciphertext and truncated data rejected before restore',async t=>{
 const cfg=await setup(t),data=Buffer.from('fixture');
 const b=await createEncryptedBackup(Readable.from([data]),cfg),mf=join(b.path,'manifest.json'),af=join(b.path,'archive.enc');
 const original=await readFile(mf),cipher=await readFile(af);
 const m=JSON.parse(original);m.sha256='a'.repeat(64);await writeFile(mf,JSON.stringify(m));
 await assert.rejects(verifyAndStageBackup({...cfg,path:b.path}));await writeFile(mf,original);
 const corrupt=Buffer.from(cipher);corrupt[0]^=1;await writeFile(af,corrupt);await assert.rejects(verifyAndStageBackup({...cfg,path:b.path}));
 await writeFile(af,cipher.subarray(0,1));await assert.rejects(verifyAndStageBackup({...cfg,path:b.path}));
 assert.deepEqual(await readdir(cfg.root),['backup-'+b.backupId]);
});
test('failed dump, size limit and abort cannot publish partial backup',async t=>{
 const cfg=await setup(t);
 for(const extras of [{assertComplete:async()=>{throw Error('dump failure');}},{maxBytes:1}]){
  await assert.rejects(createEncryptedBackup(Readable.from([Buffer.from('fixture')]),{...cfg,...extras}));
  assert.deepEqual(await readdir(cfg.root),[]);
 }
 const ctrl=new AbortController();ctrl.abort();
 await assert.rejects(createEncryptedBackup(Readable.from([Buffer.from('fixture')]),{...cfg,signal:ctrl.signal}));assert.deepEqual(await readdir(cfg.root),[]);
});
