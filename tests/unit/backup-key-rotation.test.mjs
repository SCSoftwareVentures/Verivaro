import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID,createHash} from 'node:crypto';
import {mkdtemp,readFile,writeFile,rm,statfs} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Readable} from 'node:stream';
import {createBackupKeyring} from '../../src/security/backup-keyring.mjs';
import {createEncryptedBackup,verifyAndStageBackup,MAX_BACKUP_BYTES} from '../../src/security/encrypted-database-backup.mjs';
async function setup(t){const root=await mkdtemp(join(tmpdir(),'vv-rotation-'));t.after(()=>rm(root,{recursive:true,force:true}));return {root,spoolDirectory:root,installationId:randomUUID(),database:'verivaro_test',signal:new AbortController().signal};}
const input=()=>Readable.from([Buffer.from('synthetic backup record')]);
test('rotation selects only authenticated key ID, old archives remain recoverable, new writes use active key',async t=>{
 const cfg=await setup(t),old=randomBytes(32),next=randomBytes(32),legacy=randomBytes(32);
 const a=createBackupKeyring({activeId:'old',keys:[{id:'old',key:old}]});
 const b=createBackupKeyring({activeId:'next',keys:[{id:'old',key:old},{id:'next',key:next}],legacyKey:legacy});
 const c=createBackupKeyring({activeId:'next',keys:[{id:'next',key:next}]});
 t.after(()=>{a.close();b.close();c.close();});
 const original=await createEncryptedBackup(input(),{...cfg,keyring:a});
 const newer=await createEncryptedBackup(input(),{...cfg,keyring:b});
 const legacyBackup=await createEncryptedBackup(input(),{...cfg,key:legacy});
 assert.equal(original.keyId,'old');assert.equal(newer.keyId,'next');
 for(const archive of [original,newer,legacyBackup]){
  const s=await verifyAndStageBackup({...cfg,path:archive.path,keyring:b});
  try{assert.equal(s.keyId,archive.keyId);assert.equal(s.sha256,archive.sha256);}finally{await s.close();}
 }
 await assert.rejects(verifyAndStageBackup({...cfg,path:original.path,keyring:c}));
 await assert.rejects(verifyAndStageBackup({...cfg,path:legacyBackup.path,keyring:c}));
 await assert.rejects(verifyAndStageBackup({...cfg,path:newer.path,key:next}));
 const file=join(original.path,'manifest.json'),m=JSON.parse(await readFile(file));m.keyId='next';await writeFile(file,JSON.stringify(m));
 await assert.rejects(verifyAndStageBackup({...cfg,path:original.path,keyring:b}));
});
test('1 GiB streaming backup and restore exceeds previous capacity with bounded memory',{timeout:90000},async t=>{
 const cfg=await setup(t),key=randomBytes(32),length=1024*1024*1024,block=Buffer.alloc(256*1024,0x7b),count=length/block.length;
 const volume=await statfs(cfg.root,{bigint:true});assert.ok(volume.bavail*volume.bsize>BigInt(length*2+128*1024*1024),'insufficient isolated test disk');
 assert.equal(MAX_BACKUP_BYTES,2*1024*1024*1024);
 const started=performance.now();
 const source=Readable.from((async function*(){for(let i=0;i<count;i++)yield block;})());
 const b=await createEncryptedBackup(source,{...cfg,key,maxBytes:length});
 const staged=await verifyAndStageBackup({...cfg,path:b.path,key,maxBytes:length});
 try{
  let received=0;const h=createHash('sha256');
  for await(const bytes of staged.read()){assert.ok(bytes.length<=256*1024);h.update(bytes);received+=bytes.length;}
  assert.equal(received,length);assert.equal(h.digest('hex'),b.sha256);
 }finally{await staged.close();}
 const rss=process.resourceUsage().maxRSS;
 if(process.platform==='linux')assert.ok(rss<448*1024,'unexpected full-file memory allocation');
 console.log('encrypted_backup_1GiB_roundtrip_ms='+Math.round(performance.now()-started)+' peak_rss_KiB='+rss);
});
