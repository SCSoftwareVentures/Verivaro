import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,randomUUID,randomBytes,generateKeyPairSync} from 'node:crypto';
import {mkdtemp,mkdir,open,rm,stat,statfs,readdir} from 'node:fs/promises';
import {createReadStream} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Readable} from 'node:stream';
import {createEncryptedBackup,verifyAndStageBackup,MAX_BACKUP_BYTES} from '../../src/security/encrypted-database-backup.mjs';
import {createEvidenceBackup,restoreEvidenceBackup,MAX_EVIDENCE_BACKUP_BYTES} from '../../src/security/evidence-recovery.mjs';
if(process.env.VV_RECOVERY_STRESS!=='database'&&process.env.VV_RECOVERY_STRESS!=='evidence')throw Error('explicit disposable stress test required');
const GiB=1024**3,MiB=1024**2;
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
async function fixture(t){
 const root=await mkdtemp(join(tmpdir(),'vv-max-recovery-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const dirs={root:join(root,'archive'),sourceRoot:join(root,'source'),destinationRoot:join(root,'destination'),spoolDirectory:join(root,'spool')};
 for(const p of Object.values(dirs))await mkdir(p,{mode:0o700});
 return {...dirs,key:randomBytes(32),installationId:randomUUID(),database:'verivaro_test',signal:new AbortController().signal};
}
async function headroom(path,bytes){const s=await statfs(path,{bigint:true});assert.ok(s.bavail*s.bsize>BigInt(bytes),'insufficient isolated stress-test disk');}
test('maximum 2 GiB encrypted logical archive streaming roundtrip',{skip:process.env.VV_RECOVERY_STRESS!=='database',timeout:240000},async t=>{
 const cfg=await fixture(t),length=2*GiB;assert.equal(MAX_BACKUP_BYTES,length);
 await headroom(cfg.root,5*GiB);
 const block=Buffer.alloc(256*1024,0x6d),count=length/block.length,h=createHash('sha256');
 const started=performance.now();
 const b=await createEncryptedBackup(Readable.from((async function*(){for(let i=0;i<count;i++){h.update(block);yield block;}})()),{...cfg,maxBytes:length});
 assert.equal(b.bytes,length);assert.equal(b.sha256,h.digest('hex'));
 const stage=await verifyAndStageBackup({...cfg,path:b.path,maxBytes:length});
 let total=0;const check=createHash('sha256');
 try{for await(const b of stage.read()){assert.ok(b.length<=256*1024);total+=b.length;check.update(b);}}finally{await stage.close();}
 assert.equal(total,length);assert.equal(check.digest('hex'),b.sha256);
 assert.deepEqual(await readdir(cfg.spoolDirectory),[]);
 const rss=process.resourceUsage().maxRSS;assert.ok(rss<448*1024);
 console.log('maximum_backup_2GiB_ms='+Math.round(performance.now()-started)+' bytes='+total+' peak_rss_KiB='+rss);
});
test('maximum 8 GiB evidence bundle and full byte integrity with sparse source and destination',{skip:process.env.VV_RECOVERY_STRESS!=='evidence',timeout:480000},async t=>{
 const cfg=await fixture(t),length=512*MiB,count=16;assert.equal(MAX_EVIDENCE_BACKUP_BYTES,length*count);
 await headroom(cfg.root,10*GiB);
 const {privateKey:signingKey,publicKey:verificationKey}=generateKeyPairSync('ed25519');
 const inventory=[];
 // Sparse fixtures have unique nonzero sentinels; ciphertext is actually
 // written at full size. Source/restore logical bytes are all read and hashed.
 for(let i=0;i<count;i++){
  const id=randomUUID(),path=join(cfg.sourceRoot,id),h=await open(path,'wx',0o600),marker=randomBytes(64);
  try{await h.truncate(length);await h.write(marker,0,marker.length,length-marker.length);await h.write(marker,0,marker.length,0);}finally{await h.close();}
  const hash=createHash('sha256');for await(const chunk of createReadStream(path))hash.update(chunk);
  inventory.push({id,sha256:hash.digest('hex')});
 }
 const databaseBackup={backupId:randomUUID(),sha256:sha('synthetic database reference'),createdAt:new Date().toISOString()};
 const started=performance.now();
 const b=await createEvidenceBackup({...cfg,inventory,databaseBackup,sequence:1,previousDigest:null,signingKey});
 assert.equal(b.bytes,length*count);assert.equal(b.objects,count);
 const restored=await restoreEvidenceBackup({...cfg,inventory,databaseBackup,path:b.path,checkpoint:b.checkpoint,verificationKey,sparseZeroBlocks:true});
 assert.equal(restored.bytes,length*count);assert.equal(restored.objects,count);
 for(const item of inventory){
  const p=join(restored.path,item.id);assert.equal((await stat(p)).size,length);
  const hash=createHash('sha256');for await(const chunk of createReadStream(p))hash.update(chunk);
  assert.equal(hash.digest('hex'),item.sha256);
 }
 assert.deepEqual(await readdir(cfg.spoolDirectory),[]);
 const rss=process.resourceUsage().maxRSS;assert.ok(rss<448*1024);
 console.log('maximum_evidence_8GiB_ms='+Math.round(performance.now()-started)+' bytes='+restored.bytes+' objects='+count+' peak_rss_KiB='+rss);
});
