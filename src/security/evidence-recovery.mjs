import {createHash,sign,verify,randomUUID,createPrivateKey,createPublicKey} from 'node:crypto';
import {open,mkdtemp,rename,rm,stat} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join,isAbsolute} from 'node:path';
import {createEncryptedBackup,verifyAndStageBackup} from './encrypted-database-backup.mjs';
import {backupKeyConfigValid} from './backup-keyring.mjs';
import {createPrivateFileStore,isArtifactId} from './private-file-store.mjs';
const LIMIT=4096,MAX_TOTAL=8*1024*1024*1024,MAX_MANIFEST=2*1024*1024;
const hash=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const digest=x=>createHash('sha256').update(x).digest('hex');
const validDate=x=>typeof x==='string'&&new Date(x).toISOString()===x;
async function privateDir(p){if(typeof p!=='string'||!isAbsolute(p))throw Error('private directory required');const s=await stat(p);if(!s.isDirectory()||(s.mode&0o077)!==0)throw Error('private directory required');}
async function syncDir(p){const h=await open(p,constants.O_RDONLY|constants.O_DIRECTORY);try{await h.sync();}finally{await h.close();}}
async function readBounded(p){
 const h=await open(p,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{const s=await h.stat();if(!s.isFile()||s.size<1||s.size>MAX_MANIFEST)throw Error('invalid catalog size');const b=Buffer.alloc(s.size);let n=0;while(n<b.length){const r=await h.read(b,n,b.length-n,n);if(!r.bytesRead)throw Error('truncated catalog');n+=r.bytesRead;}return b;}finally{await h.close();}
}
// Stable object ID is evidence.id or released_exports.artifact_id. Storage
// references are never interpreted as paths, URLs, or credentials.
export function normalizeRecoveryInventory(rows){
 if(!Array.isArray(rows)||rows.length>LIMIT)throw Error('inventory capacity exceeded');
 const seen=new Map();
 for(const r of rows){
  if(!r||!isArtifactId(r.id)||!hash(r.sha256))throw Error('invalid inventory row');
  if(seen.has(r.id)&&seen.get(r.id)!==r.sha256)throw Error('conflicting object identity');
  seen.set(r.id,r.sha256);
 }
 return [...seen].sort(([a],[b])=>a<b?-1:a>b?1:0).map(([id,sha256])=>({id,sha256}));
}
function scope(c){if(!isArtifactId(c.installationId)||!/^[a-z][a-z0-9_]{0,62}$/.test(c.database)||!backupKeyConfigValid(c.key,c.keyring))throw Error('invalid recovery scope');}
function checkAnchor(a){if(!a||!Number.isSafeInteger(a.sequence)||a.sequence<1||!hash(a.catalogSha256))throw Error('trusted checkpoint required');}
function checkDb(db){if(!db||!isArtifactId(db.backupId)||!hash(db.sha256)||!validDate(db.createdAt))throw Error('invalid database backup');}
function canonical(m){return Buffer.from(JSON.stringify(m));}
// Caller must derive inventory from the exact quiesced database snapshot and
// provide the corresponding authenticated database archive identity.
export async function createEvidenceBackup({root,sourceRoot,inventory,databaseBackup,sequence,previousDigest,signingKey,...cfg}){
 scope(cfg);checkDb(databaseBackup);
 if(!Number.isSafeInteger(sequence)||sequence<1||!(sequence===1?previousDigest===null:hash(previousDigest)))throw Error('invalid catalog sequence');
 const signer=signingKey?.type==='private'?signingKey:createPrivateKey(signingKey);if(signer.asymmetricKeyType!=='ed25519')throw Error('invalid signer');
 await privateDir(root);await privateDir(sourceRoot);
 const rows=normalizeRecoveryInventory(inventory),openObject=createPrivateFileStore(sourceRoot);
 const stage=await mkdtemp(join(root,'.evidence-'));let published=false,total=0;
 try{
  const objects=[];
  for(const row of rows){
   cfg.signal.throwIfAborted();
   const source=await openObject(row.id,{signal:cfg.signal,maxBytes:Math.min(512*1024*1024,MAX_TOTAL-total)});
   let item;
   try{item=await createEncryptedBackup(source,{...cfg,root:stage,maxBytes:Math.min(512*1024*1024,MAX_TOTAL-total)});}finally{source.destroy();}
   if(item.sha256!==row.sha256)throw Error('source evidence integrity failure');
   total+=item.bytes;objects.push({...row,backupId:item.backupId,bytes:item.bytes});
  }
  const m={version:1,installationId:cfg.installationId,database:cfg.database,sequence,previousDigest,databaseBackup:{backupId:databaseBackup.backupId,sha256:databaseBackup.sha256,createdAt:databaseBackup.createdAt},createdAt:new Date().toISOString(),objects};
  const bytes=canonical(m);if(bytes.length>MAX_MANIFEST)throw Error('catalog too large');
  const signature=sign(null,bytes,signer);
  for(const [name,data] of [['catalog.json',bytes],['catalog.sig',signature]]){
   const h=await open(join(stage,name),constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
   try{await h.writeFile(data);await h.sync();}finally{await h.close();}
  }
  await syncDir(stage);cfg.signal.throwIfAborted();
  const path=join(root,'evidence-'+randomUUID());await rename(stage,path);published=true;await syncDir(root);
  return Object.freeze({path,checkpoint:Object.freeze({sequence,catalogSha256:digest(bytes)}),objects:objects.length,bytes:total});
 }finally{if(!published)await rm(stage,{recursive:true,force:true});}
}
export async function restoreEvidenceBackup({path,destinationRoot,spoolDirectory,inventory,databaseBackup,checkpoint,verificationKey,maxAgeMs=24*60*60*1000,now=Date.now(),...cfg}){
 scope(cfg);checkAnchor(checkpoint);checkDb(databaseBackup);
 if(!Number.isSafeInteger(maxAgeMs)||maxAgeMs<1||maxAgeMs>30*86400000||!Number.isFinite(now))throw Error('invalid freshness policy');
 await privateDir(path);await privateDir(destinationRoot);await privateDir(spoolDirectory);
 const pub=verificationKey?.type==='public'?verificationKey:createPublicKey(verificationKey);if(pub.asymmetricKeyType!=='ed25519')throw Error('invalid verification key');
 const bytes=await readBounded(join(path,'catalog.json')),sig=await readBounded(join(path,'catalog.sig'));
 if(sig.length!==64||digest(bytes)!==checkpoint.catalogSha256||!verify(null,bytes,pub,sig))throw Error('catalog authentication or checkpoint mismatch');
 const m=JSON.parse(bytes.toString('utf8'));
 if(m.version!==1||m.sequence!==checkpoint.sequence||m.installationId!==cfg.installationId||m.database!==cfg.database||!validDate(m.createdAt)||!validDate(m.databaseBackup?.createdAt)||
 m.databaseBackup.backupId!==databaseBackup.backupId||m.databaseBackup.sha256!==databaseBackup.sha256||m.databaseBackup.createdAt!==databaseBackup.createdAt||
 now-Date.parse(m.databaseBackup.createdAt)>maxAgeMs||Date.parse(m.databaseBackup.createdAt)>now+5000||Date.parse(m.createdAt)>now+5000||
 Date.parse(m.createdAt)<Date.parse(m.databaseBackup.createdAt))throw Error('stale or mismatched catalog');
 const expected=normalizeRecoveryInventory(inventory);
 if(!Array.isArray(m.objects)||m.objects.length!==expected.length)throw Error('inventory mismatch');
 let total=0;const ids=new Set();
 for(let i=0;i<expected.length;i++){
  const r=m.objects[i],e=expected[i];if(r.id!==e.id||r.sha256!==e.sha256||!isArtifactId(r.backupId)||ids.has(r.backupId)||!Number.isSafeInteger(r.bytes)||r.bytes<1||r.bytes>512*1024*1024)throw Error('inventory mismatch');
  ids.add(r.backupId);total+=r.bytes;if(total>MAX_TOTAL)throw Error('restore capacity exceeded');
 }
 const stage=await mkdtemp(join(destinationRoot,'.restore-'));let published=false;
 try{
  for(const item of m.objects){
   cfg.signal.throwIfAborted();
   const s=await verifyAndStageBackup({...cfg,path:join(path,'backup-'+item.backupId),spoolDirectory,maxBytes:item.bytes});
   try{
    if(s.backupId!==item.backupId||s.sha256!==item.sha256||s.length!==item.bytes)throw Error('object substitution');
    const output=await open(join(stage,item.id),constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
    try{
     // Explicit positionless writes; sync before publishing the private directory.
     for await(const block of s.read()){let offset=0;while(offset<block.length){cfg.signal.throwIfAborted();const r=await output.write(block,offset,block.length-offset,null);if(!r.bytesWritten)throw Error('short restore write');offset+=r.bytesWritten;}}
     await output.sync();
    }finally{await output.close();}
   }finally{await s.close();}
  }
  await syncDir(stage);cfg.signal.throwIfAborted();
  const restoredPath=join(destinationRoot,'recovered-'+randomUUID());await rename(stage,restoredPath);published=true;await syncDir(destinationRoot);
  return Object.freeze({path:restoredPath,backupId:databaseBackup.backupId,catalogSha256:checkpoint.catalogSha256,sequence:checkpoint.sequence,objects:expected.length,bytes:total,inventorySha256:digest(canonical(expected))});
 }finally{if(!published)await rm(stage,{recursive:true,force:true});}
}
// Run only through a trusted backup/recovery administrator on a frozen snapshot.
// Query result is bounded before loading all rows. Never interpret storage_ref.
export async function readRecoveryInventory(client){
 const result=await client.query("SELECT id,sha256 FROM (SELECT id,sha256 FROM verivaro.evidence UNION ALL SELECT artifact_id AS id,sha256 FROM verivaro_private.released_exports) AS items ORDER BY id LIMIT 4097");
 return normalizeRecoveryInventory(result.rows);
}
