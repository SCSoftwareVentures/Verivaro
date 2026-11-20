// Standalone operator-only encrypted quarantine for *untrusted original* PDF bytes.
// This is NOT an application's public upload store or evidence admission bypass.
import {open,lstat,unlink,rename} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join,isAbsolute} from 'node:path';
import {createCipheriv,createDecipheriv,createHash,randomBytes,randomUUID,timingSafeEqual} from 'node:crypto';
import {PDF_NORMALIZER_MAX_SOURCE} from './pdf-normalization.mjs';
const id=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const sha=/^[a-f0-9]{64}$/;
const digest=b=>createHash('sha256').update(b).digest('hex');
const fail=()=>{throw Error('original PDF quarantine denied');};
const pdf=b=>Buffer.isBuffer(b)&&b.length>=20&&b.length<=PDF_NORMALIZER_MAX_SOURCE&&/^%PDF-1\.[0-7]\r?\n/.test(b.subarray(0,12).toString('latin1'));
const aad=m=>Buffer.from(JSON.stringify(['vv-original-pdf-quarantine-v1',m.quarantineId,m.tenantId,m.projectId,m.sha256,m.bytes,m.keyId]));
const valid=m=>m&&id.test(m.quarantineId)&&id.test(m.tenantId)&&id.test(m.projectId)&&sha.test(m.sha256)&&Number.isInteger(m.bytes)&&m.bytes>=20&&m.bytes<=PDF_NORMALIZER_MAX_SOURCE&&typeof m.keyId==='string'&&/^[a-z][a-z0-9_-]{0,31}$/.test(m.keyId)&&Object.keys(m).sort().join('|')===['bytes','keyId','projectId','quarantineId','sha256','tenantId'].sort().join('|');
async function checkRoot(root){
 const s=await lstat(root);
 if(!s.isDirectory()||(s.mode&0o077)!==0||(typeof process.getuid==='function'&&s.uid!==process.getuid()))fail();
}
export function createOriginalPdfQuarantine({root,key,keyId,scan,retentionGate}={}){
 if(typeof root!=='string'||!isAbsolute(root)||root.length>250||/[\x00-\x1f]/.test(root)||!Buffer.isBuffer(key)||key.length!==32||typeof scan!=='function'||typeof keyId!=='string'||!/^[a-z][a-z0-9_-]{0,31}$/.test(keyId)||!constants.O_NOFOLLOW||(retentionGate!==undefined&&typeof retentionGate!=='function'))fail();
 const secret=Buffer.from(key);let busy=false,closed=false;
 async function gate(fn){
  if(closed||busy)fail();busy=true;
  try{await checkRoot(root);return await fn();}
  finally{busy=false;}
 }
 const location=quarantineId=>join(root,quarantineId+'.vvq');
 const deletionIntent=quarantineId=>join(root,quarantineId+'.delete-intent');
 const deletedReceipt=quarantineId=>join(root,quarantineId+'.deleted');
 async function assertNotDeleting(quarantineId){try{await lstat(deletionIntent(quarantineId));fail();}catch(e){if(e.code!=='ENOENT')throw e;}}
 async function put({source,tenantId,projectId,signal}){
  return gate(async()=>{
   if(!id.test(tenantId)||!id.test(projectId)||!pdf(source)||!signal)fail();
   signal.throwIfAborted();
   const original=Buffer.from(source),before=digest(original);
   let encrypted,handle,filePath,created=false,committed=false;
   try{
    const verdict=await scan(original,signal);
    signal.throwIfAborted();
    if(verdict!=='clean'||digest(original)!==before)fail();
    const meta={quarantineId:randomUUID(),tenantId,projectId,sha256:before,bytes:original.length,keyId};
    const nonce=randomBytes(12),cipher=createCipheriv('aes-256-gcm',secret,nonce);
    cipher.setAAD(aad(meta));encrypted=Buffer.concat([nonce,cipher.update(original),cipher.final(),cipher.getAuthTag()]);
    filePath=location(meta.quarantineId);
    // Server-generated UUID name, new file only; any collision or symlink fails.
    handle=await open(filePath,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW|constants.O_SYNC,0o600);created=true;
    try{let off=0;while(off<encrypted.length){const r=await handle.write(encrypted,off,encrypted.length-off,off);if(r.bytesWritten<1)fail();off+=r.bytesWritten;}await handle.sync();}
    finally{await handle.close();handle=undefined;}
    signal.throwIfAborted();committed=true;return Object.freeze(meta);
   }finally{original.fill(0);encrypted?.fill(0);if(handle)await handle.close();if(created&&!committed)try{await unlink(filePath);}catch{ /* quarantine cleanup must be administratively reconciled on storage failure */ }}
  });
 }
 async function read(meta,{signal}={}){
  return gate(async()=>{
   if(!valid(meta)||meta.keyId!==keyId||!signal)fail();
   signal.throwIfAborted();
   await assertNotDeleting(meta.quarantineId);
   const path=location(meta.quarantineId);
   const handle=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
   let encrypted,plain;
   try{
    const before=await handle.stat();
    if(!before.isFile()||(before.mode&0o077)!==0||(typeof process.getuid==='function'&&before.uid!==process.getuid())||before.size!==meta.bytes+28)fail();
    encrypted=Buffer.alloc(before.size);let off=0;
    while(off<encrypted.length){const r=await handle.read(encrypted,off,encrypted.length-off,off);if(r.bytesRead<1)fail();off+=r.bytesRead;}
    const after=await handle.stat();
    if(before.size!==after.size||before.mtimeMs!==after.mtimeMs||before.ino!==after.ino||before.dev!==after.dev)fail();
    signal.throwIfAborted();
    const decipher=createDecipheriv('aes-256-gcm',secret,encrypted.subarray(0,12));
    decipher.setAAD(aad(meta));decipher.setAuthTag(encrypted.subarray(-16));
    plain=Buffer.concat([decipher.update(encrypted.subarray(12,-16)),decipher.final()]);
    if(!pdf(plain)||!timingSafeEqual(Buffer.from(digest(plain),'hex'),Buffer.from(meta.sha256,'hex')))fail();
    const result=plain;plain=undefined;return result;
   }finally{plain?.fill(0);encrypted?.fill(0);await handle.close();}
  });
 }
 async function destroy(meta,{authorization,signal}={}){
  return gate(async()=>{
   if(!retentionGate||!valid(meta)||meta.keyId!==keyId||!signal)fail();
   signal.throwIfAborted();
   await assertNotDeleting(meta.quarantineId);
   const originalPath=location(meta.quarantineId),intentPath=deletionIntent(meta.quarantineId);
   const target=await open(originalPath,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
   let before;
   try{
    before=await target.stat();
    if(!before.isFile()||(before.mode&0o077)!==0||(typeof process.getuid==='function'&&before.uid!==process.getuid())||before.size!==meta.bytes+28)fail();
   }finally{await target.close();}
   if(await retentionGate(meta,authorization,signal)!==true)fail();
   signal.throwIfAborted();
   // Write-ahead intent makes interrupted deletions deny future reads.
   const record=Buffer.from(JSON.stringify({version:1,kind:'original-pdf-delete-intent',quarantineId:meta.quarantineId,tenantId:meta.tenantId,projectId:meta.projectId,sha256:meta.sha256,authorizationSha256:digest(Buffer.from(JSON.stringify(authorization))),issuedAt:new Date().toISOString()}));
   const f=await open(intentPath,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY|constants.O_NOFOLLOW|constants.O_SYNC,0o600);
   try{await f.writeFile(record);await f.sync();}finally{await f.close();record.fill(0);}
   const directory=await open(root,constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);
   try{
    await directory.sync();
    signal.throwIfAborted();
    const same=await lstat(originalPath);
    if(same.dev!==before.dev||same.ino!==before.ino||same.size!==before.size||!same.isFile())fail();
    await unlink(originalPath);await directory.sync();
    await rename(intentPath,deletedReceipt(meta.quarantineId));await directory.sync();
    return Object.freeze({deleted:true,quarantineId:meta.quarantineId,originalSha256:meta.sha256,receiptName:meta.quarantineId+'.deleted'});
   }finally{await directory.close();}
  });
 }
 return Object.freeze({put,read,...(retentionGate?{destroy}:{}),close(){closed=true;secret.fill(0);}});
}
