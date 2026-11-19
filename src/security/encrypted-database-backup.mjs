import {createCipheriv,createDecipheriv,createHash,createHmac,hkdfSync,randomBytes,randomUUID,timingSafeEqual} from 'node:crypto';
import {open,mkdtemp,rename,rm,stat} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join,isAbsolute} from 'node:path';
import {Readable} from 'node:stream';
import {stageEncryptedArtifact,MAX_SPOOL_BYTES} from './encrypted-artifact-spool.mjs';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const DB=/^[a-z][a-z0-9_]{0,62}$/;
const fields=['version','backupId','installationId','database','createdAt','salt','nonce','bytes','sha256','cipherSha256','tag'];
const hex=(v,n)=>typeof v==='string'&&v.length===n*2&&/^[a-f0-9]+$/.test(v);
const canonical=m=>JSON.stringify(Object.fromEntries(fields.map(k=>[k,m[k]])));
const header=m=>JSON.stringify(Object.fromEntries(fields.slice(0,7).map(k=>[k,m[k]])));
const keys=(key,salt)=>[Buffer.from(hkdfSync('sha256',key,salt,'verivaro-backup-v1/aes',32)),Buffer.from(hkdfSync('sha256',key,salt,'verivaro-backup-v1/manifest',32))];
const mac=(m,k)=>createHmac('sha256',k).update(canonical(m)).digest();
function config({key,installationId,database,maxBytes}){
 if(!Buffer.isBuffer(key)||key.length!==32||!UUID.test(installationId)||!DB.test(database)||!Number.isSafeInteger(maxBytes)||maxBytes<1||maxBytes>MAX_SPOOL_BYTES)throw Error('invalid backup configuration');
}
async function privateDirectory(path){
 if(typeof path!=='string'||!isAbsolute(path))throw Error('private directory required');
 const s=await stat(path);if(!s.isDirectory()||(s.mode&0o077)!==0)throw Error('private directory required');
}
async function writeAll(f,b,signal){
 let offset=0;
 while(offset<b.length){signal.throwIfAborted();const r=await f.write(b,offset,b.length-offset,null);if(!r.bytesWritten)throw Error('short backup write');offset+=r.bytesWritten;}
}
async function readManifest(path){
 const f=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const s=await f.stat();if(!s.isFile()||s.size<1||s.size>4096)throw Error('invalid manifest');
  const b=Buffer.alloc(s.size);
  let pos=0;while(pos<b.length){const r=await f.read(b,pos,b.length-pos,pos);if(!r.bytesRead)throw Error('truncated manifest');pos+=r.bytesRead;}
  const m=JSON.parse(b.toString('utf8'));
  if(!m||Object.keys(m).length!==fields.length+1||!fields.every(k=>Object.hasOwn(m,k))||!Object.hasOwn(m,'mac')||
   m.version!==1||!UUID.test(m.backupId)||!UUID.test(m.installationId)||!DB.test(m.database)||
   typeof m.createdAt!=='string'||new Date(m.createdAt).toISOString()!==m.createdAt||
   !hex(m.salt,32)||!hex(m.nonce,12)||!hex(m.sha256,32)||!hex(m.cipherSha256,32)||!hex(m.tag,16)||!hex(m.mac,32)||
   !Number.isSafeInteger(m.bytes)||m.bytes<1||m.bytes>MAX_SPOOL_BYTES)throw Error('invalid manifest');
  return m;
 }finally{await f.close();}
}
export async function createEncryptedBackup(source,{root,key,installationId,database,signal,maxBytes=MAX_SPOOL_BYTES,assertComplete=async()=>{}}){
 config({key,installationId,database,maxBytes});await privateDirectory(root);signal.throwIfAborted();
 const m={version:1,backupId:randomUUID(),installationId,database,createdAt:new Date().toISOString(),salt:randomBytes(32).toString('hex'),nonce:randomBytes(12).toString('hex')};
 const [enc,auth]=keys(key,Buffer.from(m.salt,'hex'));
 let stage,file,manifest,published=false;
 try{
  stage=await mkdtemp(join(root,'.backup-'));
  file=await open(join(stage,'archive.enc'),constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  const cipher=createCipheriv('aes-256-gcm',enc,Buffer.from(m.nonce,'hex'));cipher.setAAD(Buffer.from(header(m)));
  const plainHash=createHash('sha256'),cipherHash=createHash('sha256');let bytes=0;
  for await(const chunk of source){
   signal.throwIfAborted();if(!Buffer.isBuffer(chunk)||chunk.length>maxBytes-bytes)throw Error('backup capacity exceeded');
   bytes+=chunk.length;plainHash.update(chunk);
   const sealed=cipher.update(chunk);cipherHash.update(sealed);await writeAll(file,sealed,signal);
  }
  await assertComplete();signal.throwIfAborted();if(!bytes)throw Error('empty backup');
  const final=cipher.final();cipherHash.update(final);await writeAll(file,final,signal);
  Object.assign(m,{bytes,sha256:plainHash.digest('hex'),cipherSha256:cipherHash.digest('hex'),tag:cipher.getAuthTag().toString('hex')});
  m.mac=mac(m,auth).toString('hex');
  await file.sync();await file.close();file=null;
  manifest=await open(join(stage,'manifest.json'),constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  await writeAll(manifest,Buffer.from(JSON.stringify(m)+'\n'),signal);await manifest.sync();await manifest.close();manifest=null;
  const dir=await open(stage,constants.O_RDONLY|constants.O_DIRECTORY);try{await dir.sync();}finally{await dir.close();}
  signal.throwIfAborted();const destination=join(root,'backup-'+m.backupId);await rename(stage,destination);published=true;
  const parent=await open(root,constants.O_RDONLY|constants.O_DIRECTORY);try{await parent.sync();}finally{await parent.close();}
  return Object.freeze({path:destination,backupId:m.backupId,bytes,sha256:m.sha256,createdAt:m.createdAt});
 }finally{
  enc.fill(0);auth.fill(0);
  try{await file?.close();await manifest?.close();}finally{if(stage&&!published)await rm(stage,{recursive:true,force:true});}
 }
}
// Decrypted bytes are staged in another anonymous encrypted file. No plaintext
// is passed to a restore process until both AEAD and the full manifest hash pass.
export async function verifyAndStageBackup({path,spoolDirectory,key,installationId,database,signal,maxBytes=MAX_SPOOL_BYTES}){
 config({key,installationId,database,maxBytes});await privateDirectory(path);await privateDirectory(spoolDirectory);
 const m=await readManifest(join(path,'manifest.json'));
 if(m.installationId!==installationId||m.database!==database||m.bytes>maxBytes)throw Error('backup scope mismatch');
 const [enc,auth]=keys(key,Buffer.from(m.salt,'hex'));let file;
 try{
  if(!timingSafeEqual(mac(m,auth),Buffer.from(m.mac,'hex')))throw Error('backup manifest authentication failed');
  file=await open(join(path,'archive.enc'),constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  const stats=await file.stat();if(!stats.isFile()||stats.size!==m.bytes)throw Error('backup length mismatch');
  const decipher=createDecipheriv('aes-256-gcm',enc,Buffer.from(m.nonce,'hex'));decipher.setAAD(Buffer.from(header(m)));decipher.setAuthTag(Buffer.from(m.tag,'hex'));
  const digest=createHash('sha256');
  const source=Readable.from((async function*(){
   let count=0;
   for await(const chunk of file.createReadStream({autoClose:false,signal})){
    signal.throwIfAborted();count+=chunk.length;if(count>m.bytes)throw Error('backup length mismatch');
    digest.update(chunk);yield decipher.update(chunk);
   }
   if(count!==m.bytes||!timingSafeEqual(digest.digest(),Buffer.from(m.cipherSha256,'hex')))throw Error('backup ciphertext integrity failure');
   const last=decipher.final();if(last.length)yield last;
  })());
  const staged=await stageEncryptedArtifact(source,{directory:spoolDirectory,maxBytes:m.bytes,sha256:m.sha256,signal});
  return Object.freeze({backupId:m.backupId,createdAt:m.createdAt,sha256:m.sha256,length:staged.length,read:staged.read,close:staged.close});
 }finally{enc.fill(0);auth.fill(0);await file?.close();}
}
