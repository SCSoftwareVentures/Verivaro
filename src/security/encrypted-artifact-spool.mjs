import {createCipheriv,createDecipheriv,createHash,randomBytes,timingSafeEqual} from 'node:crypto';
import {mkdtemp,open,unlink,rmdir} from 'node:fs/promises';
import {constants} from 'node:fs';
import {isAbsolute,join} from 'node:path';

const BLOCK=256*1024,TAG=16;
export const MAX_SPOOL_BYTES=512*1024*1024;
const nonce=(prefix,index)=>{const iv=Buffer.alloc(12);prefix.copy(iv);iv.writeUInt32BE(index,8);return iv;};
const aad=(index,length)=>{const bytes=Buffer.alloc(8);bytes.writeUInt32BE(index,0);bytes.writeUInt32BE(length,4);return bytes;};
async function writeAll(handle,data,offset,signal){
 let written=0;
 while(written<data.length){
  signal.throwIfAborted();
  const result=await handle.write(data,written,data.length-written,offset+written);
  if(!result.bytesWritten)throw Error('short spool write');
  written+=result.bytesWritten;
 }
}
async function readAll(handle,length,offset,signal){
 const result=Buffer.allocUnsafe(length);
 let read=0;
 while(read<length){
  signal.throwIfAborted();
  const part=await handle.read(result,read,length-read,offset+read);
  if(!part.bytesRead)throw Error('truncated spool');
  read+=part.bytesRead;
 }
 return result;
}
// POSIX anonymous encrypted temporary file. The trusted spool parent must be
// private to the service. No recoverable key or named plaintext file is written.
export async function stageEncryptedArtifact(source,{directory,maxBytes,sha256,signal}){
 if(typeof directory!=='string'||!isAbsolute(directory)||!Number.isSafeInteger(maxBytes)||maxBytes<1||maxBytes>MAX_SPOOL_BYTES||
 typeof sha256!=='string'||!/^[0-9a-f]{64}$/.test(sha256))throw Error('invalid staging request');
 let folder,file,handle;
 const key=randomBytes(32),prefix=randomBytes(8);
 const clear=Buffer.alloc(BLOCK);
 let used=0,total=0,index=0,offset=0,closed=false,consumed=false;
 const hash=createHash('sha256');
 async function close(){
  if(closed)return;
  closed=true;key.fill(0);clear.fill(0);
  try{if(handle)await handle.close();}
  finally{
   if(file)await unlink(file).catch(e=>{if(e.code!=='ENOENT')throw e;});
   if(folder)await rmdir(folder).catch(e=>{if(e.code!=='ENOENT')throw e;});
  }
 }
 async function flush(){
  const cipher=createCipheriv('aes-256-gcm',key,nonce(prefix,index));
  cipher.setAAD(aad(index,used));
  const ciphertext=Buffer.concat([cipher.update(clear.subarray(0,used)),cipher.final(),cipher.getAuthTag()]);
  await writeAll(handle,ciphertext,offset,signal);
  offset+=ciphertext.length;index++;clear.fill(0);used=0;
 }
 try{
  signal.throwIfAborted();
  folder=await mkdtemp(join(directory,'vv-spool-'));
  file=join(folder,'artifact');
  handle=await open(file,constants.O_CREAT|constants.O_EXCL|constants.O_RDWR|constants.O_NOFOLLOW,0o600);
  await unlink(file);file=undefined;
  await rmdir(folder);folder=undefined;
  for await(const chunk of source){
   signal.throwIfAborted();
   if(!Buffer.isBuffer(chunk)||chunk.length>maxBytes-total)throw Error('invalid artifact size');
   hash.update(chunk);total+=chunk.length;
   for(let pos=0;pos<chunk.length;){
    const n=Math.min(BLOCK-used,chunk.length-pos);
    chunk.copy(clear,used,pos,pos+n);used+=n;pos+=n;
    if(used===BLOCK)await flush();
   }
  }
  if(used)await flush();
  signal.throwIfAborted();
  if(!total||!timingSafeEqual(hash.digest(),Buffer.from(sha256,'hex')))throw Error('artifact integrity mismatch');
  const length=total;
  return Object.freeze({length,close,async *read(){
   if(closed||consumed)throw Error('staged artifact unavailable');
   consumed=true;
   let remaining=length,position=0,block=0;
   while(remaining>0){
    signal.throwIfAborted();
    const n=Math.min(BLOCK,remaining);
    const sealed=await readAll(handle,n+TAG,position,signal);
    const decipher=createDecipheriv('aes-256-gcm',key,nonce(prefix,block));
    decipher.setAAD(aad(block,n));decipher.setAuthTag(sealed.subarray(n));
    // Authenticate the entire block before yielding any of its plaintext.
    const plain=Buffer.concat([decipher.update(sealed.subarray(0,n)),decipher.final()]);
    position+=n+TAG;remaining-=n;block++;
    yield plain;
   }
  }});
 }catch(e){try{await close();}catch{const failure=Error('staging cleanup uncertain');failure.cleanupUncertain=true;throw failure;}throw e;}
}
