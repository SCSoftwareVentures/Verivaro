import {constants} from 'node:fs';
import {open,lstat,realpath,unlink} from 'node:fs/promises';
import {join} from 'node:path';
import {createHash,randomUUID} from 'node:crypto';
const limit=50*1024*1024;
const mimeSet=new Set(['application/pdf','image/jpeg','image/png','text/plain']);
const keyPattern=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function expected(e){
 if(!e||typeof e.sha256!=='string'||! /^[a-f0-9]{64}$/.test(e.sha256)||!Number.isSafeInteger(e.bytes)||e.bytes<1||e.bytes>limit||!mimeSet.has(e.mediaType))throw Error('invalid quarantine metadata');
 return {sha256:e.sha256,bytes:e.bytes,mediaType:e.mediaType};
}
async function privateRoot(root){
 const s=await lstat(root);
 if(!s.isDirectory()||s.isSymbolicLink()||(s.mode&0o077)!==0||typeof process.getuid!=='function'||s.uid!==process.getuid())throw Error('quarantine root must be private and owned by worker');
 return realpath(root);
}
function magic(header,type){
 if(type==='application/pdf')return header.subarray(0,5).equals(Buffer.from('%PDF-'));
 if(type==='image/jpeg')return header.length>=3&&header[0]===255&&header[1]===216&&header[2]===255;
 if(type==='image/png')return header.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10]));
 return true;
}
/** Private local quarantine adapter for Linux demo and isolated tests.
 * Root must be provisioned by operator outside web roots, with no untrusted writers.
 * A content signature is only a coarse format check, not parser safety or malware clearance.
 */
export async function quarantineUpload(root,metadata,body,{objectKey=randomUUID()}={}){
 const e=expected(metadata),dir=await privateRoot(root);
 if(typeof objectKey!=='string'||!keyPattern.test(objectKey))throw Error('invalid reserved object key');
 const path=join(dir,objectKey);
 const hash=createHash('sha256');let count=0,header=Buffer.alloc(0);
 const decoder=e.mediaType==='text/plain'?new TextDecoder('utf-8',{fatal:true}):null;
 let f;let created=false;
 try{
 f=await open(path,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);created=true;
 for await(const chunk of body){
 if(!(chunk instanceof Uint8Array))throw Error('invalid byte chunk');
 const b=Buffer.from(chunk);count+=b.length;
 if(count>e.bytes)throw Error('upload size exceeded');
 hash.update(b);if(header.length<8)header=Buffer.concat([header,b.subarray(0,8-header.length)]);
 if(decoder){const text=decoder.decode(b,{stream:true});if(text.includes('\0'))throw Error('invalid text');}
 await f.writeFile(b);
 }
 if(decoder&&decoder.decode().includes('\0'))throw Error('invalid text');
 if(count!==e.bytes||hash.digest('hex')!==e.sha256||!magic(header,e.mediaType))throw Error('upload integrity mismatch');
 await f.sync();await f.close();f=null;
 return Object.freeze({objectKey,sha256:e.sha256,bytes:e.bytes,mediaType:e.mediaType,state:'quarantined'});
 }catch(err){if(f)await f.close().catch(()=>{});if(created)await unlink(path).catch(()=>{});throw err;}
}
/** Recheck immutable-intended quarantine bytes; scanner is an injected TRUSTED adapter.
 * No clean verdict enables a release. No production malware engine is bundled.
 * A supervisor must enforce hard process isolation/time and resource limits.
 */
export async function readVerifiedQuarantine(root,receipt,{maxBytes=limit}={}){
 const e=expected(receipt);
 if(receipt.state!=='quarantined'||typeof receipt.objectKey!=='string'||!keyPattern.test(receipt.objectKey))throw Error('invalid receipt');
 if(!Number.isSafeInteger(maxBytes)||maxBytes<1||maxBytes>limit||e.bytes>maxBytes)throw Error('quarantine read exceeds limit');
 const path=join(await privateRoot(root),receipt.objectKey);
 const f=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 let data;
 try{
 const s=await f.stat();
 if(!s.isFile()||s.size!==e.bytes||s.nlink!==1||(s.mode&0o077)!==0||s.uid!==process.getuid())throw Error('quarantine object invalid');
 data=Buffer.alloc(e.bytes+1);let n=0;
 while(n<data.length){const r=await f.read(data,n,data.length-n,n);if(!r.bytesRead)break;n+=r.bytesRead;}
 if(n!==e.bytes)throw Error('quarantine size mismatch');data=data.subarray(0,n);
 if(createHash('sha256').update(data).digest('hex')!==e.sha256||!magic(data.subarray(0,8),e.mediaType))throw Error('quarantine integrity mismatch');
 }finally{await f.close();}
 return data;
}
export async function scanQuarantine(root,receipt,scanner,{timeoutMs=10000}={}){
 const e=expected(receipt);
 if(!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>60000)throw Error('invalid scan timeout');
 const data=await readVerifiedQuarantine(root,receipt);
 const result=(outcome,engine=null,engineVersion=null)=>Object.freeze({objectKey:receipt.objectKey,sha256:e.sha256,outcome,engine,engineVersion,state:'quarantined'});
 if(typeof scanner!=='function')return result('unavailable');
 let timer;const controller=new AbortController();
 try{
 const verdict=await Promise.race([Promise.resolve().then(()=>scanner(Buffer.from(data),Object.freeze({...e}),controller.signal)),new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(Error('scan timed out'));},timeoutMs);})]);
 if(!verdict||verdict.sha256!==e.sha256||!['clean','rejected'].includes(verdict.outcome)||typeof verdict.engine!=='string'||!verdict.engine.trim()||verdict.engine.length>80||typeof verdict.engineVersion!=='string'||!verdict.engineVersion.trim()||verdict.engineVersion.length>80)return result('unavailable');
 return result(verdict.outcome,verdict.engine,verdict.engineVersion);
 }catch{return result('unavailable');}finally{clearTimeout(timer);}
}

/** Only use keys returned by the committed recovery procedure. No directory sweeps or client keys. */
export async function removeAbandonedObject(root,key){
 if(typeof key!=='string'||!keyPattern.test(key))throw Error('invalid recovery key');
 const path=join(await privateRoot(root),key);
 try{const s=await lstat(path);if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1||s.uid!==process.getuid())throw Error('unexpected recovery object');await unlink(path);return true;}
 catch(e){if(e?.code==='ENOENT')return false;throw e;}
}
