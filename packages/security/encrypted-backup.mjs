import {createCipheriv,createDecipheriv,createHash,randomBytes,randomUUID} from 'node:crypto';
import {open,link,unlink,lstat,realpath} from 'node:fs/promises';
import {constants} from 'node:fs';
import {dirname,basename,join} from 'node:path';
const MAGIC=Buffer.from('VVBKUP1\0'),HEADER=60,TAG=16,CHUNK=1024*1024,MAX=32*1024*1024*1024;
const hash=s=>createHash('sha256').update(s).digest();
function options({key,keyId,context,maxBytes=16*1024*1024*1024}){
 if(!Buffer.isBuffer(key)||key.length!==32||typeof keyId!=='string'||!/^[A-Za-z0-9_-]{1,80}$/.test(keyId)||typeof context!=='string'||!context||Buffer.byteLength(context)>512||!Number.isSafeInteger(maxBytes)||maxBytes<1||maxBytes>MAX)throw Error('invalid backup configuration');
 return {key:Buffer.from(key),binding:hash(JSON.stringify([keyId,context])),maxBytes};
}
async function privateDir(path){const s=await lstat(path);if(!s.isDirectory()||s.isSymbolicLink()||(s.mode&0o077)!==0||s.uid!==process.getuid())throw Error('private backup directory required');return realpath(path);}
async function paths(source,destination){
 const input=join(await privateDir(dirname(source)),basename(source)),outDir=await privateDir(dirname(destination)),output=join(outDir,basename(destination));
 if(input===output||!basename(destination)||['.','..'].includes(basename(destination)))throw Error('unsafe backup destination');
 try{await lstat(output);throw Error('destination exists');}catch(e){if(e.code!=='ENOENT')throw e;}
 return {input,outDir,output};
}
async function readExact(f,b,n,pos){let k=0;while(k<n){const r=await f.read(b,k,n-k,pos+k);if(!r.bytesRead)throw Error('truncated backup');k+=r.bytesRead;}}
async function writeAll(f,b,pos){let k=0;while(k<b.length){const r=await f.write(b,k,b.length-k,pos+k);if(!r.bytesWritten)throw Error('backup write failed');k+=r.bytesWritten;}}
async function run(source,destination,opts,decrypt){
 const config=options(opts);let input,output,stage,stageCreated=false,published=false;
 try{
 const loc=await paths(source,destination);input=await open(loc.input,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 const stat=await input.stat();if(!stat.isFile()||stat.nlink!==1||stat.uid!==process.getuid()||(stat.mode&0o077)!==0)throw Error('private regular backup input required');
 let header=Buffer.alloc(HEADER),length,offset,cipher;
 if(decrypt){
 if(stat.size<HEADER+TAG+1)throw Error('truncated encrypted backup');await readExact(input,header,HEADER,0);
 if(!header.subarray(0,8).equals(MAGIC)||!header.subarray(28,60).equals(config.binding))throw Error('backup binding mismatch');
 const declared=header.readBigUInt64BE(20);if(declared>BigInt(config.maxBytes)||declared<1n||BigInt(stat.size)!==BigInt(HEADER+TAG)+declared)throw Error('backup size mismatch');length=Number(declared);
 const tag=Buffer.alloc(TAG);await readExact(input,tag,TAG,HEADER+length);
 cipher=createDecipheriv('aes-256-gcm',config.key,header.subarray(8,20),{authTagLength:TAG});cipher.setAAD(header);cipher.setAuthTag(tag);offset=HEADER;
 }else{
 length=stat.size;if(length<1||length>config.maxBytes)throw Error('backup size limit');MAGIC.copy(header);randomBytes(12).copy(header,8);header.writeBigUInt64BE(BigInt(length),20);config.binding.copy(header,28);
 cipher=createCipheriv('aes-256-gcm',config.key,header.subarray(8,20),{authTagLength:TAG});cipher.setAAD(header);offset=0;
 }
 stage=join(loc.outDir,'.vv-backup-stage-'+randomUUID());output=await open(stage,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);stageCreated=true;
 let written=0;if(!decrypt){await writeAll(output,header,0);written=HEADER;}
 const buffer=Buffer.alloc(Math.min(CHUNK,length)),plainHash=createHash('sha256');
 for(let pos=0;pos<length;){const n=Math.min(buffer.length,length-pos);await readExact(input,buffer,n,offset+pos);
 const chunk=buffer.subarray(0,n),converted=cipher.update(chunk);plainHash.update(decrypt?converted:chunk);await writeAll(output,converted,written);written+=converted.length;pos+=n;}
 const final=cipher.final();if(decrypt)plainHash.update(final);await writeAll(output,final,written);written+=final.length;
 if(!decrypt){const tag=cipher.getAuthTag();await writeAll(output,tag,written);written+=tag.length;}
 const after=await input.stat();if(after.size!==stat.size||after.mtimeMs!==stat.mtimeMs||after.ctimeMs!==stat.ctimeMs)throw Error('backup input changed');
 if(written!==(decrypt?length:HEADER+length+TAG))throw Error('backup size mismatch');
 await output.sync();await output.close();output=null;await input.close();input=null;
 // Publish only after authentication succeeds; link refuses existing destination.
 await link(stage,loc.output);published=true;await unlink(stage);stageCreated=false;
 const d=await open(loc.outDir,'r');try{await d.sync();}finally{await d.close();}
 return {plaintextBytes:length,plaintextSha256:plainHash.digest('hex'),authenticated:true,algorithm:'AES-256-GCM',chunkBytes:buffer.length};
 }finally{config.key.fill(0);if(input)await input.close().catch(()=>{});if(output)await output.close().catch(()=>{});if(stageCreated)await unlink(stage).catch(()=>{});}
}
export const encryptBackup=(source,destination,opts)=>run(source,destination,opts,false);
export const decryptBackup=(source,destination,opts)=>run(source,destination,opts,true);
