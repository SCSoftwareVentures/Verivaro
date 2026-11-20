// Read-only verification key is sufficient for replica admission.
// Operator must place this archive on independently managed storage off host
// for actual disaster recovery; two local test directories are NOT offsite.
import {open,lstat} from 'node:fs/promises';
import {constants} from 'node:fs';
import {createHash} from 'node:crypto';
import {isAbsolute,join} from 'node:path';
import {verifyPdfDeletionEvidence} from './pdf-deletion-ledger.mjs';
const fail=()=>{throw Error('PDF deletion replica denied');};
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[89ab][a-f0-9]{3}$/; // overwritten below
const ID=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const HEX=/^[a-f0-9]{64}$/;
const sha=b=>createHash('sha256').update(b).digest('hex');
function scope(m){
 if(!m||!ID.test(m.tenantId)||!ID.test(m.projectId)||!ID.test(m.quarantineId)||!HEX.test(m.sha256))fail();
 return {tenantId:m.tenantId,projectId:m.projectId,quarantineId:m.quarantineId,sourceSha256:m.sha256};
}
export function createLocalPdfDeletionReplica({root,trustedKey}={}){
 if(typeof root!=='string'||!isAbsolute(root)||root.length>220||/[\x00-\x1f]/.test(root)||!trustedKey||!constants.O_NOFOLLOW)fail();
 let closed=false;
 async function check(){
  if(closed)fail();const st=await lstat(root);
  if(!st.isDirectory()||(st.mode&0o077)!==0||(typeof process.getuid==='function'&&st.uid!==process.getuid()))fail();
 }
 const paths=m=>{const token=sha(Buffer.from(JSON.stringify(['vv-pdf-replica-v1',scope(m)])));return {prepared:join(root,token+'.prepared'),completed:join(root,token+'.completed')};};
 async function load(path){
  let file;try{file=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);}
  catch(e){if(e.code==='ENOENT')return null;throw e;}
  try{
   const st=await file.stat();
   if(!st.isFile()||(st.mode&0o077)!==0||(typeof process.getuid==='function'&&st.uid!==process.getuid())||st.size<20||st.size>4096)fail();
   const data=Buffer.alloc(st.size);try{
    let n=0;while(n<data.length){const r=await file.read(data,n,data.length-n,n);if(r.bytesRead<1)fail();n+=r.bytesRead;}
    const after=await file.stat();if(after.dev!==st.dev||after.ino!==st.ino||after.size!==st.size||after.mtimeMs!==st.mtimeMs)fail();
    const text=new TextDecoder('utf8',{fatal:true}).decode(data);
    if(!text.endsWith('\n'))fail();
    const decoded=JSON.parse(text.slice(0,-1));if(JSON.stringify(decoded)+'\n'!==text)fail();
    verifyPdfDeletionEvidence(decoded,trustedKey);return decoded;
   }finally{data.fill(0);}
  }finally{await file.close();}
 }
 async function read(meta,{signal}={}){
  if(!signal)fail();signal.throwIfAborted();await check();
  const p=paths(meta),prepared=await load(p.prepared),completed=await load(p.completed);
  if(completed&&!prepared)fail();
  if(prepared&&verifyPdfDeletionEvidence(prepared,trustedKey,{meta}).kind!=='prepared')fail();
  if(completed)verifyPdfDeletionEvidence(completed,trustedKey,{meta,prepared});
  signal.throwIfAborted();
  return {status:completed?'completed':prepared?'prepared':'none',prepared,completed};
 }
 async function write(meta,receipt,signal){
  if(!signal)fail();signal.throwIfAborted();await check();
  const type=verifyPdfDeletionEvidence(receipt,trustedKey,{meta}).kind,state=await read(meta,{signal});
  if(type==='prepared'?state.status!=='none':state.status!=='prepared')fail();
  if(type==='completed')verifyPdfDeletionEvidence(receipt,trustedKey,{meta,prepared:state.prepared});
  const dest=paths(meta)[type],data=Buffer.from(JSON.stringify(receipt)+'\n');
  let f;try{
   f=await open(dest,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW|constants.O_SYNC,0o600);
   let n=0;while(n<data.length){const r=await f.write(data,n,data.length-n,n);if(r.bytesWritten<1)fail();n+=r.bytesWritten;}
   await f.sync();
  }finally{data.fill(0);if(f)await f.close();}
  const dir=await open(root,constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);
  try{await dir.sync();}finally{await dir.close();}
  const checked=await read(meta,{signal});
  if(JSON.stringify(checked[type])!==JSON.stringify(receipt))fail();
  return checked[type];
 }
 return Object.freeze({root,read,write,close(){closed=true;}});
}
