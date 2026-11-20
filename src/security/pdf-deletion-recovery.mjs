// Read-only deletion recovery audit. Does not delete, restore or unlock files.
// A clean result requires both signed receipt copies and a matching local marker.
import {open,lstat} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join,isAbsolute} from 'node:path';
import {createHash} from 'node:crypto';
const deny=()=>{throw Error('PDF deletion recovery reconciliation denied');};
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const HEX=/^[a-f0-9]{64}$/;
const iso=s=>typeof s==='string'&&Number.isFinite(Date.parse(s))&&new Date(s).toISOString()===s;
const sha=b=>createHash('sha256').update(b).digest('hex');
async function snapshot(path,{text=false}={}){
 let file;
 try{file=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);}
 catch(e){if(e.code==='ENOENT')return null;throw e;}
 try{
  const st=await file.stat();
  if(!st.isFile()||(st.mode&0o077)!==0||(typeof process.getuid==='function'&&st.uid!==process.getuid())||st.size<1||st.size>(text?4096:262144+28))deny();
  if(!text)return {present:true,bytes:st.size};
  const buf=Buffer.alloc(st.size);
  try{
   let n=0;while(n<buf.length){const r=await file.read(buf,n,buf.length-n,n);if(r.bytesRead<1)deny();n+=r.bytesRead;}
   const after=await file.stat();if(after.size!==st.size||after.ino!==st.ino||after.dev!==st.dev||after.mtimeMs!==st.mtimeMs)deny();
   const value=new TextDecoder('utf8',{fatal:true}).decode(buf);
   const object=JSON.parse(value);
   if(JSON.stringify(object)!==value)deny();
   return object;
  }finally{buf.fill(0);}
 }finally{await file.close();}
}
export async function auditPdfDeletionRecovery({root,meta,ledger,signal}={}){
 if(typeof root!=='string'||!isAbsolute(root)||!meta||!UUID.test(meta.quarantineId)||!UUID.test(meta.tenantId)||!UUID.test(meta.projectId)||!HEX.test(meta.sha256)||typeof ledger?.read!=='function'||ledger.replicated!==true||!signal)deny();
 signal.throwIfAborted();const dir=await lstat(root);
 if(!dir.isDirectory()||(dir.mode&0o077)!==0||(typeof process.getuid==='function'&&dir.uid!==process.getuid()))deny();
 const key=meta.quarantineId,sourcePath=join(root,key+'.vvq'),intentPath=join(root,key+'.delete-intent'),tombPath=join(root,key+'.deleted');
 const state=await ledger.read(meta,{signal});
 const [source,intent,deleted]=await Promise.all([snapshot(sourcePath),snapshot(intentPath,{text:true}),snapshot(tombPath,{text:true})]);
 signal.throwIfAborted();
 if(intent&&deleted)deny();
 const prep=state.prepared?.body;
 const expected=prep&&{version:1,kind:'original-pdf-delete-intent',quarantineId:key,tenantId:meta.tenantId,projectId:meta.projectId,sha256:meta.sha256,authorizationSha256:prep.authorizationSha256,preparedSha256:sha(Buffer.from(JSON.stringify(state.prepared))),deletionId:prep.deletionId};
 for(const marker of [intent,deleted]){
  if(!marker)continue;
  if(!expected||Object.keys(marker).sort().join('|')!==[...Object.keys(expected),'issuedAt'].sort().join('|')||!iso(marker.issuedAt))deny();
  for(const [field,val] of Object.entries(expected))if(marker[field]!==val)deny();
 }
 let status;
 if(state.status==='none'&&source&&!intent&&!deleted)status='retained_no_deletion';
 else if(state.status==='prepared'&&source&&!intent&&!deleted)status='prepared_original_still_present';
 else if(state.status==='prepared'&&source&&intent&&!deleted)status='interrupted_before_unlink';
 else if(state.status==='prepared'&&!source&&intent&&!deleted)status='missing_original_pending_completion';
 else if(state.status==='completed'&&!source&&intent&&!deleted)status='signed_completion_local_tombstone_pending';
 else if(state.status==='completed'&&!source&&!intent&&deleted)status='signed_completion_verified';
 else deny();
 return Object.freeze({status,tenantId:meta.tenantId,projectId:meta.projectId,quarantineId:key,sourceSha256:meta.sha256,manualReconciliationRequired:status!=='retained_no_deletion'&&status!=='signed_completion_verified',completedVerified:status==='signed_completion_verified',sourcePresent:Boolean(source),signedPrepared:Boolean(prep),signedCompleted:Boolean(state.completed)});
}
