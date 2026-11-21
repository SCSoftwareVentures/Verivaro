// Single-host REFERENCE signed receipt publisher; NOT an independent service.
// Production needs a separately administered, durable remote trust domain.
// Signing is delegated to a caller-provided capability; no private key stored.
import {open,rename,unlink,realpath} from 'node:fs/promises';
import {constants} from 'node:fs';
import {randomUUID} from 'node:crypto';
import {isAbsolute,join,resolve} from 'node:path';
import {
 canonicalWitnessAuditStatement,verifyExternallySignedWitnessAuditReceipt
} from './provider-witness-audit-receipt.mjs';

const HEX=/^[a-f0-9]{64}$/;
const scopeOk=s=>typeof s==='string'&&s.length>0&&s.length<=512&&!/[\x00-\x1f\x7f]/.test(s);
const fail=()=>Error('reference receipt publisher unavailable');
const DIR=constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW;
const READ=constants.O_RDONLY|constants.O_NOFOLLOW;
const EXCLUSIVE=constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW;
const MAX=4096;
const checkpointSame=(a,b)=>a?.sequence===b?.sequence&&a?.digest===b?.digest;
function same(a,b){return a.count===b.count&&a.headHash===b.headHash&&
 checkpointSame(a.checkpoint,b.checkpoint);}
function exactFloor(state,floor){
 if(state.count!==floor.count||state.headHash!==floor.headHash)throw fail();
}
function canonicalReceipt(e){
 if(!e||typeof e!=='object'||Array.isArray(e)||
  Object.keys(e).sort().join(',')!=='signature,statement')throw fail();
 const s=e.statement;
 // A canonical statement is structurally validated by the signature verifier.
 const body=canonicalWitnessAuditStatement(s);
 if(body.toString('utf8')!==JSON.stringify(s))throw fail();
 if(typeof e.signature!=='string')throw fail();
 const data=Buffer.from(JSON.stringify({statement:s,signature:e.signature})+'\n');
 if(data.length>MAX)throw fail();
 return data;
}
function verifyEnvelope(e,scope,trustedPublicKey,minimumCount){
 const v=verifyExternallySignedWitnessAuditReceipt(e,{
  ...scope,trustedPublicKey,minimumCount
 });
 canonicalReceipt(e);
 return v;
}
function validateStat(s){
 if(!s.isFile()||s.nlink!==1||(s.mode&0o077)!==0||
  s.size<100||s.size>MAX||
  (typeof process.getuid==='function'&&s.uid!==process.getuid()))throw fail();
}
async function strictRead(path,identity){
 const f=await open(path,READ);
 try{
  const first=await f.stat();
  validateStat(first);
  if(identity&&(identity.ino!==first.ino||identity.dev!==first.dev))throw fail();
  const bytes=await f.readFile();
  const second=await f.stat();
  if(bytes.length!==first.size||first.ino!==second.ino||
   first.dev!==second.dev||first.size!==second.size||
   first.mtimeMs!==second.mtimeMs||first.ctimeMs!==second.ctimeMs)throw fail();
  let value;
  try{value=JSON.parse(bytes.toString('utf8'));}catch{throw fail();}
  if(!canonicalReceipt(value).equals(bytes))throw fail();
  return {value,identity:{ino:first.ino,dev:first.dev},bytes};
 }finally{await f.close();}
}
const copy=e=>Object.freeze({
 statement:Object.freeze({...e.statement,
  checkpoint:Object.freeze({...e.statement.checkpoint})}),
 signature:e.signature
});
export async function openReferenceWitnessReceiptPublisher({
 directory,issuer,audience,trustedPublicKey,trustedFloor,signStatement
}){
 if(!isAbsolute(directory??'')||!scopeOk(issuer)||!scopeOk(audience)||
  !trustedFloor||Object.keys(trustedFloor).sort().join(',')!=='count,headHash'||
  !Number.isSafeInteger(trustedFloor.count)||trustedFloor.count<1||
  trustedFloor.count>8192||!HEX.test(trustedFloor.headHash)||
  !trustedPublicKey||typeof signStatement!=='function')throw fail();
 const scope=Object.freeze({issuer,audience}),root=resolve(directory);
 const path=join(root,'signed-witness-receipt.json'),lockPath=join(root,'.receipt-publisher.lock');
 const dir=await open(root,DIR);
 let lease,closed=false,busy=false,faulted=false;
 try{
  const stat=await dir.stat();
  if(!stat.isDirectory()||(stat.mode&0o077)!==0||
   (typeof process.getuid==='function'&&stat.uid!==process.getuid())||
   await realpath(root)!==root)throw fail();
  const initial=await strictRead(path);
  const trusted=verifyEnvelope(initial.value,scope,trustedPublicKey,trustedFloor.count);
  exactFloor(trusted,trustedFloor);
  lease=await open(lockPath,EXCLUSIVE,0o600);
  await lease.writeFile('reserved\n');
  await lease.sync();
  await dir.sync();
  const recheck=await strictRead(path,initial.identity);
  const confirmed=verifyEnvelope(recheck.value,scope,trustedPublicKey,trustedFloor.count);
  exactFloor(confirmed,trustedFloor);
  let expected=copy(recheck.value),identity=recheck.identity;
  async function check(){
   if(closed||faulted)throw fail();
   try{
    const current=await strictRead(path,identity);
    verifyEnvelope(current.value,scope,trustedPublicKey,expected.statement.count);
    if(!canonicalReceipt(current.value).equals(canonicalReceipt(expected)))throw fail();
    return current.value;
   }catch{
    faulted=true;
    throw fail();
   }
  }
  return Object.freeze({
   async read(requestScope){
    if(requestScope?.issuer!==issuer||requestScope?.audience!==audience||
     closed||faulted||busy)throw fail();
    return copy(await check());
   },
   async compareAndSwap({issuer:iss,audience:aud,previous,statement}={}){
    if(iss!==issuer||aud!==audience||closed||faulted||busy)throw fail();
    busy=true;
    let persistenceAttempted=false;
    try{
     const current=await check();
     if(!previous||!canonicalReceipt(previous).equals(canonicalReceipt(current)))
      throw Error('reference receipt CAS conflict');
     const prior=verifyEnvelope(current,scope,trustedPublicKey,1);
     const nextBytes=canonicalWitnessAuditStatement(statement);
     if(statement.issuer!==issuer||statement.audience!==audience||
      statement.count!==prior.count+1||statement.count>8192||
      statement.checkpoint.sequence<=prior.checkpoint.sequence||
      statement.headHash===prior.headHash)throw Error('reference receipt invalid transition');
     // The signer is an external dependency: it must independently verify the
     // signed journal transition and enforce separate custody in production.
     const signature=await signStatement(Buffer.from(nextBytes),statement);
     const next=copy({statement,signature});
     const observed=verifyEnvelope(next,scope,trustedPublicKey,statement.count);
     if(!same(observed,{count:statement.count,headHash:statement.headHash,
      checkpoint:statement.checkpoint}))throw fail();
     const bytes=canonicalReceipt(next);
     const pending=join(root,'.receipt-'+randomUUID()+'.pending');
     let pendingCreated=false;
     try{
      const f=await open(pending,EXCLUSIVE,0o600);
      pendingCreated=true;
      persistenceAttempted=true;
      try{await f.writeFile(bytes);await f.sync();}finally{await f.close();}
      await rename(pending,path);
      pendingCreated=false;
      await dir.sync();
      const verified=await strictRead(path);
      verifyEnvelope(verified.value,scope,trustedPublicKey,statement.count);
      if(!verified.bytes.equals(bytes))throw fail();
      identity=verified.identity;
      expected=next;
      return copy(next);
     }finally{
      if(pendingCreated)await unlink(pending).catch(()=>{});
     }
    }catch(e){
     if(e?.message==='reference receipt CAS conflict'&&!persistenceAttempted)throw e;
     if(e?.message==='reference receipt invalid transition'&&!persistenceAttempted)throw e;
     // No successful operation or retry may follow signer/persistence uncertainty.
     faulted=true;
     throw fail();
    }finally{busy=false;}
   },
   async close(){
    if(closed)return;
    if(busy)throw fail();
    closed=true;
    await lease.close();
    if(!faulted){
     await unlink(lockPath);
     await dir.sync();
    }
    // Faulted publisher preserves its writer lock: reconciliation must be
    // supervised rather than silently resuming after uncertain writes.
    await dir.close();
   }
  });
 }catch(e){
  if(lease)await lease.close().catch(()=>{});
  await dir.close().catch(()=>{});
  // Caller must not distinguish malformed or rolled-back signed records.
  throw fail();
 }
}
