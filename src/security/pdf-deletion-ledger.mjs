// Offline original-PDF deletion evidence. The signer must live outside the PDF
// rendering worker. This is a separate *local* archive, not an offsite backup.
import {open,lstat} from 'node:fs/promises';
import {constants} from 'node:fs';
import {createHash,createPrivateKey,createPublicKey,randomUUID,sign,verify} from 'node:crypto';
import {isAbsolute,join} from 'node:path';
const deny=()=>{throw Error('PDF deletion evidence denied');};
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const HEX=/^[a-f0-9]{64}$/;
const sha=b=>createHash('sha256').update(b).digest('hex');
const iso=x=>typeof x==='string'&&Number.isFinite(Date.parse(x))&&new Date(x).toISOString()===x;
const exact=(o,fields)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).sort().join('|')===fields.slice().sort().join('|');
const properties=['version','kind','deletionId','tenantId','projectId','quarantineId','sourceSha256','authorizationSha256','preparedSha256','issuedAt','keyFingerprint'];
function checkedMeta(meta){
 if(!meta||!UUID.test(meta.tenantId)||!UUID.test(meta.projectId)||!UUID.test(meta.quarantineId)||!HEX.test(meta.sha256))deny();
 return {tenantId:meta.tenantId,projectId:meta.projectId,quarantineId:meta.quarantineId,sourceSha256:meta.sha256};
}
function identity(key){
 const k=key?.type==='public'?key:createPublicKey(key);
 if(k.asymmetricKeyType!=='ed25519')deny();
 return {key:k,fingerprint:sha(k.export({type:'spki',format:'der'}))};
}
function encoded(body){
 if(!exact(body,properties)||body.version!==1||!['prepared','completed'].includes(body.kind)||!UUID.test(body.deletionId)||![body.tenantId,body.projectId,body.quarantineId].every(x=>UUID.test(x))||![body.sourceSha256,body.authorizationSha256,body.keyFingerprint].every(x=>HEX.test(x))||!iso(body.issuedAt)||(body.kind==='prepared'?body.preparedSha256!==null:!HEX.test(body.preparedSha256)))deny();
 return Buffer.from('verivaro-original-pdf-deletion-v1\n'+JSON.stringify(body),'utf8');
}
export function verifyPdfDeletionEvidence(envelope,trustedKey,{meta,prepared}={}){
 const {key,fingerprint}=identity(trustedKey);
 if(!exact(envelope,['body','signature'])||envelope.body?.keyFingerprint!==fingerprint||typeof envelope.signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(envelope.signature))deny();
 const signature=Buffer.from(envelope.signature,'base64url');
 if(signature.length!==64||signature.toString('base64url')!==envelope.signature||!verify(null,encoded(envelope.body),key,signature))deny();
 if(meta){const expected=checkedMeta(meta);for(const [k,v] of Object.entries(expected))if(envelope.body[k]!==v)deny();}
 if(prepared){
  const p=verifyPdfDeletionEvidence(prepared,key,{meta});
  if(p.kind!=='prepared'||envelope.body.kind!=='completed'||p.deletionId!==envelope.body.deletionId||p.authorizationSha256!==envelope.body.authorizationSha256||envelope.body.preparedSha256!==sha(Buffer.from(JSON.stringify(prepared))))deny();
 }
 return envelope.body;
}
export function createLocalPdfDeletionLedger({root,privateKey,clock=()=>new Date()}={}){
 if(typeof root!=='string'||!isAbsolute(root)||root.length>220||/[\x00-\x1f]/.test(root)||typeof clock!=='function'||!constants.O_NOFOLLOW||!constants.O_EXCL)deny();
 const key=privateKey?.type==='private'?privateKey:createPrivateKey(privateKey);
 if(key.asymmetricKeyType!=='ed25519')deny();
 const publicInfo=identity(key);let closed=false;
 async function checkRoot(){
  if(closed)deny();
  const stat=await lstat(root);
  if(!stat.isDirectory()||(stat.mode&0o077)!==0||(typeof process.getuid==='function'&&stat.uid!==process.getuid()))deny();
 }
 function paths(meta){
  const scope=checkedMeta(meta);
  const id=sha(Buffer.from(JSON.stringify(['vv-deletion-ledger-v1',scope])));
  return {stage:join(root,id+'.prepared'),completed:join(root,id+'.completed')};
 }
 function make(body){
  const stamp=clock();if(!(stamp instanceof Date)||!Number.isFinite(stamp.getTime()))deny();
  const completedBody={...body,issuedAt:stamp.toISOString(),keyFingerprint:publicInfo.fingerprint};
  return {body:completedBody,signature:sign(null,encoded(completedBody),key).toString('base64url')};
 }
 async function load(path){
  let f;
  try{f=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);}
  catch(e){if(e.code==='ENOENT')return null;throw e;}
  try{
   const st=await f.stat();
   if(!st.isFile()||(st.mode&0o077)!==0||(typeof process.getuid==='function'&&st.uid!==process.getuid())||st.size<20||st.size>4096)deny();
   const b=Buffer.alloc(st.size);let n=0;try{
    while(n<b.length){const r=await f.read(b,n,b.length-n,n);if(r.bytesRead<1)deny();n+=r.bytesRead;}
    const after=await f.stat();if(after.dev!==st.dev||after.ino!==st.ino||after.size!==st.size||after.mtimeMs!==st.mtimeMs)deny();
    const s=new TextDecoder('utf8',{fatal:true}).decode(b);
    if(!s.endsWith('\n'))deny();const parsed=JSON.parse(s.slice(0,-1));
    if(JSON.stringify(parsed)+'\n'!==s)deny();
    verifyPdfDeletionEvidence(parsed,publicInfo.key);return parsed;
   }finally{b.fill(0);}
  }finally{await f.close();}
 }
 async function writeOnce(path,receipt){
  const bytes=Buffer.from(JSON.stringify(receipt)+'\n');
  if(bytes.length>4096)deny();
  let f;
  try{
   f=await open(path,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW|constants.O_SYNC,0o600);
   let n=0;while(n<bytes.length){const r=await f.write(bytes,n,bytes.length-n,n);if(r.bytesWritten<1)deny();n+=r.bytesWritten;}
   await f.sync();
  }finally{bytes.fill(0);if(f)await f.close();}
  const d=await open(root,constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);
  try{await d.sync();}finally{await d.close();}
  const saved=await load(path);
  if(JSON.stringify(saved)!==JSON.stringify(receipt))deny();
  return saved;
 }
 async function read(meta,{signal}={}){
  if(!signal)deny();signal.throwIfAborted();await checkRoot();
  const p=paths(meta);
  const prepared=await load(p.stage),completed=await load(p.completed);
  if(completed&&!prepared)deny();
  if(prepared){if(verifyPdfDeletionEvidence(prepared,publicInfo.key,{meta}).kind!=='prepared')deny();}
  if(completed)verifyPdfDeletionEvidence(completed,publicInfo.key,{meta,prepared});
  signal.throwIfAborted();
  return {status:completed?'completed':prepared?'prepared':'none',prepared,completed};
 }
 async function prepare(meta,authorizationSha256,signal){
  if(!signal||!HEX.test(authorizationSha256))deny();signal.throwIfAborted();await checkRoot();
  const status=await read(meta,{signal});if(status.status!=='none')deny();
  const body={version:1,kind:'prepared',deletionId:randomUUID(),...checkedMeta(meta),authorizationSha256,preparedSha256:null};
  const envelope=make(body),stored=await writeOnce(paths(meta).stage,envelope);
  verifyPdfDeletionEvidence(stored,publicInfo.key,{meta});
  signal.throwIfAborted();return stored;
 }
 async function complete(meta,prepared,originalPath,signal){
  if(!signal||typeof originalPath!=='string'||!isAbsolute(originalPath))deny();signal.throwIfAborted();await checkRoot();
  const state=await read(meta,{signal});
  if(state.status!=='prepared'||JSON.stringify(state.prepared)!==JSON.stringify(prepared))deny();
  // This proves only that the nominated source path is absent at signing time;
  // it is not a proof of physical erasure or deletion from all backups.
  try{await lstat(originalPath);deny();}catch(e){if(e.code!=='ENOENT')throw e;}
  const verified=verifyPdfDeletionEvidence(prepared,publicInfo.key,{meta});
  const envelope=make({version:1,kind:'completed',deletionId:verified.deletionId,...checkedMeta(meta),authorizationSha256:verified.authorizationSha256,preparedSha256:sha(Buffer.from(JSON.stringify(prepared)))});
  const saved=await writeOnce(paths(meta).completed,envelope);
  verifyPdfDeletionEvidence(saved,publicInfo.key,{meta,prepared});
  signal.throwIfAborted();return saved;
 }
 return Object.freeze({root,fingerprint:publicInfo.fingerprint,publicKey:publicInfo.key.export({format:'pem',type:'spki'}),prepare,complete,read,close(){closed=true;}});
}
