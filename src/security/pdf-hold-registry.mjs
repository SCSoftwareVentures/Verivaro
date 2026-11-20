import {open,lstat,unlink} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join,isAbsolute} from 'node:path';
import {createHmac,randomUUID,timingSafeEqual} from 'node:crypto';
// Offline single-host registry; never auto-remove a stale cross-process lock.
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const sha=/^[a-f0-9]{64}$/;
const deny=()=>{throw Error('legal-hold registry denied');};
const keys=(o,fields)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).sort().join('|')===fields.slice().sort().join('|');
const scope=m=>{if(!m||!uuid.test(m.tenantId)||!uuid.test(m.projectId)||!uuid.test(m.quarantineId)||!sha.test(m.sha256))deny();return Object.freeze({tenantId:m.tenantId,projectId:m.projectId,quarantineId:m.quarantineId,sourceSha256:m.sha256});};
const clean=s=>typeof s==='string'&&s.length>=8&&s.length<=256&&s===s.trim()&&!/[\x00-\x1f\x7f-\x9f]/u.test(s);
const iso=s=>typeof s==='string'&&Number.isFinite(Date.parse(s))&&new Date(s).toISOString()===s;
const mac=(k,v)=>createHmac('sha256',k).update(v).digest('hex');
const equal=(a,b)=>sha.test(a)&&sha.test(b)&&timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));
const fields=['version','sequence','eventId','tenantId','projectId','quarantineId','sourceSha256','held','actorId','reason','issuedAt','previousMac'];
export function createLocalPdfHoldRegistry({root,key,authorizeChange,clock=()=>new Date()}={}){
 if(typeof root!=='string'||!isAbsolute(root)||root.length>220||/[\x00-\x1f]/.test(root)||!Buffer.isBuffer(key)||key.length!==32||typeof authorizeChange!=='function'||typeof clock!=='function'||!constants.O_NOFOLLOW||!constants.O_EXCL)deny();
 const secret=Buffer.from(key),active=new Set();let closed=false;
 async function check(){if(closed)deny();const s=await lstat(root);if(!s.isDirectory()||(s.mode&0o077)!==0||(typeof process.getuid==='function'&&s.uid!==process.getuid()))deny();}
 const paths=m=>{const token=mac(secret,JSON.stringify(['vv-pdf-hold-v1',scope(m)]));return {token,lock:join(root,token+'.lock'),journal:join(root,token+'.holdlog')};};
 async function events(meta){
  if(closed)deny();const {token,journal}=paths(meta);if(!active.has(token))deny();
  let f;try{f=await open(journal,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);}catch(e){if(e.code==='ENOENT')return [];throw e;}
  try{
   const s=await f.stat();if(!s.isFile()||(s.mode&0o077)!==0||(typeof process.getuid==='function'&&s.uid!==process.getuid())||s.size<1||s.size>65536)deny();
   const buf=Buffer.alloc(s.size);let n=0;
   while(n<buf.length){const c=(await f.read(buf,n,buf.length-n,n)).bytesRead;if(c<1)deny();n+=c;}
   const after=await f.stat();if(after.size!==s.size||after.ino!==s.ino||after.dev!==s.dev||after.mtimeMs!==s.mtimeMs)deny();
   let content;try{content=new TextDecoder('utf8',{fatal:true}).decode(buf);}finally{buf.fill(0);}
   if(!content.endsWith('\n'))deny();const lines=content.slice(0,-1).split('\n');if(lines.length>64)deny();
   let prev='0'.repeat(64);const output=[];
   for(let i=0;i<lines.length;i++){
    let row;try{row=JSON.parse(lines[i]);}catch{deny();}
    const v=row?.body;if(!keys(row,['body','mac'])||!keys(v,fields)||!sha.test(row.mac)||v.version!==1||v.sequence!==i+1||!uuid.test(v.eventId)||!uuid.test(v.actorId)||!iso(v.issuedAt)||typeof v.held!=='boolean'||!clean(v.reason)||v.previousMac!==prev)deny();
    for(const [k,value] of Object.entries(scope(meta)))if(v[k]!==value)deny();
    if(!equal(row.mac,mac(secret,JSON.stringify(v)))||JSON.stringify(row)!==lines[i])deny();
    prev=row.mac;output.push(row);
   }
   return output;
  }finally{await f.close();}
 }
 async function withExclusiveHoldLock(meta,fn,signal){
  if(typeof fn!=='function'||!signal)deny();signal.throwIfAborted();await check();
  const {token,lock}=paths(meta);if(active.has(token))deny();
  let f,created=false;
  try{
   f=await open(lock,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY|constants.O_NOFOLLOW|constants.O_SYNC,0o600);created=true;
   const mark=Buffer.from(JSON.stringify({version:1,id:randomUUID(),at:new Date().toISOString()})+'\n');
   try{await f.writeFile(mark);await f.sync();}finally{mark.fill(0);}
   active.add(token);signal.throwIfAborted();
   return await fn();
  }finally{
   active.delete(token);
   if(f)await f.close();
   if(created)await unlink(lock);
  }
 }
 async function holdLookup(meta,signal){
  if(!signal)deny();signal.throwIfAborted();
  const rows=await events(meta);signal.throwIfAborted();
  return rows.at(-1)?.body.held;
 }
 async function recordHoldChange(meta,{actorId,held,reason,signal}={}){
  return withExclusiveHoldLock(meta,async()=>{
   if(!uuid.test(actorId)||typeof held!=='boolean'||!clean(reason))deny();
   const proposal=Object.freeze({...scope(meta),actorId,held,reason});
   if(await authorizeChange(proposal,signal)!==true)deny();
   signal.throwIfAborted();
   const rows=await events(meta);if(rows.length>=64||rows.at(-1)?.body.held===held)deny();
   const at=clock();if(!(at instanceof Date)||!Number.isFinite(at.getTime()))deny();
   const body={version:1,sequence:rows.length+1,eventId:randomUUID(),...scope(meta),held,actorId,reason,issuedAt:at.toISOString(),previousMac:rows.at(-1)?.mac??'0'.repeat(64)};
   const row={body,mac:mac(secret,JSON.stringify(body))},line=Buffer.from(JSON.stringify(row)+'\n');
   if(line.length>2048)deny();
   const {journal}=paths(meta);
   const f=await open(journal,constants.O_WRONLY|constants.O_APPEND|constants.O_CREAT|constants.O_NOFOLLOW|constants.O_SYNC,0o600);
   try{
    const s=await f.stat();if(!s.isFile()||(s.mode&0o077)!==0||(typeof process.getuid==='function'&&s.uid!==process.getuid())||s.size>65536-line.length)deny();
    let n=0;while(n<line.length){const count=(await f.write(line,n,line.length-n,null)).bytesWritten;if(!count)deny();n+=count;}await f.sync();
   }finally{line.fill(0);await f.close();}
   const check=await events(meta);if(check.length!==rows.length+1||check.at(-1).mac!==row.mac)deny();
   return Object.freeze({sequence:body.sequence,eventId:body.eventId,held,entryMac:row.mac});
  },signal);
 }
 return Object.freeze({withExclusiveHoldLock,holdLookup,recordHoldChange,close(){if(active.size)deny();closed=true;secret.fill(0);}});
}
