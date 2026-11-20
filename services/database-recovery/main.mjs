import {open} from 'node:fs/promises';
import {constants} from 'node:fs';
import {createBackupKeyring} from '../../src/security/backup-keyring.mjs';
import {spawn} from 'node:child_process';
import {pipeline} from 'node:stream/promises';
import {Readable} from 'node:stream';
import {fileURLToPath} from 'node:url';
import {createEncryptedBackup,verifyAndStageBackup,MAX_BACKUP_BYTES} from '../../src/security/encrypted-database-backup.mjs';
const [mode,path,target]=process.argv.slice(2);
const database=process.env.PGDATABASE,installationId=process.env.VV_INSTALLATION_ID;
const raw=process.env.VV_BACKUP_KEY,keyFile=process.env.VV_BACKUP_KEYRING_FILE;
const maxBytes=Number(process.env.VV_BACKUP_MAX_BYTES??512*1024*1024);
function decode(raw){const k=Buffer.from(raw??'','base64url');if(k.length!==32||k.toString('base64url')!==raw)throw Error('invalid backup credential');return k;}
let key,keyring;
if(!['backup','restore'].includes(mode)||!path||!/^[a-z][a-z0-9_]{0,62}$/.test(database??'')||
 !process.env.PGHOST||!process.env.PGUSER||(raw===undefined)===(keyFile===undefined)||!Number.isSafeInteger(maxBytes)||maxBytes<1||maxBytes>MAX_BACKUP_BYTES)throw Error('invalid backup configuration');
const env={PATH:process.env.PATH,LANG:'C'};
for(const name of ['PGHOST','PGPORT','PGUSER','PGPASSWORD','PGPASSFILE','PGSSLMODE','PGSSLROOTCERT','PGSSLCERT','PGSSLKEY'])if(process.env[name]!==undefined)env[name]=process.env[name];
env.PGCONNECT_TIMEOUT='5';
const controller=new AbortController(),signal=controller.signal;
const timer=setTimeout(()=>controller.abort(),120000);timer.unref();
const stop=()=>controller.abort();process.once('SIGINT',stop);process.once('SIGTERM',stop);
function child(command,args,{input=false,output=false}={}){
 const p=spawn(command,args,{env,stdio:[input?'pipe':'ignore',output?'pipe':'ignore','ignore'],signal});
 const done=new Promise((resolve,reject)=>{p.once('error',reject);p.once('close',code=>code===0?resolve():reject(Error('database tool failed')));});
 done.catch(()=>{});return {p,done};
}
async function execute(command,args){await child(command,args).done;}
async function query(db,sql){
 const {p,done}=child('psql',['-X','-w','-Atq','-v','ON_ERROR_STOP=1','--dbname='+db,'-c',sql],{output:true});
 let text='';for await(const chunk of p.stdout){text+=chunk;if(text.length>8192){p.kill();throw Error('unexpected database response');}}
 await done;return text.trim();
}
async function checkToolVersion(command,db){
 const {p,done}=child(command,['--version'],{output:true});
 let version='';for await(const c of p.stdout){version+=c;if(version.length>1024){p.kill();throw Error('invalid utility version');}}
 await done;
 const m=/PostgreSQL\) (\d+)/.exec(version);
 const server=Number(await query(db,'SHOW server_version_num'));
 if(!m||!Number.isSafeInteger(server)||Number(m[1])!==Math.floor(server/10000))throw Error('PostgreSQL major version mismatch');
}
try{
 if(keyFile!==undefined){
  const file=await open(keyFile,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{
   const s=await file.stat();if(!s.isFile()||(s.mode&0o077)!==0||s.size<1||s.size>8192)throw Error('unsafe keyring file');
   const data=Buffer.alloc(s.size);let n=0;
   while(n<data.length){const r=await file.read(data,n,data.length-n,n);if(!r.bytesRead)throw Error('truncated keyring');n+=r.bytesRead;}
   const m=JSON.parse(data.toString('utf8'));data.fill(0);
   if(!Array.isArray(m.keys)||m.keys.length>16)throw Error('invalid keyring');
   const keys=m.keys.map(x=>({id:x.id,key:decode(x.key)})),legacyKey=m.legacyKey===undefined?undefined:decode(m.legacyKey);
   try{keyring=createBackupKeyring({activeId:m.activeId,keys,legacyKey});}finally{for(const k of keys)k.key.fill(0);legacyKey?.fill(0);}
  }finally{await file.close();}
 }else key=decode(raw);
 const cryptoConfig=keyring?{keyring}:{key};
 if(mode==='backup'){
  await checkToolVersion('pg_dump',database);
  if(target)throw Error('unexpected backup parameter');
  const {p,done}=child('pg_dump',['--format=custom','--no-password','--dbname='+database],{output:true});
  try{
   const backup=await createEncryptedBackup(p.stdout,{root:path,...cryptoConfig,maxBytes,installationId,database,signal,assertComplete:()=>done});
   process.stdout.write(JSON.stringify(backup)+'\n');
  }finally{if(p.exitCode===null)p.kill();}
 }else{
  if(process.env.VV_RESTORE_APPROVED!=='1'||!/^verivaro_restore_[a-z0-9_]{1,40}$/.test(target??'')||target===database)throw Error('isolated restore approval required');
  await checkToolVersion('pg_restore','postgres');
  const staged=await verifyAndStageBackup({path,spoolDirectory:process.env.VV_RESTORE_SPOOL,...cryptoConfig,maxBytes,installationId,database,signal});
  try{
   // Never reuse or overwrite a database. The newly-created target remains
   // restricted even if restore/quarantine fails.
   await query('postgres','CREATE DATABASE '+target+' WITH TEMPLATE template0 ALLOW_CONNECTIONS false');
   await query('postgres','REVOKE CONNECT ON DATABASE '+target+' FROM PUBLIC');
   await query('postgres','ALTER DATABASE '+target+' ALLOW_CONNECTIONS true');
   if(await query(target,"SELECT count(*) FROM pg_catalog.pg_roles WHERE rolcanlogin AND NOT rolsuper AND rolname<>current_user AND has_database_privilege(oid,current_database(),'CONNECT')")!=='0')throw Error('restore target connection boundary failed');
   if(await query(target,"SELECT count(*) FROM pg_catalog.pg_namespace WHERE nspname NOT IN ('public','information_schema') AND nspname NOT LIKE 'pg_%'")!=='0')throw Error('restore target not empty');
   const {p,done}=child('pg_restore',['--no-password','--single-transaction','--exit-on-error','--dbname='+target],{input:true});
   try{await Promise.all([pipeline(Readable.from(staged.read()),p.stdin,{signal}),done]);}catch(e){p.kill();throw e;}
   if(await query(target,"SELECT count(*) FROM pg_catalog.pg_roles WHERE rolcanlogin AND NOT rolsuper AND rolname<>current_user AND has_database_privilege(oid,current_database(),'CONNECT')")!=='0')throw Error('post-restore connection boundary failed');
   await execute('psql',['-X','-w','-q','-v','ON_ERROR_STOP=1','-v','backup_id='+staged.backupId,'--dbname='+target,'-f',fileURLToPath(new URL('./quarantine.sql',import.meta.url))]);
   process.stdout.write(JSON.stringify({backupId:staged.backupId,target,status:'restored_quarantined'})+'\n');
  }finally{await staged.close();}
 }
}catch{process.stderr.write('backup_or_restore_failed\n');process.exitCode=1;}
finally{key?.fill(0);keyring?.close();clearTimeout(timer);process.removeListener('SIGINT',stop);process.removeListener('SIGTERM',stop);}
