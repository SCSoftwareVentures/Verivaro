import {spawn} from 'node:child_process';
import {pipeline} from 'node:stream/promises';
import {Readable} from 'node:stream';
import {fileURLToPath} from 'node:url';
import {createEncryptedBackup,verifyAndStageBackup} from '../../src/security/encrypted-database-backup.mjs';
const [mode,path,target]=process.argv.slice(2);
const database=process.env.PGDATABASE,installationId=process.env.VV_INSTALLATION_ID;
const raw=process.env.VV_BACKUP_KEY??'',key=Buffer.from(raw,'base64url');
if(!['backup','restore'].includes(mode)||!path||!/^[a-z][a-z0-9_]{0,62}$/.test(database??'')||
 !process.env.PGHOST||!process.env.PGUSER||key.length!==32||key.toString('base64url')!==raw)throw Error('invalid backup configuration');
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
try{
 if(mode==='backup'){
  if(target)throw Error('unexpected backup parameter');
  const {p,done}=child('pg_dump',['--format=custom','--no-password','--dbname='+database],{output:true});
  try{
   const backup=await createEncryptedBackup(p.stdout,{root:path,key,installationId,database,signal,assertComplete:()=>done});
   process.stdout.write(JSON.stringify(backup)+'\n');
  }finally{if(p.exitCode===null)p.kill();}
 }else{
  if(process.env.VV_RESTORE_APPROVED!=='1'||!/^verivaro_restore_[a-z0-9_]{1,40}$/.test(target??'')||target===database)throw Error('isolated restore approval required');
  const staged=await verifyAndStageBackup({path,spoolDirectory:process.env.VV_RESTORE_SPOOL,key,installationId,database,signal});
  try{
   // Never reuse or overwrite a database. The newly-created target remains
   // restricted even if restore/quarantine fails.
   await execute('createdb',['-w','--maintenance-db=postgres','--template=template0',target]);
   await query('postgres','REVOKE CONNECT ON DATABASE '+target+' FROM PUBLIC');
   if(await query(target,"SELECT count(*) FROM pg_catalog.pg_roles WHERE rolcanlogin AND NOT rolsuper AND rolname<>current_user AND has_database_privilege(oid,current_database(),'CONNECT')")!=='0')throw Error('restore target connection boundary failed');
   if(await query(target,"SELECT count(*) FROM pg_catalog.pg_namespace WHERE nspname NOT IN ('public','information_schema') AND nspname NOT LIKE 'pg_%'")!=='0')throw Error('restore target not empty');
   const {p,done}=child('pg_restore',['--no-password','--single-transaction','--exit-on-error','--dbname='+target],{input:true});
   try{await Promise.all([pipeline(Readable.from(staged.read()),p.stdin,{signal}),done]);}catch(e){p.kill();throw e;}
   await execute('psql',['-X','-w','-q','-v','ON_ERROR_STOP=1','-v','backup_id='+staged.backupId,'--dbname='+target,'-f',fileURLToPath(new URL('./quarantine.sql',import.meta.url))]);
   process.stdout.write(JSON.stringify({backupId:staged.backupId,target,status:'restored_quarantined'})+'\n');
  }finally{await staged.close();}
 }
}catch{process.stderr.write('backup_or_restore_failed\n');process.exitCode=1;}
finally{key.fill(0);clearTimeout(timer);process.removeListener('SIGINT',stop);process.removeListener('SIGTERM',stop);}
