import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync, sign, randomBytes} from 'node:crypto';
import {createScopedDatabase} from '../../src/security/scoped-database.mjs';
const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
const tenant='11111111-1111-4111-8111-111111111111', project='33333333-3333-4333-8333-333333333333';
const actor='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const key=randomBytes(32);
const options={expectedLogin:'vv_ci_runtime',key,verifier:{publicKey,issuer:'fixture',audience:'db-api'}};
const token=()=>{
 const now=Math.floor(Date.now()/1000);
 const b64=obj=>Buffer.from(JSON.stringify(obj)).toString('base64url');
 const body=b64({alg:'RS256',typ:'JWT'})+'.'+b64({iss:'fixture',aud:'db-api',sub:actor,sid:'12345678-1234-4234-8234-123456789abc',iat:now-1,nbf:now-1,exp:now+120});
 return body+'.'+sign('RSA-SHA256',Buffer.from(body),privateKey).toString('base64url');
};
function fixture({failAt, deny=false, privileged=false, rollbackFails=false}={}) {
 const calls=[], releases=[];
 let connects=0;
 const pool={async connect(){connects++;return {
  async query(sql,values){
   calls.push({sql,values});
   if(sql===failAt || (rollbackFails && sql==='ROLLBACK')) throw Error('driver error');
   if(sql.includes('pg_catalog.pg_roles')) return {rows:[{privileged,login_name:'vv_ci_runtime'}]};
   if(sql.includes('pg_backend_pid')) return {rows:[{pid:2345,xid:'123456'}]};
   if(sql.includes('verivaro.authorized')) return {rows:[{allowed:!deny}]};
   if(sql.startsWith('SELECT id,'))return {rows:[{id:project}]};
   return {rows:[]};
  },
  release(error){releases.push(error);}
 };}};
 return {pool,calls,releases,connects:()=>connects};
}
test('exclusive lease sets role, bounded transaction, signed context, parameterized query and cleanup',async()=>{
 const f=fixture(); const db=createScopedDatabase(f.pool,options);
 assert.deepEqual(await db.execute({token:token(),tenantId:tenant,operation:'getProject',args:{projectId:project}}),[{id:project}]);
 const sql=f.calls.map(x=>x.sql);
 assert.equal(sql[0],'DISCARD ALL');assert.equal(sql.at(-1),'DISCARD ALL');
 assert.ok(sql.indexOf('BEGIN ISOLATION LEVEL READ COMMITTED')<sql.findIndex(x=>x.includes('pg_backend_pid')));
 const context=f.calls.find(x=>x.sql.includes('set_config'));
 assert.equal(context.values[0].split('|')[3],'2345');
 assert.equal(context.values[0].split('|')[4],'123456');
 assert.deepEqual(f.calls.find(x=>x.sql.startsWith('SELECT id,')).values,[tenant,project]);
 assert.equal(f.releases.length,1);assert.equal(f.releases[0],undefined);
});
test('rejects unknown operations, injected identifiers and invalid tenant before checkout',async()=>{
 const f=fixture();const db=createScopedDatabase(f.pool,options);
 for(const input of [
  {tenantId:tenant,operation:'toString'},
  {tenantId:tenant,operation:'getProject',args:{projectId:"x'; SELECT 1;--"}},
  {tenantId:'not-a-uuid',operation:'listProjects'}])
  await assert.rejects(db.execute({...input,token:token()}));
 assert.equal(f.connects(),0);
});
test('unauthorized identity fails closed and discards lease',async()=>{
 const f=fixture({deny:true});const db=createScopedDatabase(f.pool,options);
 await assert.rejects(db.execute({token:token(),tenantId:tenant,operation:'listProjects'}),/failed/);
 assert.ok(f.calls.some(x=>x.sql==='ROLLBACK'));
 assert.ok(!f.calls.some(x=>x.sql.startsWith('SELECT id,')));
 assert.ok(f.releases[0] instanceof Error);
});
test('privileged login never reaches transaction or business query',async()=>{
 const f=fixture({privileged:true});const db=createScopedDatabase(f.pool,options);
 await assert.rejects(db.execute({token:token(),tenantId:tenant,operation:'listProjects'}));
 assert.ok(!f.calls.some(x=>x.sql.startsWith('BEGIN')));
 assert.ok(f.releases[0] instanceof Error);
});
test('invalid token rolls back and discards lease',async()=>{
 const f=fixture();const db=createScopedDatabase(f.pool,options);
 await assert.rejects(db.execute({token:'invalid',tenantId:tenant,operation:'listProjects'}));
 assert.ok(f.calls.some(x=>x.sql==='ROLLBACK'));assert.ok(f.releases[0] instanceof Error);
 assert.ok(!f.calls.some(x=>x.sql.includes('set_config')));
});
test('query failure and unsuccessful rollback still discard connection',async()=>{
 const f=fixture({failAt:'SELECT verivaro.authorized($1::uuid) AS allowed',rollbackFails:true});
 const db=createScopedDatabase(f.pool,options);
 await assert.rejects(db.execute({token:token(),tenantId:tenant,operation:'listProjects'}));
 assert.ok(f.calls.some(x=>x.sql==='ROLLBACK'));assert.ok(f.releases[0] instanceof Error);
});
test('commit failure is treated as unknown outcome and discards lease',async()=>{
 const f=fixture({failAt:'COMMIT'});const db=createScopedDatabase(f.pool,options);
 await assert.rejects(db.execute({token:token(),tenantId:tenant,operation:'listProjects'}));
 assert.ok(f.releases[0] instanceof Error);
});

test('indexed evidence listing uses fixed scope query without changing historical adapter default',async()=>{
 const f=fixture(),db=createScopedDatabase(f.pool,{...options,indexedEvidence:true});
 await db.execute({token:token(),tenantId:tenant,operation:'listEvidence',args:{projectId:project}});
 const q=f.calls.find(x=>x.sql.includes('list_evidence_metadata'));
 assert.deepEqual(q.values,[tenant,project]);
 assert.ok(!f.calls.some(x=>x.sql.startsWith('SELECT id, project_id')));
});
test('driver timeout destroys lease without queuing a second rollback on uncertain connection',async()=>{
 const f=fixture(),orig=f.pool.connect,events=[];
 f.pool.connect=async()=>{const c=await orig();const query=c.query;c.query=async(sql,values)=>{if(sql.startsWith('SELECT id,'))throw Error('Query read timeout');return query(sql,values);};return c;};
 await assert.rejects(createScopedDatabase(f.pool,{...options,report:x=>events.push(x)}).execute({token:token(),tenantId:tenant,operation:'listProjects'}));
 assert.ok(!f.calls.some(x=>x.sql==='ROLLBACK'));assert.ok(f.releases[0] instanceof Error);
 assert.deepEqual(events,['scoped_database_failure:listProjects:operation:driver_timeout']);
});
