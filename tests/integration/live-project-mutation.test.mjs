import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {resolve} from 'node:path';
import {randomUUID,randomBytes,sign} from 'node:crypto';
import {createServer,request as httpRequest} from 'node:http';
import {local} from '../fixtures/provider-fixture.mjs';
import {createScopedDatabase} from '../../src/security/scoped-database.mjs';
import {createApiAdmission} from '../../src/security/api-admission.mjs';
import {createApplicationApi} from '../../src/security/application-api.mjs';
if(process.env.VV_LIVE_TEST!=='1'||process.env.PGDATABASE!=='verivaro_test'||!process.env.VV_TEST_DRIVER_DIR||!process.env.VV_API_A_PASSWORD)throw Error('disposable CI only');
const {Pool}=createRequire(resolve(process.env.VV_TEST_DRIVER_DIR,'package.json'))('pg');
const cfg={host:process.env.PGHOST,port:Number(process.env.PGPORT),database:process.env.PGDATABASE,max:4,connectionTimeoutMillis:3000};
const tenant='11111111-1111-4111-8111-111111111111',project='33333333-3333-4333-8333-333333333333',other='22222222-2222-4222-8222-222222222222';
const origin='https://mutation.example.invalid',verifier={publicKey:local.publicKey,issuer:'urn:verivaro:mutation-fixture',audience:'api'};
const enc=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
function token(actor,sid){const n=Math.floor(Date.now()/1000),b=enc({alg:'RS256',typ:'JWT'})+'.'+enc({iss:verifier.issuer,aud:verifier.audience,sub:actor,sid,iat:n,nbf:n,exp:n+300});return b+'.'+sign('RSA-SHA256',Buffer.from(b),local.privateKey).toString('base64url');}
test('atomic project mutation authorization, concurrent idempotency, optimistic conflict and immutable audit',{timeout:45000},async()=>{
 const admin=new Pool({...cfg,user:process.env.PGUSER,password:process.env.PGPASSWORD}),runtime=new Pool({...cfg,user:'vv_ci_runtime',password:process.env.VV_RUNTIME_PASSWORD}),pa=new Pool({...cfg,user:'vv_ci_api_a',password:process.env.VV_API_A_PASSWORD});
 let server;const principals={},route='/api/v1/tenants/'+tenant+'/projects/'+project;
 try{
  for(const [label,tenantRole,projectRole] of [['owner','owner','owner'],['viewer','viewer','viewer'],['partial','owner','reviewer']]){
   const actor=randomUUID(),sid=randomUUID();
   await admin.query('INSERT INTO verivaro.memberships(tenant_id,actor_id,role) VALUES($1,$2,$3)',[tenant,actor,tenantRole]);
   await admin.query('INSERT INTO verivaro.project_members(tenant_id,project_id,actor_id,role) VALUES($1,$2,$3,$4)',[tenant,project,actor,projectRole]);
   await admin.query("INSERT INTO verivaro_private.identity_sessions(session_id,actor_id,expires_at) VALUES($1,$2,clock_timestamp()+interval '5 minutes')",[sid,actor]);
   principals[label]={actor,sid,jwt:token(actor,sid)};
  }
  await admin.query('DELETE FROM verivaro_private.api_rate_keys');await admin.query('UPDATE verivaro_private.api_rate_state SET bucket=-1,requests=0,global_limit=600,peer_limit=120,actor_limit=60');
  const context=(await admin.query('SELECT key_bytes FROM verivaro_private.context_key WHERE singleton')).rows[0].key_bytes;
  const scoped=createScopedDatabase(runtime,{key:context,verifier,expectedLogin:'vv_ci_runtime'});
  const admission=createApiAdmission(pa,{key:randomBytes(32),expectedLogin:'vv_ci_api_a'});
  server=createServer(createApplicationApi({origin,admission,verifier,resolveSession:async req=>principals[req.headers.cookie?.slice(8)]?.jwt??null,scoped}));
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  function patch(body,id,who='owner',url=route,extra={}){
   return new Promise((resolve,reject)=>{
    const raw=typeof body==='string'?body:JSON.stringify(body),headers={host:'mutation.example.invalid',origin,cookie:'fixture='+who,'content-type':'application/json','content-length':Buffer.byteLength(raw),'idempotency-key':id,...extra};
    const req=httpRequest({host:'127.0.0.1',port:server.address().port,path:url,method:'PATCH',headers},res=>{
     const chunks=[];res.on('data',x=>chunks.push(x));res.on('error',reject);res.on('end',()=>resolve({status:res.statusCode,body:JSON.parse(Buffer.concat(chunks).toString())}));
    });req.on('error',reject);req.setTimeout(10000,()=>req.destroy(Error('fixture timeout')));req.end(raw);
   });
  }
  const old=(await admin.query('SELECT name,revision FROM verivaro.projects WHERE id=$1',[project])).rows[0],body={name:'Audited project',revision:old.revision},id=randomUUID();
  for(const who of ['viewer','partial'])assert.equal((await patch(body,randomUUID(),who)).status,404);
  assert.equal((await patch(body,randomUUID(),'owner',route.replace(tenant,other))).status,404);
  assert.equal((await patch(body,randomUUID(),'owner',route,{origin:'https://evil.invalid'})).status,403);
  assert.equal((await patch('{"name":"x","name":"y","revision":0}',randomUUID())).status,400);
  assert.equal((await patch({...body,actor_id:principals.owner.actor},randomUUID())).status,400);
  assert.equal((await patch({...body,name:'a'.repeat(129)},randomUUID())).status,400);
  assert.equal((await patch(body,'wrong')).status,400);
  const concurrent=await Promise.all(Array.from({length:6},()=>patch(body,id)));
  assert.ok(concurrent.every(x=>x.status===200));assert.ok(concurrent.every(x=>x.body.project.revision===old.revision+1));
  assert.equal((await patch({...body,name:'Different'},id)).status,409);
  assert.equal((await patch(body,randomUUID())).status,409);
  assert.equal((await admin.query('SELECT count(*)::int AS n FROM verivaro_private.project_mutation_audit WHERE request_id=$1',[id])).rows[0].n,1);
  assert.equal((await admin.query('SELECT count(*)::int AS n FROM verivaro_private.project_mutation_receipts WHERE request_id=$1',[id])).rows[0].n,1);
  const current=(await admin.query('SELECT name,revision FROM verivaro.projects WHERE id=$1',[project])).rows[0];assert.deepEqual(current,{name:body.name,revision:old.revision+1});
  const race=await Promise.all([patch({name:'Race A',revision:current.revision},randomUUID()),patch({name:'Race B',revision:current.revision},randomUUID())]);
  assert.deepEqual(race.map(x=>x.status).sort(),[200,409]);
  await assert.rejects(admin.query('DELETE FROM verivaro_private.project_mutation_audit WHERE request_id=$1',[id]),e=>e.code==='42501');
  await assert.rejects(admin.query('UPDATE verivaro_private.project_mutation_receipts SET result_revision=9 WHERE request_id=$1',[id]),e=>e.code==='42501');
  const c=await runtime.connect();try{await c.query('SET ROLE verivaro_runtime');await assert.rejects(c.query('UPDATE verivaro.projects SET name=$1 WHERE id=$2',['bypass',project]),e=>e.code==='42501');
   await assert.rejects(c.query('SELECT * FROM verivaro_private.project_mutation_audit'),e=>e.code==='42501');
   await assert.rejects(c.query('SELECT verivaro_mutation.rename_project($1,$2,$3,$4,$5)',[tenant,project,randomUUID(),'forged',0]),e=>e.code==='42501');
  }finally{c.release(true);}
  await admin.query('UPDATE verivaro.project_members SET revoked_at=clock_timestamp() WHERE actor_id=$1 AND project_id=$2',[principals.owner.actor,project]);
  assert.equal((await patch(body,id)).status,404);
 }finally{if(server)await new Promise(r=>{server.closeAllConnections();server.close(r);});await admin.end();await runtime.end();await pa.end();}
});
