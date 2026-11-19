import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {resolve} from 'node:path';
import {randomUUID,randomBytes,sign} from 'node:crypto';
import {createServer} from 'node:http';
import {local} from '../fixtures/provider-fixture.mjs';
import {createScopedDatabase} from '../../src/security/scoped-database.mjs';
import {createApiAdmission} from '../../src/security/api-admission.mjs';
import {createApplicationApi} from '../../src/security/application-api.mjs';
if(process.env.VV_LIVE_TEST!=='1'||process.env.PGDATABASE!=='verivaro_test'||!process.env.VV_TEST_DRIVER_DIR||!process.env.VV_API_A_PASSWORD)throw Error('disposable CI only');
const {Pool}=createRequire(resolve(process.env.VV_TEST_DRIVER_DIR,'package.json'))('pg');
const cfg={host:process.env.PGHOST,port:Number(process.env.PGPORT),database:process.env.PGDATABASE,max:4,connectionTimeoutMillis:3000};
const tenant='11111111-1111-4111-8111-111111111111',other='22222222-2222-4222-8222-222222222222',project='33333333-3333-4333-8333-333333333333',hidden='44444444-4444-4444-8444-444444444444';
const origin='https://api.example.invalid',verifier={publicKey:local.publicKey,issuer:'urn:verivaro:api-fixture',audience:'api'};
const enc=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
function token(actor,sid){const n=Math.floor(Date.now()/1000),b=enc({alg:'RS256',typ:'JWT'})+'.'+enc({iss:verifier.issuer,aud:verifier.audience,sub:actor,sid,iat:n,nbf:n,exp:n+300});return b+'.'+sign('RSA-SHA256',Buffer.from(b),local.privateKey).toString('base64url');}
test('two live API replicas share peer/actor quotas and enforce tenant/project RLS and strict routing',{timeout:45000},async()=>{
 const admin=new Pool({...cfg,user:process.env.PGUSER,password:process.env.PGPASSWORD}),runtime=new Pool({...cfg,user:'vv_ci_runtime',password:process.env.VV_RUNTIME_PASSWORD}),pa=new Pool({...cfg,user:'vv_ci_api_a',password:process.env.VV_API_A_PASSWORD}),pb=new Pool({...cfg,user:'vv_ci_api_b',password:process.env.VV_API_B_PASSWORD});
 const key=randomBytes(32),a=createApiAdmission(pa,{key,expectedLogin:'vv_ci_api_a'}),b=createApiAdmission(pb,{key,expectedLogin:'vv_ci_api_b'}),actor=randomUUID(),sid=randomUUID(),jwt=token(actor,sid),handle=randomBytes(32).toString('base64url'),servers=[];
 const route='/api/v1/tenants/'+tenant+'/projects',resolveSession=async req=>req.headers.cookie==='fixture='+handle?jwt:null;
 let calls=0;
 try{
  await admin.query("INSERT INTO verivaro.memberships(tenant_id,actor_id,role) VALUES($1,$2,'viewer')",[tenant,actor]);
  await admin.query("INSERT INTO verivaro.project_members(tenant_id,project_id,actor_id,role) VALUES($1,$2,$3,'viewer')",[tenant,project,actor]);
  await admin.query("INSERT INTO verivaro_private.identity_sessions(session_id,actor_id,expires_at) VALUES($1,$2,clock_timestamp()+interval '5 minutes')",[sid,actor]);
  const context=(await admin.query('SELECT key_bytes FROM verivaro_private.context_key WHERE singleton')).rows[0].key_bytes;
  const scoped=createScopedDatabase(runtime,{key:context,verifier,expectedLogin:'vv_ci_runtime'});
  for(const admission of [a,b]){
   const handler=createApplicationApi({origin,admission,verifier,resolveSession,scoped:{execute:async x=>{calls++;return scoped.execute(x);}}});
   const s=createServer(handler);servers.push(s);await new Promise(r=>s.listen(0,'127.0.0.1',r));
  }
  const request=(i,path,opts={})=>fetch('http://127.0.0.1:'+servers[i].address().port+path,{...opts,headers:{host:'api.example.invalid',cookie:'fixture='+handle,...opts.headers}});
  const reset=async(peer=120,actor=60)=>{await admin.query('DELETE FROM verivaro_private.api_rate_keys');await admin.query('UPDATE verivaro_private.api_rate_state SET bucket=-1,requests=0,global_limit=600,peer_limit=$1,actor_limit=$2',[peer,actor]);};
  await reset();
  const good=await request(0,route);assert.equal(good.status,200);assert.equal(good.headers.get('cache-control'),'no-store, private');assert.deepEqual((await good.json()).items.map(x=>x.id),[project]);
  assert.equal((await request(1,route+'/'+project)).status,200);
  assert.equal((await request(1,route+'/'+hidden)).status,404);
  assert.equal((await request(0,route.replace(tenant,other))).status,404);
  const ev=await request(0,route+'/'+project+'/evidence');assert.equal(ev.status,200);for(const item of (await ev.json()).items)assert.deepEqual(Object.keys(item),['id','projectId','sha256','createdAt']);
  const before=calls;
  for(const p of [route+'?operation=delete',route+'%2f'+project,route+'/unknown',route+';foo'])assert.equal((await request(0,p)).status,404);
  assert.equal((await request(0,route,{method:'POST',body:'{}'})).status,400);
  assert.equal((await request(0,route,{method:'DELETE'})).status,405);
  assert.equal((await request(0,route,{headers:{origin:'https://evil.invalid'}})).status,403);
  assert.equal((await request(0,route,{headers:{authorization:'Bearer forged'}})).status,400);
  assert.equal((await request(0,route,{headers:{cookie:'fixture=wrong'}})).status,401);
  assert.equal(calls,before);
  await reset(120,3);
  const actorBurst=await Promise.all(Array.from({length:6},(_,i)=>request(i%2,route)));
  assert.equal(actorBurst.filter(r=>r.status===200).length,3);assert.equal(actorBurst.filter(r=>r.status===429).length,3);
  await reset(3,60);
  const peerBurst=await Promise.all(Array.from({length:6},(_,i)=>request(i%2,route,{headers:{'x-forwarded-for':'192.0.2.'+(i+1)}})));
  assert.equal(peerBurst.filter(r=>r.status===200).length,3);assert.equal(peerBurst.filter(r=>r.status===429).length,3);
  await reset();
  await admin.query('UPDATE verivaro_private.identity_sessions SET revoked_at=clock_timestamp() WHERE session_id=$1',[sid]);
  assert.equal((await request(0,route)).status,404);
  await assert.rejects(pa.query('SELECT * FROM verivaro_private.api_rate_keys'),e=>e.code==='42501');
  const c=await pa.connect();try{await c.query('SET ROLE verivaro_api_admission');await assert.rejects(c.query('SELECT verivaro_admission.acquire($1,$2,$3)',[randomUUID(),randomBytes(32),1]),e=>e.code==='42501');}finally{c.release(true);}
 }finally{for(const s of servers)await new Promise(r=>{s.closeAllConnections();s.close(r);});await admin.end();await runtime.end();await pa.end();await pb.end();}
});
