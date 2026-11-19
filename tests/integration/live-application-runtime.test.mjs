import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {resolve,join} from 'node:path';
import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {randomUUID,randomBytes,generateKeyPairSync,createHash,sign} from 'node:crypto';
import {request as httpsRequest} from 'node:https';
import {issuer,audience,publicKey,local,token} from '../fixtures/provider-fixture.mjs';
import {digestSubject} from '../../src/security/provider-identity.mjs';
import {createApplicationRuntime} from '../../src/security/application-runtime.mjs';
if(process.env.VV_LIVE_TEST!=='1'||process.env.PGDATABASE!=='verivaro_test'||!process.env.VV_TLS_FIXTURE||!process.env.VV_TEST_DRIVER_DIR)throw Error('disposable CI only');
const {Pool}=createRequire(resolve(process.env.VV_TEST_DRIVER_DIR,'package.json'))('pg');
const tenant='11111111-1111-4111-8111-111111111111',project='33333333-3333-4333-8333-333333333333';
test('HTTPS runtime boots with three TLS-pinned database pools, real browser login and RLS API',{timeout:60000},async()=>{
 const admin=new Pool({host:process.env.PGHOST,port:Number(process.env.PGPORT),user:process.env.PGUSER,password:process.env.PGPASSWORD,database:'verivaro_test',max:2});
 const dir=await mkdtemp(join(tmpdir(),'vv-runtime-')),tls=process.env.VV_TLS_FIXTURE,authority=generateKeyPairSync('ed25519'),actor=randomUUID(),subject='runtime-'+randomUUID(),origin='https://localhost:18443',codes=new Map();
 let app;
 async function put(name,data){const p=join(dir,name);await writeFile(p,data,{mode:0o600});return p;}
 const now=Math.floor(Date.now()/1000),catalogue=Buffer.from(JSON.stringify({version:1,issuer,audience,sequence:1,issuedAt:now,expiresAt:now+600,keys:[{kid:'fixture',pem:publicKey.export({type:'spki',format:'pem'})}]}));
 try{
  await admin.query("INSERT INTO verivaro.memberships(tenant_id,actor_id,role) VALUES($1,$2,'viewer')",[tenant,actor]);
  await admin.query("INSERT INTO verivaro.project_members(tenant_id,project_id,actor_id,role) VALUES($1,$2,$3,'viewer')",[tenant,project,actor]);
  await admin.query('SELECT verivaro_identity.provision_binding($1,$2,$3,$4)',[issuer,digestSubject(subject),actor,randomUUID()]);
  await admin.query('DELETE FROM verivaro_private.api_rate_keys');
  await admin.query('UPDATE verivaro_private.api_rate_state SET bucket=-1,requests=0,global_limit=600,peer_limit=120,actor_limit=60');
  const context=(await admin.query('SELECT key_bytes FROM verivaro_private.context_key WHERE singleton')).rows[0].key_bytes,secret=randomBytes(32).toString('base64url');
  const cfg={origin,listenHost:'127.0.0.1',listenPort:18443,tlsKeyFile:join(tls,'server.key'),tlsCertFile:join(tls,'server.crt'),
   database:{host:'localhost',port:Number(process.env.PGPORT),name:'verivaro_test',caFile:join(tls,'ca.pem')},
   logins:{identity:{user:'vv_ci_identity',passwordFile:await put('identity',process.env.VV_IDENTITY_PASSWORD)},runtime:{user:'vv_ci_runtime',passwordFile:await put('runtime',process.env.VV_RUNTIME_PASSWORD)},admission:{user:'vv_ci_api_a',passwordFile:await put('admission',process.env.VV_API_A_PASSWORD)}},
   provider:{issuer,audience,authorizationEndpoint:issuer+'/authorize',tokenEndpoint:issuer+'/token',requiredAcr:'fixture:mfa',requiredAmr:['mfa'],authorityFile:await put('authority',authority.publicKey.export({type:'spki',format:'pem'})),checkpointFile:await put('checkpoint',JSON.stringify({sequence:1,digest:createHash('sha256').update(catalogue).digest('hex')})),catalogueFile:await put('catalogue',catalogue),signatureFile:await put('sig',sign(null,catalogue,authority.privateKey)),clientSecretFile:await put('client-secret',secret)},
   local:{issuer:'urn:verivaro:runtime-fixture',audience:'api',signingKeyFile:await put('signing',local.privateKey.export({type:'pkcs8',format:'pem'}))},
   secrets:{admissionKeyFile:await put('admission-key',randomBytes(32).toString('base64url')),contextKeyFile:await put('context-key',context.toString('base64url')),browserKeyFile:await put('browser-key',randomBytes(32).toString('base64url'))}};
  const configPath=await put('configuration',JSON.stringify(cfg));
  const invalidPath=await put('invalid',JSON.stringify({...cfg,logins:{...cfg.logins,admission:cfg.logins.identity}}));
  await assert.rejects(createApplicationRuntime({configPath:invalidPath,Pool}),/startup denied/);
  app=await createApplicationRuntime({configPath,Pool,fetcher:async(url,opts)=>{
   assert.equal(url,issuer+'/token');assert.equal(opts.redirect,'error');
   const c=codes.get(opts.body.get('code'));assert.ok(c);
   assert.equal(createHash('sha256').update(opts.body.get('code_verifier')).digest('base64url'),c.challenge);
   codes.delete(opts.body.get('code'));
   return new Response(JSON.stringify({id_token:token(c.nonce,{sub:subject})}),{headers:{'content-type':'application/json'}});
  }});
  await app.listen();
  const ca=await readFile(join(tls,'ca.pem'));
  function request(path,{method='GET',headers={},trusted=true}={}){
   return new Promise((resolve,reject)=>{
    const req=httpsRequest({host:'127.0.0.1',port:18443,servername:'localhost',path,method,ca:trusted?ca:undefined,headers:{host:'localhost:18443',...headers},agent:false},res=>{
     const chunks=[];const protocol=res.socket.getProtocol();res.on('data',b=>chunks.push(b));res.on('error',reject);res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body:Buffer.concat(chunks).toString('utf8'),protocol}));
    });req.on('error',reject);req.setTimeout(10000,()=>req.destroy(Error('fixture timeout')));req.end();
   });
  }
  const root=await request('/');assert.equal(root.status,200);assert.match(root.protocol,/TLSv1\.[23]/);assert.match(root.body,/Sign in/);assert.equal(root.headers['strict-transport-security'],'max-age=31536000');
  await assert.rejects(request('/',{trusted:false}));
  assert.equal((await request('/',{headers:{host:'evil.invalid'}})).status,400);
  assert.equal((await request('/auth/login',{method:'POST',headers:{origin:'https://evil.invalid'}})).status,403);
  const route='/api/v1/tenants/'+tenant+'/projects';
  assert.equal((await request(route)).status,401);
  const login=await request('/auth/login',{method:'POST',headers:{origin}});assert.equal(login.status,303);
  const u=new URL(login.headers.location),code=randomUUID();
  codes.set(code,{challenge:u.searchParams.get('code_challenge'),nonce:u.searchParams.get('nonce')});
  const flow=login.headers['set-cookie'][0].split(';')[0];
  const cb=await request('/auth/callback?'+new URLSearchParams({state:u.searchParams.get('state'),code,iss:issuer}),{headers:{cookie:flow,'sec-fetch-site':'cross-site'}});
  assert.equal(cb.status,303);const session=cb.headers['set-cookie'].find(x=>x.startsWith('__Host-vv_session=')).split(';')[0];
  const data=await request(route,{headers:{cookie:session}});assert.equal(data.status,200);assert.deepEqual(JSON.parse(data.body).items.map(x=>x.id),[project]);assert.equal(data.headers['strict-transport-security'],'max-age=31536000');
  assert.equal((await request(route.replace(tenant,'22222222-2222-4222-8222-222222222222'),{headers:{cookie:session}})).status,404);
  assert.equal((await request('/auth/logout-all',{method:'POST',headers:{origin,cookie:session}})).status,204);
  assert.equal((await request(route,{headers:{cookie:session}})).status,401);
  await app.stop();assert.equal(app.server.listening,false);
  console.log('application_https_browser_to_rls_gate_passed');
 }finally{await app?.stop();await admin.end();await rm(dir,{recursive:true,force:true});}
});
