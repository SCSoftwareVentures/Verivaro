import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {resolve} from 'node:path';
import {randomUUID,randomBytes,generateKeyPairSync,sign} from 'node:crypto';
import {issuer,audience,provider,local,token} from '../fixtures/provider-fixture.mjs';
import {digestSubject,digestOpaque} from '../../src/security/provider-identity.mjs';
import {createIdentityDatabase} from '../../src/security/identity-database.mjs';
import {createAuthenticationGateway} from '../../src/security/authentication-gateway.mjs';
import {verifyIdentityToken} from '../../src/security/verify-identity.mjs';
import {createProviderEventDatabase,createProviderEventReceiver} from '../../src/security/provider-events.mjs';
if(process.env.VV_LIVE_TEST!=='1'||process.env.PGDATABASE!=='verivaro_test'||!process.env.VV_TEST_DRIVER_DIR||!process.env.VV_IDENTITY_EVENTS_PASSWORD)throw Error('disposable CI only');
const {Pool}=createRequire(resolve(process.env.VV_TEST_DRIVER_DIR,'package.json'))('pg');
const cfg={host:process.env.PGHOST,port:Number(process.env.PGPORT),database:process.env.PGDATABASE,max:4,connectionTimeoutMillis:3000};
test('real database signed lifecycle delivery, global logout, replay fencing and authentication pressure',{timeout:30000},async()=>{
 const admin=new Pool({...cfg,user:process.env.PGUSER,password:process.env.PGPASSWORD}),ip=new Pool({...cfg,user:'vv_ci_identity',password:process.env.VV_IDENTITY_PASSWORD}),ep=new Pool({...cfg,user:'vv_ci_identity_events',password:process.env.VV_IDENTITY_EVENTS_PASSWORD});
 const db=createIdentityDatabase(ip,{expectedLogin:'vv_ci_identity'}),eventDb=createProviderEventDatabase(ep,{expectedLogin:'vv_ci_identity_events'});
 const kp=generateKeyPairSync('ed25519'),receive=createProviderEventReceiver({issuer,audience,publicKey:kp.publicKey,db:eventDb});
 const localVerifier={publicKey:local.publicKey,issuer:'urn:verivaro:local',audience:'api'};
 const gw=createAuthenticationGateway({db,provider,localIssuer:localVerifier.issuer,localAudience:localVerifier.audience,privateKey:local.privateKey});
 const tenant='11111111-1111-4111-8111-111111111111',actor=randomUUID(),subject='event-fixture-'+randomUUID();
 const event=(kind)=>Buffer.from(JSON.stringify({version:1,iss:issuer,aud:audience,event_id:randomUUID(),sub:subject,kind,iat:Math.floor(Date.now()/1000)}));
 async function session(){
  const c=await gw.begin(),r=await gw.exchange({idToken:token(c.nonce,{sub:subject}),binding:c.binding});
  const p=verifyIdentityToken(r.token,localVerifier),h=randomBytes(32).toString('base64url');
  assert.equal(await db.storeBrowserSession(digestOpaque(h),p.sessionId,randomBytes(64)),true);return h;
 }
 try{
  await admin.query("INSERT INTO verivaro.memberships(tenant_id,actor_id,role) VALUES($1,$2,'viewer')",[tenant,actor]);
  await admin.query('SELECT verivaro_identity.provision_binding($1,$2,$3,$4)',[issuer,digestSubject(subject),actor,randomUUID()]);
  const first=await session(),second=await session();
  const pending=await gw.begin(),oldToken=token(pending.nonce,{sub:subject});
  assert.equal(await db.logoutAllBrowser(digestOpaque(first)),true);
  assert.equal(await db.readBrowserSession(digestOpaque(first)),null);assert.equal(await db.readBrowserSession(digestOpaque(second)),null);
  await assert.rejects(gw.exchange({idToken:oldToken,binding:pending.binding}));
  // auth_time is whole seconds; wait past the local logout fence.
  await new Promise(r=>setTimeout(r,1100));
  const third=await session(),body=event('logout'),signature=sign(null,body,kp.privateKey);
  assert.deepEqual(await Promise.all([receive(body,signature),receive(body,signature)]),[true,true]);
  assert.equal(await db.readBrowserSession(digestOpaque(third)),null);
  await new Promise(r=>setTimeout(r,1100));
  const fourth=await session();await receive(body,signature);
  assert.ok(await db.readBrowserSession(digestOpaque(fourth)));
  const disable=event('disable');await receive(disable,sign(null,disable,kp.privateKey));
  assert.equal(await db.readBrowserSession(digestOpaque(fourth)),null);
  const late=await gw.begin();await assert.rejects(gw.exchange({idToken:token(late.nonce,{sub:subject}),binding:late.binding}));
  await assert.rejects(ep.query('SELECT * FROM verivaro_private.provider_bindings'),e=>e.code==='42501');
  const c=await ep.connect();try{await c.query('SET ROLE verivaro_identity_events');await assert.rejects(c.query('SELECT verivaro_identity.record_auth($1)',['denied']),e=>e.code==='42501');}finally{c.release(true);}
  for(let i=0;i<20;i++)assert.equal(await db.recordAuth('denied'),true);
  await admin.query('SELECT verivaro_monitor.evaluate()');
  assert.equal((await admin.query("SELECT count(*)::int AS n FROM verivaro_private.security_incidents WHERE kind='authentication_pressure' AND closed_at IS NULL")).rows[0].n,1);
  await admin.query('SELECT verivaro_monitor.evaluate()');
  assert.equal((await admin.query("SELECT count(*)::int AS n FROM verivaro_private.security_incidents WHERE kind='authentication_pressure' AND closed_at IS NULL")).rows[0].n,1);
 }finally{await admin.end();await ip.end();await ep.end();}
});
