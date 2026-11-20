import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,generateKeyPairSync} from 'node:crypto';
import {provider,issuer,audience,local,nonce,subject,token} from '../fixtures/provider-fixture.mjs';
import {createAuthenticationGateway} from '../../src/security/authentication-gateway.mjs';
import {verifyIdentityToken} from '../../src/security/verify-identity.mjs';
test('provider verifier rejects spoofed issuer, audience, MFA, stale proof, key and ambiguous claims',()=>{
 const n=nonce(),now=Math.floor(Date.now()/1000),good=token(n);
 assert.equal(provider.verify(good).nonce,n);
 for(const bad of [
  token(n,{iss:'https://wrong.invalid'}),token(n,{aud:'wrong'}),token(n,{aud:[audience,'other']}),token(n,{azp:'wrong'}),
  token(n,{amr:['pwd']}),token(n,{acr:'none'}),token(n,{auth_time:now-241}),token(n,{iat:now+5}),token(n,{exp:now-1}),
  token(n,{nonce:'invalid'}),token(n,{sub:''}),token(n,{}, {kid:'unknown'}),token(n,{}, {jku:'https://wrong.invalid/key'}),
  token(n,{}, {},generateKeyPairSync('rsa',{modulusLength:2048}).privateKey),
  token(n,{}, {},undefined,'{"sub":"first","\\u0073ub":"second"}')
 ])assert.throws(()=>provider.verify(bad));
});
test('local session minted only after database redemption, mapped actor never upstream subject',async()=>{
 const actor=randomUUID(),calls=[];
 const db={begin:async()=>true,redeem:async x=>{calls.push(x);return actor;},revoke:async(a,s)=>{calls.push({a,s});return true;}};
 const gateway=createAuthenticationGateway({db,provider,localIssuer:'urn:verivaro:local',localAudience:'api',privateKey:local.privateKey});
 const c=await gateway.begin(),result=await gateway.exchange({idToken:token(c.nonce),binding:c.binding});
 const p=verifyIdentityToken(result.token,{publicKey:local.publicKey,issuer:'urn:verivaro:local',audience:'api'});
 assert.equal(p.actorId,actor);assert.notEqual(p.actorId,subject);assert.equal(p.sessionId,calls[0].sessionId);
 assert.equal(await gateway.logout(result.token),true);
 assert.deepEqual(calls[1],{a:actor,s:p.sessionId});
 await assert.rejects(gateway.exchange({idToken:token(c.nonce,{amr:['pwd']}),binding:c.binding}),/authentication denied/);
 assert.equal(calls.length,2);
});
