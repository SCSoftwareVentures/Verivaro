import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,sign,randomUUID} from 'node:crypto';
import {createRotatingProviderVerifier} from '../../src/security/provider-key-rotation.mjs';
import {createProviderEventReceiver} from '../../src/security/provider-events.mjs';
import {issuer,audience,publicKey,privateKey,nonce,token,subject} from '../fixtures/provider-fixture.mjs';
test('signed keyset rotation rejects rollback, wrong anchor, retired keys and expired snapshots',()=>{
 const authority=generateKeyPairSync('ed25519'),replacement=generateKeyPairSync('rsa',{modulusLength:2048});
 let now=1800000000;
 const fixedToken=(challenge,header={},key=privateKey)=>token(challenge,{iat:now,auth_time:now,exp:now+300},header,key);
 function snapshot(sequence,kid,key){
  const catalogue=Buffer.from(JSON.stringify({version:1,issuer,audience,sequence,issuedAt:now,expiresAt:now+600,keys:[{kid,pem:key.export({type:'spki',format:'pem'})}]}));
  return {catalogue,signature:sign(null,catalogue,authority.privateKey),checkpoint:{sequence,digest:createHash('sha256').update(catalogue).digest('hex')}};
 }
 const first=snapshot(1,'fixture',publicKey),second=snapshot(2,'next',replacement.publicKey);
 const p=createRotatingProviderVerifier({issuer,audience,requiredAcr:'fixture:mfa',authorityKey:authority.publicKey,...first,now:()=>now});
 assert.equal(p.verify(fixedToken(nonce())).issuer,issuer);
 assert.throws(()=>p.rotate(second.catalogue,second.signature,first.checkpoint));
 assert.throws(()=>p.rotate(second.catalogue,Buffer.alloc(64),second.checkpoint));
 p.rotate(second.catalogue,second.signature,second.checkpoint);
 assert.throws(()=>p.verify(fixedToken(nonce())));
 assert.equal(p.verify(fixedToken(nonce(),{kid:'next'},replacement.privateKey)).issuer,issuer);
 assert.throws(()=>p.rotate(first.catalogue,first.signature,first.checkpoint));
 now+=601;assert.throws(()=>p.verify(fixedToken(nonce())));
});
test('signed lifecycle messages reject tampering, stale events, wrong audience and ambiguous payloads',async()=>{
 const kp=generateKeyPairSync('ed25519'),calls=[],now=Math.floor(Date.now()/1000);
 const receive=createProviderEventReceiver({issuer,audience,publicKey:kp.publicKey,db:{apply:async x=>{calls.push(x);return true;}},now:()=>now});
 const event={version:1,iss:issuer,aud:audience,event_id:randomUUID(),sub:subject,kind:'logout',iat:now};
 const encode=x=>Buffer.from(JSON.stringify(x)),sig=x=>sign(null,x,kp.privateKey);
 const b=encode(event);assert.equal(await receive(b,sig(b)),true);
 for(const x of [{...event,iat:now-241},{...event,aud:'other'},{...event,kind:'enable'},{...event,sub:''}]){
  const b=encode(x);await assert.rejects(receive(b,sig(b)));
 }
 const duplicate=Buffer.from(b.toString().replace('"version":1','"version":1,"version":1'));
 await assert.rejects(receive(duplicate,sig(duplicate)));await assert.rejects(receive(b,Buffer.alloc(64)));
 assert.equal(calls.length,1);
});
