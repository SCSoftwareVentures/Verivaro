import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, createHmac, randomBytes } from 'node:crypto';
import { signDatabaseContext } from '../../src/security/sign-database-context.mjs';
const {publicKey,privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});
const now=1800000000, issuer='synthetic-issuer', audience='synthetic-api';
const actor='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', tenant='11111111-1111-4111-8111-111111111111';
const key=randomBytes(32);
const token=(claims={})=>{
 const head=Buffer.from(JSON.stringify({alg:'RS256',typ:'JWT'})).toString('base64url');
 const body=Buffer.from(JSON.stringify({iss:issuer,aud:audience,sub:actor,sid:'12345678-1234-4234-8234-123456789abc',iat:now-5,nbf:now-5,exp:now+120,...claims})).toString('base64url');
 const payload=head+'.'+body;
 return payload+'.'+sign('RSA-SHA256',Buffer.from(payload),privateKey).toString('base64url');
};
const options={verifier:{publicKey,issuer,audience},key,now};
const input={token:token(),tenantId:tenant,challenge:{pid:12345,xid:'9876543210'}};
test('signs canonical context using authenticated actor and transaction challenge',()=>{
 const payload=['v2',tenant,actor,12345,'9876543210',now+45,'12345678-1234-4234-8234-123456789abc'].join('|');
 assert.equal(signDatabaseContext({...input,actorId:'ignored'},options),payload+'|'+createHmac('sha256',key).update(payload).digest('hex'));
});
test('limits context expiry to verified identity expiry',()=>{
 assert.equal(signDatabaseContext({...input,token:token({exp:now+2})},options).split('|')[5],String(now+2));
});
test('refuses forged identity and malformed transaction challenges',()=>{
 assert.throws(()=>signDatabaseContext({...input,token:input.token+'x'},options));
 for(const challenge of [{pid:0,xid:'1'},{pid:1,xid:'01'},{pid:1,xid:'18446744073709551616'},{pid:1,xid:1}])
  assert.throws(()=>signDatabaseContext({...input,challenge},options),/challenge/);
 assert.throws(()=>signDatabaseContext(input,{...options,key:Buffer.alloc(16)}),/key/);
 assert.throws(()=>signDatabaseContext({...input,tenantId:'bad'},options),/tenant/);
});
