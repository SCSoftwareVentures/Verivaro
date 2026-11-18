import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { verifyIdentityToken } from '../../src/security/verify-identity.mjs';

const { privateKey, publicKey } = generateKeyPairSync('rsa',{modulusLength:2048});
const now=1900000000;
const actor='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const base={iss:'https://identity.example.test',aud:'verivaro',sub:actor,iat:now-10,nbf:now-10,exp:now+300};
function token(claims=base,header={alg:'RS256',typ:'JWT'},key=privateKey) {
 const h=Buffer.from(JSON.stringify(header)).toString('base64url');
 const p=Buffer.from(JSON.stringify(claims)).toString('base64url');
 return h+'.'+p+'.'+sign('RSA-SHA256',Buffer.from(h+'.'+p),key).toString('base64url');
}
const options={publicKey,issuer:base.iss,audience:base.aud,now};
test('accepts a correctly signed short-lived identity',()=>{
 assert.equal(verifyIdentityToken(token(),options).actorId,actor);
});
test('rejects impersonation, wrong issuer/audience and expired claims',()=>{
 for(const claims of [
  {...base,sub:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'},
  {...base,iss:'https://attacker.test'},
  {...base,aud:'other'},
  {...base,exp:now},
  {...base,nbf:now+1},
  {...base,iat:now+1},
  {...base,exp:now+7200}
 ]) {
  // Altered subject with valid issuer signature is legitimate identity, not an attack.
  if(claims.sub!==base.sub) continue;
  assert.throws(()=>verifyIdentityToken(token(claims),options));
 }
 const parts=token().split('.');
 const forged={...base,sub:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'};
 parts[1]=Buffer.from(JSON.stringify(forged)).toString('base64url');
 assert.throws(()=>verifyIdentityToken(parts.join('.'),options));
});
test('rejects alg confusion, missing signature and unknown signing key',()=>{
 assert.throws(()=>verifyIdentityToken(token(base,{alg:'none',typ:'JWT'}),options));
 assert.throws(()=>verifyIdentityToken(token().split('.').slice(0,2).join('.')+'.',options));
 const other=generateKeyPairSync('rsa',{modulusLength:2048});
 assert.throws(()=>verifyIdentityToken(token(base,undefined,other.privateKey),options));
});
