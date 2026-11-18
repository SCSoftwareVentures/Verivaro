import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {verifyAccessToken} from '../../packages/security/oidc.mjs';
const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
const jwk={...publicKey.export({format:'jwk'}),kid:'synthetic-1',alg:'RS256',use:'sig'};
const now=100000,config={issuer:'https://issuer.invalid',audience:'verivaro-api',jwks:[jwk]};
const payload={iss:config.issuer,sub:'synthetic-user',aud:config.audience,iat:now-60,exp:now+60};
function token(p=payload,h={alg:'RS256',kid:jwk.kid,typ:'at+jwt'}){const enc=x=>Buffer.from(JSON.stringify(x)).toString('base64url');const m=enc(h)+'.'+enc(p);return m+'.'+sign('RSA-SHA256',Buffer.from(m),privateKey).toString('base64url');}
test('valid signed token returns only identity claims',()=>assert.deepEqual(verifyAccessToken(token({...payload,role:'admin',tenant:'forged'}),config,now),{issuer:config.issuer,subject:payload.sub,expiresAt:payload.exp}));
for(const [name,p] of Object.entries({expired:{exp:now},wrongIssuer:{iss:'other'},wrongAudience:{aud:'other'},futureNbf:{nbf:now+1},futureIat:{iat:now+31},excessiveLifetime:{exp:now+4000},missingSubject:{sub:null},floatExpiry:{exp:now+1.5},emptyAudience:{aud:[]}}))test(name,()=>assert.throws(()=>verifyAccessToken(token({...payload,...p}),config,now),/authentication denied/));
for(const h of [{alg:'none',kid:jwk.kid},{alg:'HS256',kid:jwk.kid},{alg:'RS256',kid:'unknown'},{alg:'RS256',kid:jwk.kid,jku:'https://attacker.invalid'},{alg:'RS256',kid:jwk.kid,crit:['x']}])test('reject header '+JSON.stringify(h),()=>assert.throws(()=>verifyAccessToken(token(payload,h),config,now),/authentication denied/));
test('duplicate key ID denied',()=>assert.throws(()=>verifyAccessToken(token(),{...config,jwks:[jwk,jwk]},now)));
test('signature tampering denied',()=>{const t=token().split('.');const b=Buffer.from(t[2],'base64url');b[0]^=1;t[2]=b.toString('base64url');assert.throws(()=>verifyAccessToken(t.join('.'),config,now));});
test('mixed audience types denied',()=>assert.throws(()=>verifyAccessToken(token({...payload,aud:[config.audience,3]}),config,now)));
test('malformed tokens and padded encoding denied',()=>{for(const t of ['a.b.c','a.b','',null,token()+'='])assert.throws(()=>verifyAccessToken(t,config,now));});
