import {generateKeyPairSync,sign,randomBytes} from 'node:crypto';
import {createProviderVerifier} from '../../src/security/provider-identity.mjs';
export const issuer='https://identity.example.invalid',audience='verivaro-client';
export const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
export const local=generateKeyPairSync('rsa',{modulusLength:2048});
export const provider=createProviderVerifier({issuer,audience,keys:[{kid:'fixture',publicKey}],requiredAcr:'fixture:mfa',requiredAmr:['mfa']});
export const nonce=()=>randomBytes(32).toString('base64url');
export const subject='provider-account-1';
const b64=o=>Buffer.from(JSON.stringify(o)).toString('base64url');
export function token(challenge,overrides={},header={},key=privateKey,raw){
 const n=Math.floor(Date.now()/1000);
 const body=b64({alg:'RS256',typ:'JWT',kid:'fixture',...header})+'.'+(raw?Buffer.from(raw).toString('base64url'):b64({iss:issuer,aud:audience,sub:subject,nonce:challenge,acr:'fixture:mfa',amr:['pwd','mfa'],iat:n,auth_time:n,exp:n+300,...overrides}));
 return body+'.'+sign('RSA-SHA256',Buffer.from(body),key).toString('base64url');
}
