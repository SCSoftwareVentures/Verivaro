import {createPublicKey,verify} from 'node:crypto';
const denied=()=>new Error('authentication denied');
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
function decode(s){if(typeof s!=='string'||! /^[A-Za-z0-9_-]+$/.test(s))throw denied();const b=Buffer.from(s,'base64url');if(b.toString('base64url')!==s)throw denied();return b;}
function json(s){const val=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(decode(s)));if(!object(val))throw denied();return val;}
/** Only locally supplied, trusted issuer configuration and pre-fetched public JWKS.
 * This is not a network JWKS client, revocation provider, HTTP middleware or login flow.
 * No issuer, audience, key URL or permissions are taken from unverified claims.
 */
export function verifyAccessToken(token,config,now=Math.floor(Date.now()/1000)){
 try{
 if(typeof token!=='string'||token.length>16384||!object(config)||typeof config.issuer!=='string'||!config.issuer||typeof config.audience!=='string'||!config.audience||!Array.isArray(config.jwks)||config.jwks.length>100||!Number.isSafeInteger(now))throw denied();
 const parts=token.split('.');if(parts.length!==3)throw denied();
 const h=json(parts[0]);const p=json(parts[1]);
 // Refuse embedded keys, critical/unsupported headers and remote key discovery.
 if(h.alg!=='RS256'||typeof h.kid!=='string'||h.kid.length<1||h.kid.length>128||Object.keys(h).some(k=>!['alg','kid','typ'].includes(k))||(h.typ!==undefined&&!['JWT','at+jwt'].includes(h.typ)))throw denied();
 const matches=config.jwks.filter(k=>object(k)&&k.kid===h.kid);
 if(matches.length!==1)throw denied();
 const k=matches[0];if(k.kty!=='RSA'||(k.alg!==undefined&&k.alg!=='RS256')||(k.use!==undefined&&k.use!=='sig')||(k.key_ops!==undefined&&(!Array.isArray(k.key_ops)||!k.key_ops.includes('verify')))||Object.keys(k).some(x=>['d','p','q','dp','dq','qi','oth'].includes(x)))throw denied();
 const key=createPublicKey({key:k,format:'jwk'});if(key.asymmetricKeyType!=='rsa'||(key.asymmetricKeyDetails?.modulusLength??0)<2048||(key.asymmetricKeyDetails?.modulusLength??0)>4096)throw denied();
 if(!verify('RSA-SHA256',Buffer.from(parts[0]+'.'+parts[1]),key,decode(parts[2])))throw denied();
 if(p.iss!==config.issuer||typeof p.sub!=='string'||!p.sub.trim()||p.sub.length>512)throw denied();
 const audiences=typeof p.aud==='string'?[p.aud]:p.aud;
 if(!Array.isArray(audiences)||!audiences.length||audiences.some(x=>typeof x!=='string')||!audiences.includes(config.audience))throw denied();
 // Require positive bounded issuance interval; no clock-skew allowance at expiry.
 if(!Number.isSafeInteger(p.exp)||!Number.isSafeInteger(p.iat)||p.exp<=now||p.iat>now+30||p.exp<=p.iat||p.exp-p.iat>3600||(p.nbf!==undefined&&(!Number.isSafeInteger(p.nbf)||p.nbf>now||p.nbf>=p.exp)))throw denied();
 return Object.freeze({issuer:p.iss,subject:p.sub,expiresAt:p.exp});
 }catch{throw denied();}
}
