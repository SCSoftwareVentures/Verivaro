import {createPublicKey,verify,createHash} from 'node:crypto';
const opaque=x=>typeof x==='string'&&/^[A-Za-z0-9_-]{43}$/.test(x)&&Buffer.from(x,'base64url').toString('base64url')===x;
export const digestOpaque=x=>{if(!opaque(x))throw Error('invalid login challenge');return createHash('sha256').update(Buffer.from(x,'base64url')).digest();};
export const digestSubject=x=>{if(typeof x!=='string'||!/^[\x21-\x7e]{1,255}$/.test(x))throw Error('invalid provider subject');return createHash('sha256').update(x,'utf8').digest();};
export function decodeStrictJson(part){
 if(typeof part!=='string'||part.length>16384||!/^[A-Za-z0-9_-]+$/.test(part))throw Error('invalid token encoding');
 const raw=Buffer.from(part,'base64url'),json=raw.toString('utf8');
 if(raw.toString('base64url')!==part||!Buffer.from(json).equals(raw))throw Error('invalid token encoding');
 // JSON.parse alone accepts duplicate object member names. Reject ambiguous
 // keys (including escaped names), with bounded nesting and token size.
 let pos=0;
 const ws=()=>{while(pos<json.length&&/[ \t\r\n]/.test(json[pos]))pos++;};
 function str(){
  ws();const start=pos;if(json[pos++]!=='"')throw Error('invalid JSON');
  while(pos<json.length){const c=json[pos++];if(c==='\\'){pos++;continue;}if(c==='"')return JSON.parse(json.slice(start,pos));}
  throw Error('invalid JSON');
 }
 function value(depth){
  if(depth>12)throw Error('token nesting limit');ws();
  if(json[pos]==='{'){
   pos++;ws();const seen=new Set();if(json[pos]==='}'){pos++;return;}
   for(;;){const k=str();if(seen.has(k))throw Error('duplicate claim');seen.add(k);ws();if(json[pos++]!==':')throw Error('invalid JSON');value(depth+1);ws();const c=json[pos++];if(c==='}')return;if(c!==',')throw Error('invalid JSON');}
  }
  if(json[pos]==='['){
   pos++;ws();if(json[pos]===']'){pos++;return;}
   for(;;){value(depth+1);ws();const c=json[pos++];if(c===']')return;if(c!==',')throw Error('invalid JSON');}
  }
  if(json[pos]==='"'){str();return;}
  const m=/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(json.slice(pos));
  if(!m)throw Error('invalid JSON');pos+=m[0].length;
 }
 value(0);ws();if(pos!==json.length)throw Error('invalid JSON');
 const v=JSON.parse(json);if(!v||typeof v!=='object'||Array.isArray(v))throw Error('invalid token object');return v;
}
const httpsIssuer=x=>{try{const u=new URL(x);return typeof x==='string'&&x.length<=512&&u.protocol==='https:'&&!u.username&&!u.password&&!u.search&&!u.hash;}catch{return false;}};
export function createProviderVerifier({issuer,audience,keys,requiredAcr,requiredAmr=['mfa']}){
 if(!httpsIssuer(issuer)||typeof audience!=='string'||!/^[\x21-\x7e]{1,256}$/.test(audience)||!Array.isArray(keys)||keys.length<1||keys.length>8||
 typeof requiredAcr!=='string'||!requiredAcr||requiredAcr.length>256||!Array.isArray(requiredAmr)||requiredAmr.length<1||requiredAmr.length>8||requiredAmr.some(x=>typeof x!=='string'||!x||x.length>64))throw Error('invalid provider configuration');
 const pinned=new Map(),mfa=Object.freeze([...requiredAmr]);
 for(const {kid,publicKey} of keys){
  if(typeof kid!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(kid)||pinned.has(kid))throw Error('invalid provider key ID');
  const k=publicKey?.type==='public'?publicKey:createPublicKey(publicKey);
  if(k.asymmetricKeyType!=='rsa'||(k.asymmetricKeyDetails?.modulusLength??0)<2048)throw Error('invalid provider key');
  pinned.set(kid,k);
 }
 return Object.freeze({issuer,audience,verify(token,now=Math.floor(Date.now()/1000)){
  if(typeof token!=='string'||token.length>32768||!Number.isSafeInteger(now))throw Error('invalid provider token');
  const parts=token.split('.');if(parts.length!==3)throw Error('invalid provider token');
  const [h,p,s]=parts,header=decodeStrictJson(h);
  if(header.alg!=='RS256'||(header.typ!==undefined&&header.typ!=='JWT')||Object.keys(header).some(k=>!['alg','typ','kid'].includes(k))||!pinned.has(header.kid))throw Error('unsupported provider header');
  const signature=Buffer.from(s,'base64url');if(!s||signature.toString('base64url')!==s||!verify('RSA-SHA256',Buffer.from(h+'.'+p),pinned.get(header.kid),signature))throw Error('invalid provider signature');
  const c=decodeStrictJson(p);
  if(c.iss!==issuer||!(c.aud===audience||Array.isArray(c.aud)&&c.aud.length===1&&c.aud[0]===audience)||(c.azp!==undefined&&c.azp!==audience)||
  !opaque(c.nonce)||c.acr!==requiredAcr||!Array.isArray(c.amr)||c.amr.length>16||c.amr.some(x=>typeof x!=='string')||!mfa.every(x=>c.amr.includes(x))||
  ![c.iat,c.exp,c.auth_time].every(Number.isSafeInteger)||c.iat>now||c.exp<=now||c.exp<=c.iat||c.exp-c.iat>600||c.auth_time>c.iat||now-c.auth_time>240||
  (c.nbf!==undefined&&(!Number.isSafeInteger(c.nbf)||c.nbf>now)))throw Error('provider claims denied');
  return Object.freeze({issuer,audience,subjectDigest:digestSubject(c.sub),nonce:c.nonce,authenticatedAt:c.auth_time,expiresAt:c.exp});
 }});
}
