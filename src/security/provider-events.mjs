import {createPublicKey,verify} from 'node:crypto';
import {digestSubject} from './provider-identity.mjs';
import {assertServiceLogin,validateServiceIdentity} from './service-login.mjs';
const role='verivaro_identity_events';
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
// Custom signed integration contract, not a generic OIDC logout token.
export function createProviderEventReceiver({issuer,audience,publicKey,db,now=()=>Math.floor(Date.now()/1000)}){
 const k=publicKey?.type==='public'?publicKey:createPublicKey(publicKey);
 if(k.asymmetricKeyType!=='ed25519'||typeof issuer!=='string'||typeof audience!=='string'||!issuer||!audience||typeof db?.apply!=='function')throw Error('invalid lifecycle receiver');
 return async function receive(body,signature){
  if(!Buffer.isBuffer(body)||body.length>4096||!Buffer.isBuffer(signature)||signature.length!==64||!verify(null,body,k,signature))throw Error('lifecycle event denied');
  const p=JSON.parse(body.toString('utf8'));
  if(!p||Object.keys(p).length!==7||!Buffer.from(JSON.stringify({version:p.version,iss:p.iss,aud:p.aud,event_id:p.event_id,sub:p.sub,kind:p.kind,iat:p.iat})).equals(body)||
   p.version!==1||p.iss!==issuer||p.aud!==audience||!uuid.test(p.event_id)||!['logout','disable'].includes(p.kind)||!Number.isSafeInteger(p.iat)||p.iat>now()||now()-p.iat>240)throw Error('lifecycle event denied');
  if(!await db.apply({issuer,id:p.event_id,subject:digestSubject(p.sub),kind:p.kind,at:p.iat}))throw Error('lifecycle event denied');
  return true;
 };
}
export function createProviderEventDatabase(pool,{expectedLogin}){
 validateServiceIdentity(role,expectedLogin);
 return Object.freeze({async apply(e){
  const c=await pool.connect();let tx=false,clean=false;
  try{
   await c.query('DISCARD ALL');await assertServiceLogin(c,role,expectedLogin);await c.query('SET ROLE '+role);
   await c.query('BEGIN ISOLATION LEVEL READ COMMITTED');tx=true;
   await c.query("SET LOCAL statement_timeout='5s'");await c.query("SET LOCAL lock_timeout='2s'");
   const r=await c.query('SELECT verivaro_identity.apply_provider_event($1,$2,$3,$4,$5) AS ok',[e.issuer,e.id,e.subject,e.kind,new Date(e.at*1000)]);
   await c.query('COMMIT');tx=false;await c.query('DISCARD ALL');clean=true;return r.rows[0]?.ok===true;
  }catch{if(tx)try{await c.query('ROLLBACK');}catch{}throw Error('lifecycle event operation failed');}
  finally{c.release(clean?undefined:new Error('discard event connection'));}
 }});
}
