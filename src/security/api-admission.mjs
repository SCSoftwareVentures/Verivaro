import {createHmac} from 'node:crypto';
import {isIP} from 'node:net';
import {assertServiceLogin,validateServiceIdentity} from './service-login.mjs';
const role='verivaro_api_admission',uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
export function apiPeer(raw){
 if(typeof raw!=='string'||raw.length>64)return 'unknown';
 if(isIP(raw)===4)return raw;
 if(isIP(raw)===6){
  const c=new URL('http://['+raw+']/').hostname,m=/^\[::ffff:([a-f0-9]+):([a-f0-9]+)\]$/.exec(c);
  if(m){const a=parseInt(m[1],16),b=parseInt(m[2],16);return [a>>8,a&255,b>>8,b&255].join('.');}
  // Aggregate IPv6 /64 to limit address rotation within one subnet.
  const [left,right='']=c.slice(1,-1).split('::'),l=left?left.split(':'):[],r=right?right.split(':'):[];
  const segments=c.includes('::')?[...l,...Array(8-l.length-r.length).fill('0'),...r]:l;
  return segments.slice(0,4).map(x=>parseInt(x,16).toString(16)).join(':')+'::/64';
 }
 return 'unknown';
}
export function createApiAdmission(pool,{key,expectedLogin}){
 validateServiceIdentity(role,expectedLogin);
 if(typeof pool?.connect!=='function'||!Buffer.isBuffer(key)||key.length!==32)throw Error('invalid API admission');
 const secret=Buffer.from(key);
 async function consume(kind,value){
  const d=createHmac('sha256',secret).update(kind+':'+value).digest(),c=await pool.connect();let tx=false,clean=false;
  try{
   await c.query('DISCARD ALL');await assertServiceLogin(c,role,expectedLogin);await c.query('SET ROLE '+role);
   await c.query('BEGIN ISOLATION LEVEL READ COMMITTED');tx=true;
   await c.query("SET LOCAL statement_timeout='3s'");await c.query("SET LOCAL lock_timeout='1s'");await c.query("SET LOCAL idle_in_transaction_session_timeout='5s'");
   const r=await c.query(kind==='peer'?'SELECT verivaro_admission.api_peer($1) AS ok':'SELECT verivaro_admission.api_actor($1) AS ok',[d]);
   if(r.rows.length!==1||typeof r.rows[0].ok!=='boolean')throw Error('invalid admission result');
   await c.query('COMMIT');tx=false;await c.query('DISCARD ALL');clean=true;return r.rows[0].ok;
  }catch{if(tx)try{await c.query('ROLLBACK');}catch{}throw Error('API admission unavailable');}
  finally{c.release(clean?undefined:new Error('discard API admission lease'));}
 }
 return Object.freeze({peer:raw=>consume('peer',apiPeer(raw)),actor(id){if(!uuid.test(id))throw Error('invalid actor');return consume('actor',id);}});
}
