import {createHmac,randomUUID} from 'node:crypto';
import {isIP} from 'node:net';
import {encryptedReservation} from './spool-budget.mjs';
function canonicalPeer(value){
 if(typeof value!=='string'||value.length>64)return 'unknown';
 if(isIP(value)===4)return value;
 if(isIP(value)===6){
  const canonical=new URL('http://['+value+']/').hostname;
  // Normalize IPv4 mapped addresses to the equivalent IPv4 peer.
  const mapped=/^\[::ffff:([0-9a-f]+):([0-9a-f]+)\]$/.exec(canonical);
  if(mapped){const hi=parseInt(mapped[1],16),lo=parseInt(mapped[2],16);return [hi>>8,hi&255,lo>>8,lo&255].join('.');}
  return canonical;
 }
 return 'unknown';
}
// Dedicated low-privilege pool; all replicas share the admission database and
// peer HMAC key. No bearer token or raw remote IP is stored in the database.
export function createDistributedAdmission(pool,{peerKey}){
 if(!pool||typeof pool.connect!=='function'||!Buffer.isBuffer(peerKey)||peerKey.length!==32)throw Error('invalid admission configuration');
 const key=Buffer.from(peerKey);
 async function run(sql,values){
  const client=await pool.connect();let tx=false,clean=false;
  try{
   await client.query('DISCARD ALL');
   const login=await client.query("SELECT rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication AS privileged FROM pg_catalog.pg_roles WHERE rolname=session_user");
   if(login.rows.length!==1||login.rows[0].privileged!==false)throw Error('unsafe admission login');
   await client.query('SET ROLE verivaro_admission_service');
   await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');tx=true;
   await client.query("SET LOCAL statement_timeout='3s'");
   await client.query("SET LOCAL lock_timeout='1s'");
   await client.query("SET LOCAL idle_in_transaction_session_timeout='5s'");
   const result=await client.query(sql,values);
   if(result.rows.length!==1||typeof result.rows[0].ok!=='boolean')throw Error('invalid admission result');
   await client.query('COMMIT');tx=false;
   await client.query('DISCARD ALL');clean=true;
   return result.rows[0].ok;
  }catch{
   if(tx)try{await client.query('ROLLBACK');}catch{}
   throw Error('admission operation failed');
  }finally{client.release(clean?undefined:new Error('discard admission connection'));}
 }
 return Object.freeze({
  async acquire(peer,bytes,signal){
   signal.throwIfAborted();
   const lease=randomUUID(),digest=createHmac('sha256',key).update(canonicalPeer(peer)).digest();
   const need=encryptedReservation(bytes);
   const accepted=await run('SELECT verivaro_admission.acquire($1::uuid,$2::bytea,$3::bigint) AS ok',[lease,digest,need]);
   if(!accepted)return null;
   let released=false;
   const release=async()=>{
    if(released)return;
    await run('SELECT verivaro_admission.release($1::uuid) AS ok',[lease]);released=true;
   };
   if(signal.aborted){await release();signal.throwIfAborted();}
   return Object.freeze({release});
  }
 });
}
