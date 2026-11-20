import {assertServiceLogin,validateServiceIdentity} from './service-login.mjs';
// Dedicated private gateway pool. Never share this pool with runtime or release workers.
const QUERY='SELECT artifact_id, sha256 FROM verivaro_sharing.resolve_share($1::bytea)';
export function createShareResolver(pool, {recipientBound=false,expectedLogin}={}) {
 if(!pool || typeof pool.connect!=='function')throw new TypeError('invalid share pool');
 const role=recipientBound?'verivaro_recipient_gateway':'verivaro_share_gateway';
 validateServiceIdentity(role,expectedLogin);
 const query=recipientBound?'SELECT artifact_id, sha256 FROM verivaro_sharing.resolve_recipient_share($1::bytea,$2::uuid,$3::uuid,$4::bigint)':QUERY;
 return async function resolveShare(digest,principal) {
  if(!Buffer.isBuffer(digest)||digest.length!==32)return null;
  if(recipientBound&&(!principal||typeof principal.actorId!=='string'||typeof principal.sessionId!=='string'||!Number.isSafeInteger(principal.expiresAt)))return null;
  const values=recipientBound?[digest,principal.actorId,principal.sessionId,principal.expiresAt]:[digest];
  const client=await pool.connect();
  let transaction=false,clean=false;
  try{
   await client.query('DISCARD ALL');
   await assertServiceLogin(client,role,expectedLogin);
   await client.query('SET ROLE '+role);
   await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
   transaction=true;
   await client.query("SET LOCAL statement_timeout='5s'");
   await client.query("SET LOCAL lock_timeout='2s'");
   await client.query("SET LOCAL idle_in_transaction_session_timeout='10s'");
   const result=await client.query(query,values);
   if(result.rows.length>1)throw Error('invalid share resolution');
   await client.query('COMMIT');
   transaction=false;
   await client.query('DISCARD ALL');
   clean=true;
   return result.rows[0]??null;
  } catch {
   if(transaction)try{await client.query('ROLLBACK');}catch{}
   throw Error('share resolution failed');
  }finally{client.release(clean?undefined:new Error('discard gateway connection'));}
 };
}
