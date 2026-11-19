// Dedicated private gateway pool. Never share this pool with runtime or release workers.
const QUERY='SELECT artifact_id, sha256 FROM verivaro_sharing.resolve_share($1::bytea)';
export function createShareResolver(pool) {
 if(!pool || typeof pool.connect!=='function')throw new TypeError('invalid share pool');
 return async function resolveShare(digest) {
  if(!Buffer.isBuffer(digest)||digest.length!==32)return null;
  const client=await pool.connect();
  let transaction=false,clean=false;
  try{
   await client.query('DISCARD ALL');
   const login=await client.query("SELECT rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication AS privileged FROM pg_catalog.pg_roles WHERE rolname=session_user");
   if(login.rows.length!==1||login.rows[0].privileged!==false)throw Error('unsafe gateway login');
   await client.query('SET ROLE verivaro_share_gateway');
   await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
   transaction=true;
   await client.query("SET LOCAL statement_timeout='5s'");
   await client.query("SET LOCAL lock_timeout='2s'");
   await client.query("SET LOCAL idle_in_transaction_session_timeout='10s'");
   const result=await client.query(QUERY,[digest]);
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
