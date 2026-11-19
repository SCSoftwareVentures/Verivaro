import {assertServiceLogin,validateServiceIdentity} from './service-login.mjs';
import { signDatabaseContext } from './sign-database-context.mjs';

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const validId = value => typeof value==='string' && uuid.test(value);
const requireId = value => { if(!validId(value)) throw new TypeError('invalid identifier'); return value.toLowerCase(); };

// Only fixed repository-owned statements are exposed; no generic SQL or transaction callback.
const operations = Object.freeze({
 listProjects: { sql: 'SELECT id, name FROM verivaro.projects WHERE tenant_id=$1 ORDER BY id LIMIT 200', values: () => [] },
 getProject: { sql: 'SELECT id, name FROM verivaro.projects WHERE tenant_id=$1 AND id=$2', values: args => [requireId(args.projectId)] },
 listEvidence: { sql: 'SELECT id, project_id, sha256, created_by, created_at FROM verivaro.evidence WHERE tenant_id=$1 AND project_id=$2 ORDER BY id LIMIT 200', values: args => [requireId(args.projectId)] }
});

/**
 * Driver contract: pg-compatible pool.connect(), client.query(text, values), release(error?).
 * Dedicated nonprivileged login, exclusive lease, no named prepared statements.
 * No caller-supplied SQL; this adapter is a candidate, not yet a live driver integration.
 */
export function createScopedDatabase(pool, { verifier, key, expectedLogin }) {
 if(!pool || typeof pool.connect!=='function' || !Buffer.isBuffer(key) || key.length!==32 || !verifier)
  throw new TypeError('invalid database configuration');
 validateServiceIdentity('verivaro_runtime',expectedLogin);
 const signingKey=Buffer.from(key);
 const tokenVerifier=Object.freeze({...verifier});
 return Object.freeze({
  async execute({token,tenantId,operation,args={}}) {
   if(typeof operation!=='string' || !Object.hasOwn(operations,operation)) throw new TypeError('unknown database operation');
   const tenant=requireId(tenantId);
   const spec=operations[operation];
   const values=[tenant,...spec.values(args)];
   const client=await pool.connect();
   let transaction=false, clean=false;
   try {
    // Clear session-level settings and cached database state before every lease.
    await client.query('DISCARD ALL');
    // Fail closed for a login endowed with cluster-level administration privileges.
    await assertServiceLogin(client,'verivaro_runtime',expectedLogin);
    await client.query('SET ROLE verivaro_runtime');
    await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
    transaction=true;
    await client.query("SET LOCAL statement_timeout = '10s'");
    await client.query("SET LOCAL lock_timeout = '3s'");
    await client.query("SET LOCAL idle_in_transaction_session_timeout = '15s'");
    const challenge=await client.query('SELECT pg_backend_pid() AS pid, pg_current_xact_id()::text AS xid');
    if(challenge.rows.length!==1) throw new Error('invalid database challenge');
    const context=signDatabaseContext({token,tenantId:tenant,challenge:challenge.rows[0]},{verifier:tokenVerifier,key:signingKey});
    // never interpolate or log token/context/key
    await client.query("SELECT set_config('verivaro.signed_context', $1, true)",[context]);
    const authorized=await client.query('SELECT verivaro.authorized($1::uuid) AS allowed',[tenant]);
    if(authorized.rows.length!==1 || authorized.rows[0].allowed!==true) throw new Error('access denied');
    const result=await client.query(spec.sql,values);
    const rows=result.rows;
    await client.query('COMMIT');
    transaction=false;
    await client.query('DISCARD ALL');
    clean=true;
    return rows;
   } catch {
    if(transaction) {
     try { await client.query('ROLLBACK'); } catch { /* discard the connection below */ }
    }
    // Never return an uncertain or errored connection to the pool.
    throw new Error('scoped database operation failed');
   } finally {
    client.release(clean ? undefined : new Error('discard unsafe database lease'));
   }
  }
 });
}
