import {validateServiceIdentity} from './service-login.mjs';
import {setTimeout as delay} from 'node:timers/promises';
// Explicit admin-operated action, never invoked automatically by a service.
// Requires the replacement to have been successfully checked by the caller.
export async function retireServiceCredential(client,{role,oldLogin,newLogin,confirm}){
 validateServiceIdentity(role,oldLogin);validateServiceIdentity(role,newLogin);
 if(oldLogin===newLogin||confirm!==oldLogin)throw Error('explicit retirement confirmation required');
 let transaction=false;
 try{
  await client.query('BEGIN');transaction=true;
  const r=await client.query("SELECT rolname::text AS name,rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolinherit AND pg_has_role(oid,$3,'MEMBER') AS safe FROM pg_catalog.pg_roles WHERE rolname::text IN ($1,$2)",[oldLogin,newLogin,role]);
  if(r.rows.length!==2||r.rows.some(x=>x.safe!==true))throw Error('credential retirement precondition failed');
  // Identifiers are strictly bounded ASCII, never caller-provided SQL.
  await client.query('ALTER ROLE "'+oldLogin+'" NOLOGIN PASSWORD NULL');
  await client.query('REVOKE "'+role+'" FROM "'+oldLogin+'"');
  await client.query('COMMIT');transaction=false;
 }catch{
  if(transaction)try{await client.query('ROLLBACK');}catch{}
  throw Error('credential retirement failed');
 }
 // NOLOGIN prevents new authentication; terminating existing backends is
 // separate because changing a password alone does not invalidate sessions.
 for(let i=0;i<30;i++){
  await client.query('SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity WHERE usename=$1 AND pid<>pg_backend_pid()',[oldLogin]);
  const r=await client.query('SELECT count(*)::int AS remaining FROM pg_catalog.pg_stat_activity WHERE usename=$1',[oldLogin]);
  if(r.rows[0]?.remaining===0)return {retired:true,remainingSessions:0};
  await delay(100);
 }
 throw Error('credential retired; session termination not confirmed');
}
