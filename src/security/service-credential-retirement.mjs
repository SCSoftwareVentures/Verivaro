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
  // Both principals must be *exactly* the dedicated non-privileged service
  // logins, never an arbitrary group member or elevated replacement. Do not
  // trust inherited or transitive membership as a retirement precondition.
  const r=await client.query(String.raw`SELECT l.rolname::text AS name,
    l.rolcanlogin AND NOT l.rolsuper AND NOT l.rolbypassrls
    AND NOT l.rolcreaterole AND NOT l.rolcreatedb AND NOT l.rolreplication
    AND NOT l.rolinherit AND NOT g.rolcanlogin AND NOT g.rolsuper
    AND NOT g.rolbypassrls AND NOT g.rolcreaterole AND NOT g.rolcreatedb
    AND NOT g.rolreplication AND NOT g.rolinherit
    AND (l.rolname::text<>$2 OR l.rolvaliduntil IS NULL OR l.rolvaliduntil>clock_timestamp())
    AND NOT pg_catalog.has_database_privilege(l.oid,current_database(),'CREATE')
    AND NOT EXISTS(
      SELECT 1 FROM pg_catalog.pg_namespace n
      WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema'
        AND pg_catalog.has_schema_privilege(l.oid,n.oid,'CREATE'))
    AND (SELECT count(*) FROM pg_catalog.pg_auth_members m WHERE m.member=l.oid)=1
    AND EXISTS(
      SELECT 1 FROM pg_catalog.pg_auth_members m
      WHERE m.member=l.oid AND m.roleid=g.oid
        AND m.inherit_option=false AND m.set_option=true
        AND m.admin_option=false)
    AND NOT EXISTS(
      SELECT 1 FROM pg_catalog.pg_roles x
      WHERE x.oid NOT IN (l.oid,g.oid)
        AND pg_catalog.pg_has_role(l.oid,x.oid,'MEMBER'))
    AND NOT EXISTS(
      SELECT 1 FROM pg_catalog.pg_roles x
      WHERE x.oid<>g.oid AND pg_catalog.pg_has_role(g.oid,x.oid,'MEMBER'))
    AS safe
   FROM pg_catalog.pg_roles l CROSS JOIN pg_catalog.pg_roles g
   WHERE l.rolname::text IN ($1,$2) AND g.rolname::text=$3`,[oldLogin,newLogin,role]);
  if(r.rows.length!==2||new Set(r.rows.map(x=>x.name)).size!==2||
     !r.rows.some(x=>x.name===oldLogin)||!r.rows.some(x=>x.name===newLogin)||
     r.rows.some(x=>x.safe!==true))
    throw Error('credential retirement precondition failed');
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
