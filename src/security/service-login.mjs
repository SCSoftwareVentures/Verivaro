// Shared PostgreSQL connection-boundary validation. This is a deployment
// misconfiguration guard, not a substitute for PostgreSQL ACL enforcement.
const roles=new Set(['verivaro_runtime','verivaro_share_gateway','verivaro_recipient_gateway','verivaro_admission_service','verivaro_monitor_worker','verivaro_monitor_reader','verivaro_alert_sender','verivaro_identity_service','verivaro_identity_events','verivaro_api_admission']);
const name=/^[a-z][a-z0-9_]{0,62}$/;
export function validateServiceIdentity(role,expectedLogin){
 if(!roles.has(role)||(typeof expectedLogin!=='string'||!name.test(expectedLogin)||expectedLogin===role||expectedLogin.startsWith('pg_')||expectedLogin.startsWith('verivaro_')))throw Error('invalid service identity configuration');
}
const CHECK=String.raw`SELECT
 l.rolname::text AS login_name,
 (
 l.rolsuper OR l.rolbypassrls OR l.rolcreaterole OR l.rolcreatedb OR l.rolreplication OR l.rolinherit OR NOT l.rolcanlogin
 OR (l.rolvaliduntil IS NOT NULL AND l.rolvaliduntil<=clock_timestamp())
 OR g.rolsuper OR g.rolbypassrls OR g.rolcreaterole OR g.rolcreatedb OR g.rolreplication OR g.rolinherit
 OR NOT pg_has_role(l.oid,g.oid,'MEMBER')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_roles x WHERE x.oid NOT IN (l.oid,g.oid) AND pg_has_role(l.oid,x.oid,'MEMBER'))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_roles x WHERE x.oid<>g.oid AND pg_has_role(g.oid,x.oid,'MEMBER'))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member=l.oid AND m.admin_option)
 OR has_database_privilege(l.oid,current_database(),'CREATE')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND has_schema_privilege(l.oid,n.oid,'CREATE'))
 OR (l.oid<>g.oid AND (
  g.rolcanlogin OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member=l.oid AND m.roleid=g.oid AND NOT m.admin_option)
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname LIKE 'verivaro%' AND has_schema_privilege(l.oid,n.oid,'USAGE'))
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_class t JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace
    WHERE n.nspname LIKE 'verivaro%' AND t.relkind IN ('r','p','v','m','f')
    AND (t.relowner=l.oid OR has_table_privilege(l.oid,t.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
    OR has_any_column_privilege(l.oid,t.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
    CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
    WHERE n.nspname LIKE 'verivaro%' AND (p.proowner=l.oid OR a.grantee=l.oid))
 ))
 OR (l.rolname::text<>$2 OR l.oid=g.oid OR g.rolcanlogin)
 ) AS privileged
 FROM pg_catalog.pg_roles l CROSS JOIN pg_catalog.pg_roles g
 WHERE l.rolname=session_user AND g.rolname::text=$1`;
export async function assertServiceLogin(client,role,expectedLogin){
 validateServiceIdentity(role,expectedLogin);
 // Discarded session may still have unsafe role/database default search_path.
 await client.query('SET search_path TO pg_catalog');
 const r=await client.query(CHECK,[role,expectedLogin]);
 if(r.rows.length!==1||r.rows[0].privileged!==false||r.rows[0].login_name!==expectedLogin)throw Error('unsafe service login');
}
