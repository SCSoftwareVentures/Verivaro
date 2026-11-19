-- Full G1 post-migration regression; not a substitute for production audit.
DO $audit$
DECLARE r record; t record; p record; s record; role_count integer:=0;
BEGIN
 FOR r IN SELECT oid,rolname,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolreplication,rolinherit,rolcanlogin
 FROM pg_roles WHERE rolname LIKE 'verivaro_%' LOOP
  role_count:=role_count+1;
  IF r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolinherit OR r.rolcanlogin THEN
   RAISE EXCEPTION 'elevated service role: %',r.rolname;
  END IF;
  IF EXISTS(SELECT 1 FROM pg_roles g WHERE g.oid<>r.oid
   AND (g.rolsuper OR g.rolbypassrls OR g.rolcreaterole OR g.rolcreatedb OR g.rolreplication OR g.rolname LIKE 'pg_%' OR g.rolname LIKE 'verivaro_%')
   AND pg_has_role(r.oid,g.oid,'MEMBER')) THEN RAISE EXCEPTION 'unexpected indirect service privilege: %',r.rolname; END IF;
  FOR s IN SELECT oid,nspname FROM pg_namespace WHERE nspname LIKE 'verivaro%' LOOP
   IF has_schema_privilege(r.oid,s.oid,'CREATE') OR (s.nspname='verivaro_private' AND has_schema_privilege(r.oid,s.oid,'USAGE'))
   THEN RAISE EXCEPTION 'unsafe schema permission: % %',r.rolname,s.nspname; END IF;
  END LOOP;
  FOR t IN SELECT c.oid,c.relname,c.relowner,n.nspname,c.relrowsecurity,c.relforcerowsecurity FROM pg_class c
   JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname LIKE 'verivaro%' AND c.relkind IN ('r','p','v','m') LOOP
   IF pg_has_role(r.oid,t.relowner,'MEMBER') OR has_table_privilege(r.oid,t.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   OR (has_table_privilege(r.oid,t.oid,'INSERT') AND NOT(r.rolname='verivaro_runtime' AND t.nspname='verivaro' AND t.relname='evidence'))
   OR (has_table_privilege(r.oid,t.oid,'SELECT') AND NOT(r.rolname='verivaro_runtime' AND t.nspname='verivaro' AND t.relname IN ('tenants','projects','memberships','project_members','evidence')))
   THEN RAISE EXCEPTION 'unexpected table privilege: % %.%',r.rolname,t.nspname,t.relname; END IF;
   IF t.nspname='verivaro' AND t.relname IN ('tenants','projects','memberships','project_members','evidence')
   AND NOT(t.relrowsecurity AND t.relforcerowsecurity) THEN RAISE EXCEPTION 'missing forced RLS: %',t.relname; END IF;
  END LOOP;
 END LOOP;
 IF role_count<15 THEN RAISE EXCEPTION 'incomplete role coverage'; END IF;
 FOR p IN SELECT pr.oid,pr.proname,pr.proconfig,pr.proacl,pr.proowner,n.nspname FROM pg_proc pr JOIN pg_namespace n ON n.oid=pr.pronamespace
 WHERE n.nspname LIKE 'verivaro%' AND pr.prosecdef LOOP
  IF NOT EXISTS(SELECT 1 FROM unnest(p.proconfig) v WHERE v LIKE 'search_path=pg_catalog%')
  OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE')
  THEN RAISE EXCEPTION 'unsafe definer boundary: %.%',p.nspname,p.proname; END IF;
 END LOOP;
 -- Audit sensitive functions across every service role including future roles.
 FOR r IN SELECT oid,rolname FROM pg_roles WHERE rolname LIKE 'verivaro_%' LOOP
  FOR p IN SELECT pr.oid,pr.proname,n.nspname FROM pg_proc pr JOIN pg_namespace n ON n.oid=pr.pronamespace
   WHERE n.nspname IN ('verivaro_identity','verivaro_sharing','verivaro_admission','verivaro_monitor','verivaro_alerting','verivaro_recovery') LOOP
   IF has_function_privilege(r.oid,p.oid,'EXECUTE') AND NOT (
    (r.rolname='verivaro_runtime' AND p.nspname='verivaro_sharing' AND p.proname IN ('issue_share','issue_recipient_share','revoke_share')) OR
    (r.rolname='verivaro_identity_service' AND p.nspname='verivaro_identity' AND p.proname IN ('begin_login','redeem_login','revoke_session')) OR
    (r.rolname='verivaro_identity_provisioner' AND p.nspname='verivaro_identity' AND p.proname IN ('provision_binding','disable_binding')) OR
    (r.rolname='verivaro_recovery_service' AND p.nspname='verivaro_identity' AND p.proname IN ('disable_actor','request_recovery','recover_actor')) OR
    (r.rolname='verivaro_recovery_approver' AND p.nspname='verivaro_identity' AND p.proname='approve_recovery') OR
    (r.rolname='verivaro_release_service' AND p.nspname='verivaro_sharing' AND p.proname IN ('register_export','revoke_export')) OR
    (r.rolname='verivaro_share_gateway' AND p.nspname='verivaro_sharing' AND p.proname='resolve_share') OR
    (r.rolname='verivaro_recipient_gateway' AND p.nspname='verivaro_sharing' AND p.proname='resolve_recipient_share') OR
    (r.rolname='verivaro_admission_service' AND p.nspname='verivaro_admission' AND p.proname IN ('acquire','release','finish')) OR
    (r.rolname='verivaro_admission_reconciler' AND p.nspname='verivaro_admission' AND p.proname='reconcile') OR
    (r.rolname='verivaro_monitor_worker' AND p.nspname='verivaro_monitor' AND p.proname IN ('evaluate','health')) OR
    (r.rolname='verivaro_monitor_reader' AND p.nspname='verivaro_monitor' AND p.proname IN ('health','list_open','recent_alerts','alert_delivery_health')) OR
    (r.rolname='verivaro_incident_operator' AND p.nspname='verivaro_monitor' AND p.proname IN ('health','list_open','recent_alerts','alert_delivery_health','acknowledge','resolve_incident')) OR
    (r.rolname='verivaro_alert_sender' AND p.nspname='verivaro_alerting' AND p.proname IN ('claim','finish')) OR
    (r.rolname='verivaro_restore_reviewer' AND p.nspname='verivaro_recovery' AND p.proname IN ('attest_review','review_status'))
   ) THEN RAISE EXCEPTION 'cross-service execute privilege: % %.%',r.rolname,p.nspname,p.proname; END IF;
  END LOOP;
 END LOOP;
 RAISE NOTICE 'full G1 role and definer audit passed (% roles)',role_count;
END $audit$;
