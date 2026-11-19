DO $gate$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM verivaro_private.restore_quarantine)
 OR EXISTS(SELECT 1 FROM verivaro_private.identity_sessions WHERE revoked_at IS NULL)
 OR EXISTS(SELECT 1 FROM verivaro_private.share_grants WHERE revoked_at IS NULL)
 OR EXISTS(SELECT 1 FROM verivaro.memberships m WHERE NOT EXISTS(SELECT 1 FROM verivaro_private.disabled_actors d WHERE d.actor_id=m.actor_id))
 OR EXISTS(SELECT 1 FROM verivaro_private.recovery_operators WHERE active)
 OR EXISTS(SELECT 1 FROM verivaro_private.alert_outbox WHERE state IN ('pending','sending'))
 OR EXISTS(SELECT 1 FROM verivaro_private.monitor_state WHERE evaluated_at IS NOT NULL)
 OR to_regprocedure('verivaro_private.ci_sign(uuid,uuid,integer,text,integer)') IS NOT NULL
 THEN RAISE EXCEPTION 'restore quarantine failure'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_class WHERE oid='verivaro.evidence'::regclass AND relrowsecurity AND relforcerowsecurity)
 OR has_table_privilege('verivaro_runtime','verivaro_private.context_key','SELECT')
 OR has_schema_privilege('verivaro_runtime','verivaro_private','USAGE')
 OR has_database_privilege('verivaro_runtime',current_database(),'CONNECT')
 THEN RAISE EXCEPTION 'restore privilege failure'; END IF;
 IF NOT EXISTS(SELECT 1 FROM verivaro.evidence) OR NOT EXISTS(SELECT 1 FROM verivaro_private.security_incident_events)
 THEN RAISE EXCEPTION 'restore data missing'; END IF;
END $gate$;
