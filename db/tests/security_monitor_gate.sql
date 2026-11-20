-- Independent synthetic gate; no production data.
DO $acl$
BEGIN
 IF has_schema_privilege('verivaro_runtime','verivaro_monitor','USAGE')
 OR has_schema_privilege('verivaro_admission_service','verivaro_monitor','USAGE')
 OR has_function_privilege('verivaro_monitor_worker','verivaro_monitor.close_incident(uuid)','EXECUTE')
 OR has_function_privilege('verivaro_incident_operator','verivaro_monitor.evaluate()','EXECUTE')
 OR has_table_privilege('verivaro_incident_operator','verivaro_private.security_incidents','UPDATE')
 THEN RAISE EXCEPTION 'monitor privilege boundary broken'; END IF;
END $acl$;
-- Reset synthetic fixtures from preceding admission test.
DELETE FROM verivaro_private.download_telemetry;
UPDATE verivaro_private.download_admission_config SET capacity_bytes=1048576,max_active=4,global_limit=120,peer_limit=20,bucket=-1,count=0;
DELETE FROM verivaro_private.download_peer_buckets;
SET SESSION AUTHORIZATION vv_ci_admission_a;
SET ROLE verivaro_admission_service;
DO $telemetry$
DECLARE l uuid;
BEGIN
 FOR j IN 1..10 LOOP
  l:=gen_random_uuid();
  IF NOT verivaro_admission.acquire(l,decode(repeat('aa',32),'hex'),4096) THEN RAISE EXCEPTION 'fixture admission failed'; END IF;
  IF NOT verivaro_admission.finish(l,'denied') OR verivaro_admission.finish(l,'denied') THEN RAISE EXCEPTION 'duplicate telemetry'; END IF;
 END LOOP;
 l:=gen_random_uuid();
 IF NOT verivaro_admission.acquire(l,decode(repeat('bb',32),'hex'),4096) OR NOT verivaro_admission.finish(l,'integrity') THEN RAISE EXCEPTION 'integrity fixture failed'; END IF;
END $telemetry$;
RESET ROLE;
RESET SESSION AUTHORIZATION;
INSERT INTO verivaro_private.download_leases(lease_id,login_name,reserved_bytes,acquired_at)
 VALUES('90000000-0000-4000-8000-000000000001','vv_ci_admission_a',1000000,clock_timestamp()-interval '3 minutes');
SET ROLE verivaro_monitor_worker;
DO $initial$
BEGIN
 IF verivaro_monitor.evaluate()<>4 OR verivaro_monitor.evaluate()<>0 THEN RAISE EXCEPTION 'incident detection/dedup failed'; END IF;
 IF NOT EXISTS(SELECT 1 FROM verivaro_monitor.health() WHERE open_incidents=4 AND critical_incidents=2 AND active_leases=1 AND evaluated_at IS NOT NULL)
 THEN RAISE EXCEPTION 'health mismatch'; END IF;
END $initial$;
RESET ROLE;
UPDATE verivaro_private.security_incidents SET opened_at=clock_timestamp()-interval '20 minutes';
SET ROLE verivaro_monitor_worker;
SELECT verivaro_monitor.evaluate();
SELECT verivaro_monitor.evaluate();
RESET ROLE;
DO $audit$
BEGIN
 IF (SELECT count(*) FROM verivaro_private.security_incident_events WHERE action='opened')<>4
 OR (SELECT count(*) FROM verivaro_private.security_incident_events WHERE action='escalated')<>4
 OR (SELECT sum(denied) FROM verivaro_private.download_telemetry)<>10
 THEN RAISE EXCEPTION 'incident history/telemetry mismatch'; END IF;
END $audit$;
SET ROLE verivaro_incident_operator;
DO $transition$
DECLARE i uuid;
BEGIN
 SELECT id INTO i FROM verivaro_monitor.list_open() WHERE kind='integrity_failure';
 IF verivaro_monitor.close_incident(i) THEN RAISE EXCEPTION 'unacknowledged incident closed'; END IF;
 IF NOT verivaro_monitor.acknowledge(i) OR verivaro_monitor.acknowledge(i) THEN RAISE EXCEPTION 'bad acknowledgement'; END IF;
 IF NOT verivaro_monitor.close_incident(i) OR verivaro_monitor.close_incident(i) THEN RAISE EXCEPTION 'bad close'; END IF;
END $transition$;
RESET ROLE;
SET ROLE verivaro_monitor_worker;
DO $reopen$
BEGIN
 IF verivaro_monitor.evaluate()<>1 THEN RAISE EXCEPTION 'persistent condition lost'; END IF;
END $reopen$;
RESET ROLE;
DO $immutable$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM verivaro_private.download_leases WHERE lease_id='90000000-0000-4000-8000-000000000001') THEN RAISE EXCEPTION 'monitor altered lease'; END IF;
 BEGIN
 DELETE FROM verivaro_private.security_incident_events;
 RAISE EXCEPTION 'audit deletion accepted';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $immutable$;
