-- G1: bounded aggregate telemetry and restricted incident transitions.
BEGIN;
CREATE ROLE verivaro_monitor_worker NOLOGIN NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE ROLE verivaro_incident_operator NOLOGIN NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE SCHEMA verivaro_monitor;
REVOKE ALL ON SCHEMA verivaro_monitor FROM PUBLIC;
GRANT USAGE ON SCHEMA verivaro_monitor TO verivaro_monitor_worker,verivaro_incident_operator;
-- One row per minute slot; maximum 60 rows, no address, token, file or actor.
CREATE TABLE verivaro_private.download_telemetry(
 slot integer PRIMARY KEY CHECK(slot BETWEEN 0 AND 59), bucket bigint NOT NULL,
 denied bigint NOT NULL DEFAULT 0, failed bigint NOT NULL DEFAULT 0,
 integrity bigint NOT NULL DEFAULT 0, completed bigint NOT NULL DEFAULT 0,
 CHECK(denied>=0 AND failed>=0 AND integrity>=0 AND completed>=0)
);
CREATE TABLE verivaro_private.monitor_state(
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 evaluated_at timestamptz
);
INSERT INTO verivaro_private.monitor_state(singleton) VALUES(true);
CREATE TABLE verivaro_private.security_incidents(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 kind text NOT NULL CHECK(kind IN ('access_denials','integrity_failure','resource_pressure','stranded_reservation','delivery_failures')),
 severity text NOT NULL CHECK(severity IN ('warning','critical')),
 opened_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 last_seen timestamptz NOT NULL DEFAULT clock_timestamp(),
 acknowledged_at timestamptz, escalated_at timestamptz, closed_at timestamptz
);
CREATE UNIQUE INDEX incident_one_open ON verivaro_private.security_incidents(kind) WHERE closed_at IS NULL;
CREATE TABLE verivaro_private.security_incident_events(
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 incident_id uuid NOT NULL REFERENCES verivaro_private.security_incidents(id),
 action text NOT NULL CHECK(action IN ('opened','acknowledged','escalated','closed')),
 operator_login name NOT NULL DEFAULT session_user,
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER incident_events_immutable BEFORE UPDATE OR DELETE OR TRUNCATE
 ON verivaro_private.security_incident_events FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
REVOKE ALL ON verivaro_private.download_telemetry,verivaro_private.monitor_state,
 verivaro_private.security_incidents,verivaro_private.security_incident_events FROM PUBLIC;

-- Finalize only the calling replica's lease. Atomic with aggregate telemetry;
-- duplicate release cannot increment telemetry. No unbounded event per request.
CREATE FUNCTION verivaro_admission.finish(l uuid,outcome text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $finish$
DECLARE b bigint; s integer;
BEGIN
 IF outcome IS NULL OR outcome NOT IN ('unknown','denied','failed','integrity','completed') THEN RETURN false; END IF;
 PERFORM 1 FROM verivaro_private.download_admission_config WHERE singleton FOR UPDATE;
 DELETE FROM verivaro_private.download_leases WHERE lease_id=l AND login_name=session_user;
 IF NOT FOUND THEN RETURN false; END IF;
 b:=floor(extract(epoch FROM clock_timestamp())/60)::bigint;
 s:=mod(b,60)::integer;
 INSERT INTO verivaro_private.download_telemetry(slot,bucket,denied,failed,integrity,completed)
 VALUES(s,b,(outcome='denied')::int,(outcome='failed')::int,(outcome='integrity')::int,(outcome='completed')::int)
 ON CONFLICT(slot) DO UPDATE SET
 bucket=EXCLUDED.bucket,
 denied=CASE WHEN download_telemetry.bucket=EXCLUDED.bucket THEN download_telemetry.denied ELSE 0 END+EXCLUDED.denied,
 failed=CASE WHEN download_telemetry.bucket=EXCLUDED.bucket THEN download_telemetry.failed ELSE 0 END+EXCLUDED.failed,
 integrity=CASE WHEN download_telemetry.bucket=EXCLUDED.bucket THEN download_telemetry.integrity ELSE 0 END+EXCLUDED.integrity,
 completed=CASE WHEN download_telemetry.bucket=EXCLUDED.bucket THEN download_telemetry.completed ELSE 0 END+EXCLUDED.completed
 WHERE download_telemetry.bucket<=EXCLUDED.bucket;
 RETURN true;
END $finish$;
REVOKE ALL ON FUNCTION verivaro_admission.finish(uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_admission.finish(uuid,text) TO verivaro_admission_service;
CREATE OR REPLACE FUNCTION verivaro_admission.release(l uuid) RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $release$
 SELECT verivaro_admission.finish(l,'unknown')
$release$;

-- Serialized evaluator; five-minute rolling aggregate and instantaneous capacity.
-- Signals are indicators, not proof of compromise; no automatic account disable.
CREATE FUNCTION verivaro_monitor.evaluate() RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $eval$
DECLARE n timestamptz; b bigint; cfg verivaro_private.download_admission_config%ROWTYPE;
 denied bigint; failed bigint; integrity bigint; used bigint; active bigint; stale bigint;
 signal record; existing uuid; opened integer:=0;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'monitor isolation denied' USING ERRCODE='42501'; END IF;
 PERFORM 1 FROM verivaro_private.monitor_state WHERE singleton FOR UPDATE;
 n:=clock_timestamp(); b:=floor(extract(epoch FROM n)/60)::bigint;
 SELECT * INTO cfg FROM verivaro_private.download_admission_config WHERE singleton;
 SELECT COALESCE(sum(t.denied),0),COALESCE(sum(t.failed),0),COALESCE(sum(t.integrity),0)
 INTO denied,failed,integrity FROM verivaro_private.download_telemetry t WHERE t.bucket BETWEEN b-4 AND b;
 SELECT COALESCE(sum(reserved_bytes),0),count(*),count(*) FILTER(WHERE acquired_at<n-interval '2 minutes')
 INTO used,active,stale FROM verivaro_private.download_leases;
 FOR signal IN SELECT * FROM (VALUES
 ('access_denials','warning',denied>=10),
 ('delivery_failures','warning',failed>=10),
 ('integrity_failure','critical',integrity>=1),
 ('stranded_reservation','critical',stale>=1),
 ('resource_pressure','warning',used>=cfg.capacity_bytes*0.8 OR active>=cfg.max_active*0.8 OR (cfg.bucket=b AND cfg.count>=cfg.global_limit*0.8))
 ) AS s(kind,severity,detected) LOOP
  IF signal.detected THEN
   SELECT id INTO existing FROM verivaro_private.security_incidents WHERE kind=signal.kind AND closed_at IS NULL FOR UPDATE;
   IF NOT FOUND THEN
    INSERT INTO verivaro_private.security_incidents(kind,severity,opened_at,last_seen)
    VALUES(signal.kind,signal.severity,n,n) RETURNING id INTO existing;
    INSERT INTO verivaro_private.security_incident_events(incident_id,action) VALUES(existing,'opened');
    opened:=opened+1;
   ELSE
    UPDATE verivaro_private.security_incidents SET last_seen=GREATEST(last_seen,n) WHERE id=existing;
   END IF;
  END IF;
 END LOOP;
 -- Escalate unresolved incidents once; acknowledgment does not constitute resolution.
 FOR existing IN UPDATE verivaro_private.security_incidents SET escalated_at=n
 WHERE closed_at IS NULL AND escalated_at IS NULL
 AND opened_at<=n-CASE WHEN severity='critical' THEN interval '5 minutes' ELSE interval '15 minutes' END
 RETURNING id LOOP
  INSERT INTO verivaro_private.security_incident_events(incident_id,action) VALUES(existing,'escalated');
 END LOOP;
 UPDATE verivaro_private.monitor_state SET evaluated_at=n WHERE singleton;
 RETURN opened;
END $eval$;
CREATE FUNCTION verivaro_monitor.acknowledge(i uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $ack$
BEGIN
 UPDATE verivaro_private.security_incidents SET acknowledged_at=clock_timestamp()
 WHERE id=i AND closed_at IS NULL AND acknowledged_at IS NULL;
 IF NOT FOUND THEN RETURN false; END IF;
 INSERT INTO verivaro_private.security_incident_events(incident_id,action) VALUES(i,'acknowledged');
 RETURN true;
END $ack$;
CREATE FUNCTION verivaro_monitor.close_incident(i uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $close$
BEGIN
 -- Human resolution; never mutates admission leases or account permissions.
 UPDATE verivaro_private.security_incidents SET closed_at=clock_timestamp()
 WHERE id=i AND closed_at IS NULL AND acknowledged_at IS NOT NULL;
 IF NOT FOUND THEN RETURN false; END IF;
 INSERT INTO verivaro_private.security_incident_events(incident_id,action) VALUES(i,'closed');
 RETURN true;
END $close$;
CREATE FUNCTION verivaro_monitor.health()
RETURNS TABLE(evaluated_at timestamptz,active_leases bigint,reserved_bytes bigint,open_incidents bigint,critical_incidents bigint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $health$
 SELECT m.evaluated_at,(SELECT count(*) FROM verivaro_private.download_leases),
 (SELECT COALESCE(sum(l.reserved_bytes),0)::bigint FROM verivaro_private.download_leases l),
 (SELECT count(*) FROM verivaro_private.security_incidents WHERE closed_at IS NULL),
 (SELECT count(*) FROM verivaro_private.security_incidents WHERE closed_at IS NULL AND severity='critical')
 FROM verivaro_private.monitor_state m WHERE singleton
$health$;
CREATE FUNCTION verivaro_monitor.list_open()
RETURNS TABLE(id uuid,kind text,severity text,opened_at timestamptz,last_seen timestamptz,acknowledged_at timestamptz,escalated_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $list$
 SELECT i.id,i.kind,i.severity,i.opened_at,i.last_seen,i.acknowledged_at,i.escalated_at
 FROM verivaro_private.security_incidents i WHERE closed_at IS NULL ORDER BY i.opened_at,i.id
$list$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA verivaro_monitor FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_monitor.evaluate(),verivaro_monitor.health() TO verivaro_monitor_worker;
GRANT EXECUTE ON FUNCTION verivaro_monitor.health(),verivaro_monitor.list_open(),verivaro_monitor.acknowledge(uuid),verivaro_monitor.close_incident(uuid) TO verivaro_incident_operator;
COMMIT;
