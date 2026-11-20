BEGIN;
CREATE ROLE verivaro_identity_events NOLOGIN NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
GRANT USAGE ON SCHEMA verivaro_identity TO verivaro_identity_events;
CREATE TABLE verivaro_private.provider_events(
 issuer text NOT NULL,
 event_id uuid NOT NULL,
 event_time timestamptz NOT NULL,
 kind text NOT NULL CHECK(kind IN ('logout','disable')),
 received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(issuer,event_id)
);
CREATE INDEX provider_event_expiry ON verivaro_private.provider_events(received_at);
REVOKE ALL ON verivaro_private.provider_events FROM PUBLIC;
-- Actor lock serializes with new session registration. Fence prevents
-- pre-logout upstream authentication from being redeemed later.
CREATE FUNCTION verivaro_private.revoke_actor_sessions(a uuid) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $revoke$
DECLARE n timestamptz; count_revoked integer;
BEGIN
 PERFORM verivaro_private.lock_identity(a);
 n:=clock_timestamp();
 INSERT INTO verivaro_private.identity_fences(actor_id,authenticated_after) VALUES(a,n)
 ON CONFLICT(actor_id) DO UPDATE SET authenticated_after=GREATEST(identity_fences.authenticated_after,EXCLUDED.authenticated_after);
 WITH changed AS (
  UPDATE verivaro_private.identity_sessions SET revoked_at=GREATEST(n,created_at)
  WHERE actor_id=a AND revoked_at IS NULL RETURNING session_id
 )
 INSERT INTO verivaro_private.identity_events(actor_id,session_id,kind)
 SELECT a,session_id,'session_revoked' FROM changed;
 GET DIAGNOSTICS count_revoked=ROW_COUNT;
 RETURN count_revoked;
END $revoke$;
REVOKE ALL ON FUNCTION verivaro_private.revoke_actor_sessions(uuid) FROM PUBLIC;
CREATE FUNCTION verivaro_identity.logout_all_browser(h bytea) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $logout$
DECLARE a uuid; s uuid;
BEGIN
 SELECT i.actor_id,i.session_id INTO a,s FROM verivaro_private.browser_sessions b
 JOIN verivaro_private.identity_sessions i USING(session_id)
 WHERE b.handle_hash=h AND b.expires_at>clock_timestamp() AND i.revoked_at IS NULL AND i.expires_at>clock_timestamp();
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM verivaro_private.lock_identity(a);
 IF NOT EXISTS(SELECT 1 FROM verivaro_private.identity_sessions WHERE actor_id=a AND session_id=s AND revoked_at IS NULL AND expires_at>clock_timestamp())
 OR EXISTS(SELECT 1 FROM verivaro_private.disabled_actors WHERE actor_id=a) THEN RETURN false; END IF;
 PERFORM verivaro_private.revoke_actor_sessions(a);
 RETURN true;
END $logout$;
CREATE FUNCTION verivaro_identity.apply_provider_event(iss text,e uuid,subject_hash bytea,kind text,event_at timestamptz) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $event$
DECLARE a uuid; n timestamptz;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR iss IS NULL OR octet_length(iss) NOT BETWEEN 1 AND 512
 OR e IS NULL OR subject_hash IS NULL OR octet_length(subject_hash)<>32 OR kind IS NULL OR kind NOT IN ('logout','disable') OR event_at IS NULL THEN RETURN false; END IF;
 PERFORM pg_advisory_xact_lock(740129816152::bigint);
 n:=clock_timestamp();
 IF event_at>n OR event_at<n-interval '5 minutes' THEN RETURN false; END IF;
 DELETE FROM verivaro_private.provider_events WHERE received_at<n-interval '15 minutes';
 IF EXISTS(SELECT 1 FROM verivaro_private.provider_events WHERE issuer=iss AND event_id=e) THEN RETURN true; END IF;
 IF (SELECT count(*) FROM verivaro_private.provider_events)>=10000 THEN RAISE EXCEPTION 'provider event capacity exhausted'; END IF;
 SELECT actor_id INTO a FROM verivaro_private.provider_bindings WHERE issuer=iss AND subject_digest=subject_hash AND disabled_at IS NULL FOR UPDATE;
 IF FOUND THEN
  IF kind='disable' THEN PERFORM verivaro_identity.disable_binding(iss,subject_hash,e);
  ELSE PERFORM verivaro_private.revoke_actor_sessions(a); END IF;
 END IF;
 INSERT INTO verivaro_private.provider_events(issuer,event_id,event_time,kind) VALUES(iss,e,event_at,kind);
 RETURN true;
END $event$;
REVOKE ALL ON FUNCTION verivaro_identity.logout_all_browser(bytea),verivaro_identity.apply_provider_event(text,uuid,bytea,text,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_identity.logout_all_browser(bytea) TO verivaro_identity_service;
GRANT EXECUTE ON FUNCTION verivaro_identity.apply_provider_event(text,uuid,bytea,text,timestamptz) TO verivaro_identity_events;
CREATE TABLE verivaro_private.auth_telemetry(
 slot integer PRIMARY KEY CHECK(slot BETWEEN 0 AND 59), bucket bigint NOT NULL,
 denied integer NOT NULL CHECK(denied BETWEEN 0 AND 1000000), completed integer NOT NULL CHECK(completed BETWEEN 0 AND 1000000)
);
REVOKE ALL ON verivaro_private.auth_telemetry FROM PUBLIC;
CREATE FUNCTION verivaro_identity.record_auth(outcome text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $telemetry$
DECLARE b bigint:=floor(extract(epoch FROM clock_timestamp())/60)::bigint;
BEGIN
 IF outcome IS NULL OR outcome NOT IN ('denied','completed') THEN RETURN false; END IF;
 INSERT INTO verivaro_private.auth_telemetry(slot,bucket,denied,completed)
 VALUES(mod(b,60)::integer,b,(outcome='denied')::integer,(outcome='completed')::integer)
 ON CONFLICT(slot) DO UPDATE SET bucket=EXCLUDED.bucket,
 denied=LEAST(1000000,CASE WHEN auth_telemetry.bucket=EXCLUDED.bucket THEN auth_telemetry.denied ELSE 0 END+EXCLUDED.denied),
 completed=LEAST(1000000,CASE WHEN auth_telemetry.bucket=EXCLUDED.bucket THEN auth_telemetry.completed ELSE 0 END+EXCLUDED.completed)
 WHERE auth_telemetry.bucket<=EXCLUDED.bucket;
 RETURN true;
END $telemetry$;
REVOKE ALL ON FUNCTION verivaro_identity.record_auth(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_identity.record_auth(text) TO verivaro_identity_service;
ALTER TABLE verivaro_private.security_incidents DROP CONSTRAINT security_incidents_kind_check;
ALTER TABLE verivaro_private.security_incidents ADD CONSTRAINT security_incidents_kind_check CHECK(kind IN ('access_denials','integrity_failure','resource_pressure','stranded_reservation','delivery_failures','authentication_pressure'));
CREATE OR REPLACE FUNCTION verivaro_monitor.evaluate() RETURNS integer
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
 ('authentication_pressure','warning',(SELECT COALESCE(sum(t.denied),0) FROM verivaro_private.auth_telemetry t WHERE t.bucket BETWEEN b-4 AND b)>=20),
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

COMMIT;
