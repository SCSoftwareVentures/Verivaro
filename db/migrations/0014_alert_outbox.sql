BEGIN;
CREATE ROLE verivaro_alert_sender NOLOGIN NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE SCHEMA verivaro_alerting;
REVOKE ALL ON SCHEMA verivaro_alerting FROM PUBLIC;
GRANT USAGE ON SCHEMA verivaro_alerting TO verivaro_alert_sender;
-- Durable transactional outbox. No historical notifications are backfilled.
CREATE TABLE verivaro_private.alert_outbox(
 event_id bigint PRIMARY KEY REFERENCES verivaro_private.security_incident_events(id),
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','sending','delivered','dead')),
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 5),
 next_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 claim_id uuid, claimed_by name, claim_until timestamptz,
 delivered_at timestamptz,
 CHECK((state='sending')=(claim_id IS NOT NULL AND claimed_by IS NOT NULL AND claim_until IS NOT NULL)),
 CHECK((state='delivered')=(delivered_at IS NOT NULL))
);
CREATE INDEX alert_due ON verivaro_private.alert_outbox(next_at,event_id) WHERE state='pending';
CREATE INDEX alert_expired ON verivaro_private.alert_outbox(claim_until,event_id) WHERE state='sending';
REVOKE ALL ON verivaro_private.alert_outbox FROM PUBLIC;
CREATE FUNCTION verivaro_private.queue_incident_alert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $queue$
BEGIN
 IF NEW.action IN ('opened','escalated') THEN
  INSERT INTO verivaro_private.alert_outbox(event_id) VALUES(NEW.id);
 END IF;
 RETURN NEW;
END $queue$;
REVOKE ALL ON FUNCTION verivaro_private.queue_incident_alert() FROM PUBLIC;
CREATE TRIGGER enqueue_alert AFTER INSERT ON verivaro_private.security_incident_events
 FOR EACH ROW EXECUTE FUNCTION verivaro_private.queue_incident_alert();

CREATE FUNCTION verivaro_alerting.claim()
RETURNS TABLE(event_id bigint,claim_id uuid,attempt integer,incident_id uuid,kind text,severity text,action text,occurred_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $claim$
DECLARE n timestamptz:=clock_timestamp(); chosen bigint; c uuid:=gen_random_uuid();
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RETURN; END IF;
 -- A final interrupted attempt is ambiguous; do not retry forever.
 UPDATE verivaro_private.alert_outbox o SET state='dead',claim_id=NULL,claimed_by=NULL,claim_until=NULL
 WHERE o.event_id IN (SELECT x.event_id FROM verivaro_private.alert_outbox x WHERE x.state='sending' AND x.claim_until<=n AND x.attempts=5 ORDER BY x.claim_until LIMIT 100 FOR UPDATE SKIP LOCKED);
 SELECT o.event_id INTO chosen FROM verivaro_private.alert_outbox o
 WHERE o.attempts<5 AND ((o.state='pending' AND o.next_at<=n) OR (o.state='sending' AND o.claim_until<=n))
 ORDER BY o.next_at,o.event_id LIMIT 1 FOR UPDATE SKIP LOCKED;
 IF NOT FOUND THEN RETURN; END IF;
 UPDATE verivaro_private.alert_outbox o SET state='sending',attempts=o.attempts+1,claim_id=c,claimed_by=session_user,claim_until=n+interval '60 seconds' WHERE o.event_id=chosen;
 RETURN QUERY SELECT o.event_id,o.claim_id,o.attempts,i.id,i.kind,i.severity,e.action,e.occurred_at
 FROM verivaro_private.alert_outbox o JOIN verivaro_private.security_incident_events e ON e.id=o.event_id
 JOIN verivaro_private.security_incidents i ON i.id=e.incident_id WHERE o.event_id=chosen;
END $claim$;
CREATE FUNCTION verivaro_alerting.finish(e bigint,c uuid,outcome text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $finish$
DECLARE n timestamptz:=clock_timestamp();
BEGIN
 IF outcome IS NULL OR outcome NOT IN ('accepted','retry','permanent') THEN RETURN false; END IF;
 UPDATE verivaro_private.alert_outbox o SET
 state=CASE WHEN outcome='accepted' THEN 'delivered' WHEN outcome='permanent' OR o.attempts>=5 THEN 'dead' ELSE 'pending' END,
 next_at=n+make_interval(secs=>30*power(2,o.attempts-1)::integer),
 delivered_at=CASE WHEN outcome='accepted' THEN n ELSE NULL END,
 claim_id=NULL,claimed_by=NULL,claim_until=NULL
 WHERE o.event_id=e AND o.state='sending' AND o.claim_id=c AND o.claimed_by=session_user AND o.claim_until>n;
 RETURN FOUND;
END $finish$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA verivaro_alerting FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_alerting.claim(),verivaro_alerting.finish(bigint,uuid,text) TO verivaro_alert_sender;
CREATE FUNCTION verivaro_monitor.alert_delivery_health()
RETURNS TABLE(pending bigint,sending bigint,delivered bigint,dead bigint,oldest_pending timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $health$
 SELECT count(*) FILTER(WHERE state='pending'),count(*) FILTER(WHERE state='sending'),
 count(*) FILTER(WHERE state='delivered'),count(*) FILTER(WHERE state='dead'),
 min(next_at) FILTER(WHERE state='pending') FROM verivaro_private.alert_outbox
$health$;
REVOKE ALL ON FUNCTION verivaro_monitor.alert_delivery_health() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_monitor.alert_delivery_health() TO verivaro_monitor_reader,verivaro_incident_operator;

-- Closure requires a separately recorded resolution reference and controlled reason.
CREATE TABLE verivaro_private.incident_resolutions(
 incident_id uuid PRIMARY KEY REFERENCES verivaro_private.security_incidents(id),
 resolution_ref uuid UNIQUE NOT NULL,
 reason text NOT NULL CHECK(reason IN ('remediated','false_positive','risk_accepted')),
 operator_login name NOT NULL DEFAULT session_user,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON verivaro_private.incident_resolutions FROM PUBLIC;
CREATE TRIGGER incident_resolutions_immutable BEFORE UPDATE OR DELETE OR TRUNCATE
 ON verivaro_private.incident_resolutions FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
REVOKE EXECUTE ON FUNCTION verivaro_monitor.close_incident(uuid) FROM verivaro_incident_operator;
CREATE FUNCTION verivaro_monitor.resolve_incident(i uuid,r uuid,reason_code text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $resolve$
BEGIN
 IF i IS NULL OR r IS NULL OR reason_code IS NULL OR reason_code NOT IN ('remediated','false_positive','risk_accepted') THEN RETURN false; END IF;
 IF NOT verivaro_monitor.close_incident(i) THEN RETURN false; END IF;
 INSERT INTO verivaro_private.incident_resolutions(incident_id,resolution_ref,reason) VALUES(i,r,reason_code);
 RETURN true;
END $resolve$;
REVOKE ALL ON FUNCTION verivaro_monitor.resolve_incident(uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_monitor.resolve_incident(uuid,uuid,text) TO verivaro_incident_operator;
COMMIT;
