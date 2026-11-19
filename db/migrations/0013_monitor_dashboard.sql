BEGIN;
CREATE ROLE verivaro_monitor_reader NOLOGIN NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
GRANT USAGE ON SCHEMA verivaro_monitor TO verivaro_monitor_reader;
GRANT EXECUTE ON FUNCTION verivaro_monitor.health(),verivaro_monitor.list_open() TO verivaro_monitor_reader;
-- Durable read-only alert inbox, sourced from committed incident events.
CREATE FUNCTION verivaro_monitor.recent_alerts()
RETURNS TABLE(event_id bigint,incident_id uuid,kind text,severity text,action text,occurred_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $alerts$
 SELECT e.id,e.incident_id,i.kind,i.severity,e.action,e.occurred_at
 FROM verivaro_private.security_incident_events e JOIN verivaro_private.security_incidents i ON i.id=e.incident_id
 WHERE e.action IN ('opened','escalated') ORDER BY e.id DESC LIMIT 50
$alerts$;
REVOKE ALL ON FUNCTION verivaro_monitor.recent_alerts() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_monitor.recent_alerts() TO verivaro_monitor_reader,verivaro_incident_operator;
COMMIT;
