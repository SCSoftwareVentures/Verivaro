BEGIN;
-- Project policy is immutable and explicitly controlled by both-level owners.
CREATE TABLE verivaro_private.prooflock_alert_policies(
 policy_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,project_id uuid NOT NULL,revision integer NOT NULL CHECK(revision BETWEEN 1 AND 32),
 timezone text NOT NULL,quiet_start integer,quiet_end integer,critical_override boolean NOT NULL,
 actor_id uuid NOT NULL,session_id uuid NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK((quiet_start IS NULL AND quiet_end IS NULL) OR (quiet_start BETWEEN 0 AND 1439 AND quiet_end BETWEEN 0 AND 1439 AND quiet_start<>quiet_end)),
 FOREIGN KEY(tenant_id,project_id) REFERENCES verivaro.projects(tenant_id,id),UNIQUE(tenant_id,project_id,revision));
REVOKE ALL ON verivaro_private.prooflock_alert_policies FROM PUBLIC;
CREATE TRIGGER prooflock_policy_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.prooflock_alert_policies FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER prooflock_policy_archive_guard BEFORE INSERT ON verivaro_private.prooflock_alert_policies FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_project_write();
CREATE FUNCTION verivaro_verification.write_prooflock_alert_policy(t uuid,p uuid,r uuid,expected integer,zone text,qs integer,qe integer,override_critical boolean) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $policy$
DECLARE c text[];prior verivaro_private.prooflock_alert_policies%ROWTYPE;latest integer;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'owner');
 IF r IS NULL OR expected IS NULL OR expected NOT BETWEEN 0 AND 31 OR zone IS NULL OR char_length(zone)>80 OR zone !~ '^(UTC|[A-Za-z][A-Za-z0-9_+.-]*(/[A-Za-z0-9_+.-]+)+)$' OR NOT EXISTS(SELECT 1 FROM pg_timezone_names x WHERE x.name=zone)
 OR override_critical IS NULL OR (qs IS NULL)<>(qe IS NULL) OR (qs IS NOT NULL AND (qs NOT BETWEEN 0 AND 1439 OR qe NOT BETWEEN 0 AND 1439 OR qs=qe)) THEN RAISE EXCEPTION 'invalid alert policy' USING ERRCODE='22023';END IF;
 SELECT * INTO prior FROM verivaro_private.prooflock_alert_policies x WHERE x.policy_id=r;
 IF FOUND THEN
  IF prior.tenant_id<>t OR prior.project_id<>p OR prior.actor_id<>c[2]::uuid OR prior.revision<>expected+1 OR prior.timezone<>zone OR prior.quiet_start IS DISTINCT FROM qs OR prior.quiet_end IS DISTINCT FROM qe OR prior.critical_override<>override_critical THEN RAISE EXCEPTION 'policy conflict' USING ERRCODE='23505';END IF;
  RETURN jsonb_build_object('policyId',r,'revision',prior.revision);
 END IF;
 SELECT COALESCE(max(x.revision),0) INTO latest FROM verivaro_private.prooflock_alert_policies x WHERE x.tenant_id=t AND x.project_id=p;
 IF latest<>expected THEN RAISE EXCEPTION 'stale policy' USING ERRCODE='23505';END IF;
 PERFORM pg_advisory_xact_lock(740129816162::bigint);
 IF (SELECT count(*) FROM verivaro_private.prooflock_alert_policies)>=32768 THEN RAISE EXCEPTION 'policy capacity' USING ERRCODE='54000';END IF;
 INSERT INTO verivaro_private.prooflock_alert_policies(policy_id,tenant_id,project_id,revision,timezone,quiet_start,quiet_end,critical_override,actor_id,session_id) VALUES(r,t,p,expected+1,zone,qs,qe,override_critical,c[2]::uuid,c[3]::uuid);
 RETURN jsonb_build_object('policyId',r,'revision',expected+1);
END $policy$;
-- Same stable snapshot as plan inputs. Receipt timestamps are server clocks;
-- they are not a statement about when or where physical capture happened.
CREATE FUNCTION verivaro_verification.prooflock_insights_records(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $records$
DECLARE g jsonb;receipts jsonb;policy jsonb;
BEGIN
 g:=verivaro_verification.prooflock_records(t,p);
 SELECT COALESCE(jsonb_agg(jsonb_build_object('windowId',x.window_id,'versionId',l.version_id,'milestoneRevisionId',x.milestone_revision_id,'linkId',x.link_id,'evidenceId',x.evidence_id,'receivedAt',to_char(x.received_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),'deadline',CASE WHEN x.deadline_at IS NULL THEN NULL ELSE to_char(x.deadline_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,'decision',COALESCE(z.decision,'pending')) ORDER BY x.received_at,x.link_id),'[]'::jsonb)
 INTO receipts FROM verivaro_private.prooflock_capture_receipts x JOIN verivaro_private.requirement_evidence_links l ON l.link_id=x.link_id LEFT JOIN verivaro_private.requirement_link_reviews z ON z.link_id=x.link_id WHERE x.tenant_id=t AND x.project_id=p;
 SELECT jsonb_build_object('revision',x.revision,'timezone',x.timezone,'quietStart',x.quiet_start,'quietEnd',x.quiet_end,'criticalOverride',x.critical_override) INTO policy FROM verivaro_private.prooflock_alert_policies x WHERE x.tenant_id=t AND x.project_id=p ORDER BY x.revision DESC LIMIT 1;
 RETURN g||jsonb_build_object('captureReceipts',receipts,'alertPolicy',COALESCE(policy,jsonb_build_object('revision',0,'timezone','UTC','quietStart',NULL,'quietEnd',NULL,'criticalOverride',false)));
END $records$;
REVOKE ALL ON FUNCTION verivaro_verification.write_prooflock_alert_policy(uuid,uuid,uuid,integer,text,integer,integer,boolean),verivaro_verification.prooflock_insights_records(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_verification.write_prooflock_alert_policy(uuid,uuid,uuid,integer,text,integer,integer,boolean),verivaro_verification.prooflock_insights_records(uuid,uuid) TO verivaro_runtime;
COMMIT;
