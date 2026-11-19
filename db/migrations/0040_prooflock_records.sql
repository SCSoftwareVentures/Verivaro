BEGIN;
CREATE TABLE verivaro_private.prooflock_milestones(
 revision_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,project_id uuid NOT NULL,milestone_id uuid NOT NULL,
 revision integer NOT NULL CHECK(revision BETWEEN 1 AND 16),
 title text NOT NULL CHECK(char_length(title) BETWEEN 1 AND 128 AND octet_length(title)<=512),
 confirmed boolean NOT NULL,local_time text,timezone text NOT NULL,offset_minutes integer,stage_at timestamptz,
 author_id uuid NOT NULL,session_id uuid NOT NULL,created_at timestamptz NOT NULL DEFAULT date_trunc('milliseconds',clock_timestamp()),
 CHECK((confirmed AND local_time IS NOT NULL AND offset_minutes IS NOT NULL AND stage_at IS NOT NULL) OR (NOT confirmed AND local_time IS NULL AND offset_minutes IS NULL AND stage_at IS NULL)),
 FOREIGN KEY(tenant_id,project_id) REFERENCES verivaro.projects(tenant_id,id),UNIQUE(tenant_id,project_id,milestone_id,revision));
CREATE TABLE verivaro_private.prooflock_windows(
 window_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,project_id uuid NOT NULL,version_id uuid NOT NULL REFERENCES verivaro_private.requirement_versions(version_id),
 milestone_id uuid NOT NULL,lead_minutes integer NOT NULL CHECK(lead_minutes BETWEEN 0 AND 525600),
 irreversibility text NOT NULL CHECK(irreversibility IN ('reversible','costly','irreversible')),
 reason text NOT NULL CHECK(char_length(reason) BETWEEN 1 AND 512 AND octet_length(reason)<=2048),
 proposer_id uuid NOT NULL,session_id uuid NOT NULL,created_at timestamptz NOT NULL DEFAULT date_trunc('milliseconds',clock_timestamp()),
 FOREIGN KEY(tenant_id,project_id) REFERENCES verivaro.projects(tenant_id,id),UNIQUE(version_id,milestone_id));
CREATE TABLE verivaro_private.prooflock_window_reviews(
 window_id uuid PRIMARY KEY REFERENCES verivaro_private.prooflock_windows(window_id),
 reviewer_id uuid NOT NULL,session_id uuid NOT NULL,decision text NOT NULL CHECK(decision IN ('approved','rejected')),
 reason text NOT NULL CHECK(char_length(reason) BETWEEN 1 AND 512 AND octet_length(reason)<=2048),
 reviewed_at timestamptz NOT NULL DEFAULT date_trunc('milliseconds',clock_timestamp()));
REVOKE ALL ON verivaro_private.prooflock_milestones,verivaro_private.prooflock_windows,verivaro_private.prooflock_window_reviews FROM PUBLIC;
CREATE TRIGGER milestone_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.prooflock_milestones FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER window_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.prooflock_windows FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER window_review_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.prooflock_window_reviews FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER milestone_archive_guard BEFORE INSERT ON verivaro_private.prooflock_milestones FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_project_write();
CREATE TRIGGER window_archive_guard BEFORE INSERT ON verivaro_private.prooflock_windows FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_project_write();
CREATE INDEX prooflock_window_scope_idx ON verivaro_private.prooflock_windows(tenant_id,project_id,window_id);

-- PostgreSQL independently checks wall time and the proposed explicit offset.
-- An invalid or nonexistent local instant must never become a deadline.
CREATE FUNCTION verivaro_private.prooflock_stage(local_text text,zone text,offset_min integer) RETURNS timestamptz
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $stage$
DECLARE wall timestamp;result timestamptz;
BEGIN
 IF local_text IS NULL OR local_text !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}$' OR offset_min IS NULL OR offset_min NOT BETWEEN -840 AND 840 THEN RAISE EXCEPTION 'invalid schedule' USING ERRCODE='22023';END IF;
 wall:=local_text::timestamp;
 IF to_char(wall,'YYYY-MM-DD"T"HH24:MI')<>local_text THEN RAISE EXCEPTION 'invalid schedule' USING ERRCODE='22023';END IF;
 result:=(wall-make_interval(mins=>offset_min)) AT TIME ZONE 'UTC';
 IF result AT TIME ZONE zone IS DISTINCT FROM wall THEN RAISE EXCEPTION 'invalid schedule offset' USING ERRCODE='22023';END IF;
 RETURN result;
END $stage$;
REVOKE ALL ON FUNCTION verivaro_private.prooflock_stage(text,text,integer) FROM PUBLIC;

CREATE FUNCTION verivaro_verification.write_milestone(t uuid,p uuid,m uuid,rid uuid,expected integer,n text,confirmed_value boolean,local_text text,zone text,offset_min integer) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $write$
DECLARE c text[];prior verivaro_private.prooflock_milestones%ROWTYPE;latest integer;stage timestamptz;last_record timestamptz;record_time timestamptz;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'submitter');
 IF m IS NULL OR rid IS NULL OR expected IS NULL OR expected NOT BETWEEN 0 AND 15 OR n IS NULL OR char_length(n) NOT BETWEEN 1 AND 128 OR octet_length(n)>512 OR n<>btrim(n) OR n~'[[:cntrl:]]'
 OR confirmed_value IS NULL OR zone IS NULL OR char_length(zone)>80 OR zone !~ '^(UTC|[A-Za-z][A-Za-z0-9_+.-]*(/[A-Za-z0-9_+.-]+)+)$' OR NOT EXISTS(SELECT 1 FROM pg_timezone_names x WHERE x.name=zone)
 OR (NOT confirmed_value AND (local_text IS NOT NULL OR offset_min IS NOT NULL)) THEN RAISE EXCEPTION 'invalid milestone' USING ERRCODE='22023';END IF;
 IF confirmed_value THEN stage:=verivaro_private.prooflock_stage(local_text,zone,offset_min);END IF;
 SELECT * INTO prior FROM verivaro_private.prooflock_milestones WHERE revision_id=rid;
 IF FOUND THEN
  IF prior.tenant_id<>t OR prior.project_id<>p OR prior.milestone_id<>m OR prior.author_id<>c[2]::uuid OR prior.revision<>expected+1 OR prior.title<>n OR prior.confirmed<>confirmed_value OR prior.local_time IS DISTINCT FROM local_text OR prior.timezone<>zone OR prior.offset_minutes IS DISTINCT FROM offset_min THEN RAISE EXCEPTION 'milestone conflict' USING ERRCODE='23505';END IF;
  RETURN jsonb_build_object('milestoneId',m,'revisionId',rid,'revision',prior.revision);
 END IF;
 SELECT COALESCE(max(revision),0),max(created_at) INTO latest,last_record FROM verivaro_private.prooflock_milestones WHERE tenant_id=t AND project_id=p AND milestone_id=m;
 IF latest<>expected THEN RAISE EXCEPTION 'stale milestone' USING ERRCODE='23505';END IF;
 PERFORM pg_advisory_xact_lock(740129816161::bigint);
 IF (SELECT count(*) FROM verivaro_private.prooflock_milestones)>=32768 OR (latest=0 AND (SELECT count(*) FROM verivaro_private.prooflock_milestones WHERE tenant_id=t AND project_id=p AND revision=1)>=128) THEN RAISE EXCEPTION 'milestone capacity' USING ERRCODE='54000';END IF;
 record_time:=date_trunc('milliseconds',clock_timestamp());
 IF last_record IS NOT NULL AND record_time<=last_record THEN RAISE EXCEPTION 'milestone revision clock conflict' USING ERRCODE='23505';END IF;
 INSERT INTO verivaro_private.prooflock_milestones(revision_id,tenant_id,project_id,milestone_id,revision,title,confirmed,local_time,timezone,offset_minutes,stage_at,author_id,session_id,created_at)
 VALUES(rid,t,p,m,expected+1,n,confirmed_value,local_text,zone,offset_min,stage,c[2]::uuid,c[3]::uuid,record_time);
 RETURN jsonb_build_object('milestoneId',m,'revisionId',rid,'revision',expected+1);
END $write$;

CREATE FUNCTION verivaro_verification.propose_evidence_window(t uuid,p uuid,v uuid,w uuid,m uuid,lead integer,risk text,why text) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $proposal$
DECLARE c text[];q verivaro_private.requirement_versions%ROWTYPE;prior verivaro_private.prooflock_windows%ROWTYPE;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'submitter');q:=verivaro_private.graph_current(t,p,v);
 IF w IS NULL OR m IS NULL OR lead IS NULL OR lead NOT BETWEEN 0 AND 525600 OR risk IS NULL OR risk NOT IN ('reversible','costly','irreversible') OR why IS NULL OR char_length(why) NOT BETWEEN 1 AND 512 OR octet_length(why)>2048 OR why<>btrim(why) OR why~'[[:cntrl:]]'
 OR q.applicability NOT IN ('required','optional')
 OR NOT EXISTS(SELECT 1 FROM verivaro_private.requirement_reviews x WHERE x.version_id=v AND x.decision='approved')
 OR NOT EXISTS(SELECT 1 FROM verivaro_private.prooflock_milestones x WHERE x.tenant_id=t AND x.project_id=p AND x.milestone_id=m) THEN RAISE EXCEPTION 'window denied' USING ERRCODE='42501';END IF;
 SELECT * INTO prior FROM verivaro_private.prooflock_windows WHERE window_id=w;
 IF FOUND THEN
  IF prior.tenant_id<>t OR prior.project_id<>p OR prior.version_id<>v OR prior.milestone_id<>m OR prior.lead_minutes<>lead OR prior.irreversibility<>risk OR prior.reason<>why OR prior.proposer_id<>c[2]::uuid THEN RAISE EXCEPTION 'window conflict' USING ERRCODE='23505';END IF;
  RETURN w;
 END IF;
 PERFORM pg_advisory_xact_lock(740129816161::bigint);
 IF (SELECT count(*) FROM verivaro_private.prooflock_windows)>=65536 OR (SELECT count(*) FROM verivaro_private.prooflock_windows WHERE tenant_id=t AND project_id=p)>=256 THEN RAISE EXCEPTION 'window capacity' USING ERRCODE='54000';END IF;
 INSERT INTO verivaro_private.prooflock_windows(window_id,tenant_id,project_id,version_id,milestone_id,lead_minutes,irreversibility,reason,proposer_id,session_id)
 VALUES(w,t,p,v,m,lead,risk,why,c[2]::uuid,c[3]::uuid);
 RETURN w;
END $proposal$;

CREATE FUNCTION verivaro_verification.review_evidence_window(t uuid,p uuid,w uuid,d text,why text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $review$
DECLARE c text[];q verivaro_private.requirement_versions%ROWTYPE;win verivaro_private.prooflock_windows%ROWTYPE;prior verivaro_private.prooflock_window_reviews%ROWTYPE;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'reviewer');
 SELECT * INTO win FROM verivaro_private.prooflock_windows WHERE tenant_id=t AND project_id=p AND window_id=w;
 IF NOT FOUND THEN RAISE EXCEPTION 'window denied' USING ERRCODE='42501';END IF;
 q:=verivaro_private.graph_current(t,p,win.version_id);
 IF c[2]::uuid IN (win.proposer_id,q.author_id) OR d IS NULL OR d NOT IN ('approved','rejected') OR why IS NULL OR char_length(why) NOT BETWEEN 1 AND 512 OR octet_length(why)>2048 OR why<>btrim(why) OR why~'[[:cntrl:]]' THEN RAISE EXCEPTION 'window review denied' USING ERRCODE='42501';END IF;
 SELECT * INTO prior FROM verivaro_private.prooflock_window_reviews WHERE window_id=w;
 IF FOUND THEN
  IF prior.reviewer_id<>c[2]::uuid OR prior.decision<>d OR prior.reason<>why THEN RAISE EXCEPTION 'window conflict' USING ERRCODE='23505';END IF;
  RETURN true;
 END IF;
 INSERT INTO verivaro_private.prooflock_window_reviews(window_id,reviewer_id,session_id,decision,reason) VALUES(w,c[2]::uuid,c[3]::uuid,d,why);
 RETURN true;
END $review$;

-- One stable statement snapshot for authorization, criterion assessment and
-- immutable schedule records. Review hints are advisory; no direct grants.
CREATE FUNCTION verivaro_verification.prooflock_records(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $records$
DECLARE g jsonb;ms jsonb;ws jsonb;
BEGIN
 g:=verivaro_verification.assessment(t,p);
 SELECT COALESCE(jsonb_agg(jsonb_build_object('tenantId',m.tenant_id,'projectId',m.project_id,'milestoneId',m.milestone_id,'revisionId',m.revision_id,'revision',m.revision,'title',m.title,'confirmed',m.confirmed,'localTime',m.local_time,'timezone',m.timezone,'offsetMinutes',m.offset_minutes,'stage',CASE WHEN m.stage_at IS NULL THEN NULL ELSE to_char(m.stage_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,'recordedAt',to_char(m.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')) ORDER BY m.milestone_id,m.revision),'[]'::jsonb)
 INTO ms FROM verivaro_private.prooflock_milestones m WHERE m.tenant_id=t AND m.project_id=p;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('tenantId',w.tenant_id,'projectId',w.project_id,'windowId',w.window_id,'requirementId',q.requirement_id,'versionId',w.version_id,'milestoneId',w.milestone_id,'leadMinutes',w.lead_minutes,'irreversibility',w.irreversibility,'proposalReason',w.reason,'ruleDecision',COALESCE(r.decision,'pending'),'reviewReason',r.reason,'recordedAt',to_char(w.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),'reviewedAt',CASE WHEN r.reviewed_at IS NULL THEN NULL ELSE to_char(r.reviewed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END) ORDER BY w.window_id),'[]'::jsonb)
 INTO ws FROM verivaro_private.prooflock_windows w JOIN verivaro_private.requirement_versions q ON q.version_id=w.version_id LEFT JOIN verivaro_private.prooflock_window_reviews r ON r.window_id=w.window_id WHERE w.tenant_id=t AND w.project_id=p;
 RETURN jsonb_build_object('scope',jsonb_build_object('tenantId',t,'projectId',p),'asOf',to_char(statement_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),'assessment',g,'milestones',ms,'windows',ws);
END $records$;
REVOKE ALL ON FUNCTION verivaro_verification.write_milestone(uuid,uuid,uuid,uuid,integer,text,boolean,text,text,integer),verivaro_verification.propose_evidence_window(uuid,uuid,uuid,uuid,uuid,integer,text,text),verivaro_verification.review_evidence_window(uuid,uuid,uuid,text,text),verivaro_verification.prooflock_records(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_verification.write_milestone(uuid,uuid,uuid,uuid,integer,text,boolean,text,text,integer),verivaro_verification.propose_evidence_window(uuid,uuid,uuid,uuid,uuid,integer,text,text),verivaro_verification.review_evidence_window(uuid,uuid,uuid,text,text),verivaro_verification.prooflock_records(uuid,uuid) TO verivaro_runtime;
COMMIT;
