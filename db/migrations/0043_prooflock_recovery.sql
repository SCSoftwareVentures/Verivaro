BEGIN;
CREATE TABLE verivaro_private.prooflock_recovery_proposals(
 recovery_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,project_id uuid NOT NULL,
 window_id uuid NOT NULL REFERENCES verivaro_private.prooflock_windows(window_id),
 milestone_revision_id uuid NOT NULL REFERENCES verivaro_private.prooflock_milestones(revision_id),
 version_id uuid NOT NULL REFERENCES verivaro_private.requirement_versions(version_id),
 evidence_id uuid NOT NULL REFERENCES verivaro_private.evidence_objects(evidence_id),
 sha256 text NOT NULL CHECK(sha256~'^[0-9a-f]{64}$'),
 approach text NOT NULL CHECK(approach IN ('contemporaneous_record','independent_inspection','documented_exception_request')),
 reason text NOT NULL CHECK(char_length(reason) BETWEEN 1 AND 512 AND octet_length(reason)<=2048),
 deadline_at timestamptz NOT NULL,proposer_id uuid NOT NULL,session_id uuid NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,project_id) REFERENCES verivaro.projects(tenant_id,id),
 UNIQUE(window_id,milestone_revision_id,evidence_id));
CREATE TABLE verivaro_private.prooflock_recovery_reviews(
 recovery_id uuid PRIMARY KEY REFERENCES verivaro_private.prooflock_recovery_proposals(recovery_id),
 reviewer_id uuid NOT NULL,session_id uuid NOT NULL,decision text NOT NULL CHECK(decision IN ('approved','rejected')),
 reason text NOT NULL CHECK(char_length(reason) BETWEEN 1 AND 512 AND octet_length(reason)<=2048),reviewed_at timestamptz NOT NULL DEFAULT clock_timestamp());
REVOKE ALL ON verivaro_private.prooflock_recovery_proposals,verivaro_private.prooflock_recovery_reviews FROM PUBLIC;
CREATE TRIGGER prooflock_recovery_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.prooflock_recovery_proposals FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER prooflock_recovery_review_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.prooflock_recovery_reviews FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER prooflock_recovery_archive_guard BEFORE INSERT ON verivaro_private.prooflock_recovery_proposals FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_project_write();
CREATE INDEX prooflock_recovery_scope_idx ON verivaro_private.prooflock_recovery_proposals(tenant_id,project_id);
-- Historical schedule is explicitly pinned, but the underlying criterion
-- must still be current. This is an assessment proposal, never a waiver.
CREATE FUNCTION verivaro_private.recovery_gap(t uuid,p uuid,w uuid,m uuid,v uuid) RETURNS timestamptz
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $gap$
DECLARE win verivaro_private.prooflock_windows%ROWTYPE;stage verivaro_private.prooflock_milestones%ROWTYPE;q verivaro_private.requirement_versions%ROWTYPE;
 deadline timestamptz;until_at timestamptz;approved_at timestamptz;
BEGIN
 q:=verivaro_private.graph_current(t,p,v);
 SELECT * INTO win FROM verivaro_private.prooflock_windows x WHERE x.tenant_id=t AND x.project_id=p AND x.window_id=w AND x.version_id=v;
 IF NOT FOUND OR q.applicability NOT IN ('required','optional') OR NOT EXISTS(SELECT 1 FROM verivaro_private.requirement_reviews x WHERE x.version_id=v AND x.decision='approved') THEN RAISE EXCEPTION 'recovery denied' USING ERRCODE='42501';END IF;
 SELECT * INTO stage FROM verivaro_private.prooflock_milestones x WHERE x.tenant_id=t AND x.project_id=p AND x.milestone_id=win.milestone_id AND x.revision_id=m AND x.confirmed;
 IF NOT FOUND THEN RAISE EXCEPTION 'recovery schedule denied' USING ERRCODE='42501';END IF;
 SELECT COALESCE(min(x.created_at),statement_timestamp()) INTO until_at FROM verivaro_private.prooflock_milestones x WHERE x.tenant_id=t AND x.project_id=p AND x.milestone_id=win.milestone_id AND x.revision>stage.revision;
 SELECT x.reviewed_at INTO approved_at FROM verivaro_private.prooflock_window_reviews x WHERE x.window_id=w AND x.decision='approved';
 deadline:=stage.stage_at-make_interval(mins=>win.lead_minutes);
 IF approved_at IS NULL OR approved_at>until_at OR deadline>until_at THEN RAISE EXCEPTION 'no elapsed approved schedule' USING ERRCODE='42501';END IF;
 IF EXISTS(SELECT 1 FROM verivaro_private.prooflock_capture_receipts x JOIN verivaro_private.requirement_link_reviews z ON z.link_id=x.link_id JOIN verivaro_private.evidence_objects o ON o.evidence_id=x.evidence_id
 WHERE x.tenant_id=t AND x.project_id=p AND x.window_id=w AND x.milestone_revision_id=m AND x.received_at<=deadline AND z.decision='pass' AND o.cipher_digest=verivaro_private.digest(o.envelope,'sha256')) THEN RAISE EXCEPTION 'timely reviewed receipt exists' USING ERRCODE='23505';END IF;
 RETURN deadline;
END $gap$;
REVOKE ALL ON FUNCTION verivaro_private.recovery_gap(uuid,uuid,uuid,uuid,uuid) FROM PUBLIC;
CREATE FUNCTION verivaro_verification.propose_recovery(t uuid,p uuid,r uuid,w uuid,m uuid,v uuid,e uuid,h text,kind text,why text) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $proposal$
DECLARE c text[];prior verivaro_private.prooflock_recovery_proposals%ROWTYPE;deadline timestamptz;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'submitter');
 IF r IS NULL OR w IS NULL OR m IS NULL OR v IS NULL OR e IS NULL OR h IS NULL OR h!~'^[0-9a-f]{64}$' OR kind IS NULL OR kind NOT IN ('contemporaneous_record','independent_inspection','documented_exception_request') OR why IS NULL OR char_length(why) NOT BETWEEN 1 AND 512 OR octet_length(why)>2048 OR why<>btrim(why) OR why~'[[:cntrl:]]'
 OR NOT EXISTS(SELECT 1 FROM verivaro_private.evidence_objects x WHERE x.tenant_id=t AND x.project_id=p AND x.evidence_id=e AND x.sha256=h AND x.cipher_digest=verivaro_private.digest(x.envelope,'sha256')) THEN RAISE EXCEPTION 'recovery denied' USING ERRCODE='42501';END IF;
 SELECT * INTO prior FROM verivaro_private.prooflock_recovery_proposals x WHERE x.recovery_id=r;
 IF FOUND THEN
 IF prior.tenant_id<>t OR prior.project_id<>p OR prior.proposer_id<>c[2]::uuid OR prior.window_id<>w OR prior.milestone_revision_id<>m OR prior.version_id<>v OR prior.evidence_id<>e OR prior.sha256<>h OR prior.approach<>kind OR prior.reason<>why THEN RAISE EXCEPTION 'recovery conflict' USING ERRCODE='23505';END IF;
 RETURN r;END IF;
 deadline:=verivaro_private.recovery_gap(t,p,w,m,v);
 PERFORM pg_advisory_xact_lock(740129816163::bigint);
 IF (SELECT count(*) FROM verivaro_private.prooflock_recovery_proposals)>=32768 OR (SELECT count(*) FROM verivaro_private.prooflock_recovery_proposals WHERE tenant_id=t AND project_id=p)>=128 OR (SELECT count(*) FROM verivaro_private.prooflock_recovery_proposals WHERE window_id=w AND milestone_revision_id=m)>=4 THEN RAISE EXCEPTION 'recovery capacity' USING ERRCODE='54000';END IF;
 INSERT INTO verivaro_private.prooflock_recovery_proposals(recovery_id,tenant_id,project_id,window_id,milestone_revision_id,version_id,evidence_id,sha256,approach,reason,deadline_at,proposer_id,session_id) VALUES(r,t,p,w,m,v,e,h,kind,why,deadline,c[2]::uuid,c[3]::uuid);
 RETURN r;
END $proposal$;
CREATE FUNCTION verivaro_verification.review_recovery(t uuid,p uuid,r uuid,d text,why text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $review$
DECLARE c text[];req verivaro_private.prooflock_recovery_proposals%ROWTYPE;prior verivaro_private.prooflock_recovery_reviews%ROWTYPE;q verivaro_private.requirement_versions%ROWTYPE;source_actor uuid;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'reviewer');
 SELECT * INTO req FROM verivaro_private.prooflock_recovery_proposals x WHERE x.tenant_id=t AND x.project_id=p AND x.recovery_id=r;
 IF NOT FOUND THEN RAISE EXCEPTION 'recovery denied' USING ERRCODE='42501';END IF;
 SELECT * INTO q FROM verivaro_private.requirement_versions x WHERE x.version_id=req.version_id;
 SELECT x.actor_id INTO source_actor FROM verivaro_private.evidence_objects x WHERE x.tenant_id=t AND x.project_id=p AND x.evidence_id=req.evidence_id AND x.sha256=req.sha256 AND x.cipher_digest=verivaro_private.digest(x.envelope,'sha256');
 IF source_actor IS NULL OR c[2]::uuid IN (req.proposer_id,q.author_id,source_actor) OR d IS NULL OR d NOT IN ('approved','rejected') OR why IS NULL OR char_length(why) NOT BETWEEN 1 AND 512 OR octet_length(why)>2048 OR why<>btrim(why) OR why~'[[:cntrl:]]' THEN RAISE EXCEPTION 'recovery review denied' USING ERRCODE='42501';END IF;
 SELECT * INTO prior FROM verivaro_private.prooflock_recovery_reviews x WHERE x.recovery_id=r;
 IF FOUND THEN IF prior.reviewer_id<>c[2]::uuid OR prior.decision<>d OR prior.reason<>why THEN RAISE EXCEPTION 'recovery conflict' USING ERRCODE='23505';END IF;RETURN true;END IF;
 IF d='approved' THEN PERFORM verivaro_private.recovery_gap(t,p,req.window_id,req.milestone_revision_id,req.version_id);END IF;
 INSERT INTO verivaro_private.prooflock_recovery_reviews(recovery_id,reviewer_id,session_id,decision,reason) VALUES(r,c[2]::uuid,c[3]::uuid,d,why);
 RETURN true;
END $review$;
CREATE FUNCTION verivaro_verification.prooflock_recovery_records(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $records$
DECLARE g jsonb;items jsonb;
BEGIN
 g:=verivaro_verification.prooflock_insights_records(t,p);
 SELECT COALESCE(jsonb_agg(jsonb_build_object('recoveryId',x.recovery_id,'windowId',x.window_id,'revisionId',x.milestone_revision_id,'versionId',x.version_id,'requirementId',q.requirement_id,'evidenceId',x.evidence_id,'sha256',x.sha256,'approach',x.approach,'reason',x.reason,'deadline',to_char(x.deadline_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),'decision',COALESCE(z.decision,'pending'),'reviewReason',z.reason,'criterionCurrent',NOT EXISTS(SELECT 1 FROM verivaro_private.requirement_versions n WHERE n.tenant_id=t AND n.project_id=p AND n.requirement_id=q.requirement_id AND n.revision>q.revision),'sourceIntact',o.sha256=x.sha256 AND o.cipher_digest=verivaro_private.digest(o.envelope,'sha256'),'waiverGranted',false) ORDER BY x.created_at,x.recovery_id),'[]'::jsonb)
 INTO items FROM verivaro_private.prooflock_recovery_proposals x JOIN verivaro_private.requirement_versions q ON q.version_id=x.version_id JOIN verivaro_private.evidence_objects o ON o.evidence_id=x.evidence_id LEFT JOIN verivaro_private.prooflock_recovery_reviews z ON z.recovery_id=x.recovery_id WHERE x.tenant_id=t AND x.project_id=p;
 RETURN g||jsonb_build_object('recoveryProposals',items);
END $records$;
REVOKE ALL ON FUNCTION verivaro_verification.propose_recovery(uuid,uuid,uuid,uuid,uuid,uuid,uuid,text,text,text),verivaro_verification.review_recovery(uuid,uuid,uuid,text,text),verivaro_verification.prooflock_recovery_records(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_verification.propose_recovery(uuid,uuid,uuid,uuid,uuid,uuid,uuid,text,text,text),verivaro_verification.review_recovery(uuid,uuid,uuid,text,text),verivaro_verification.prooflock_recovery_records(uuid,uuid) TO verivaro_runtime;
COMMIT;
