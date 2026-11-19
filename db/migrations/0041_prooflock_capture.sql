BEGIN;
CREATE TABLE verivaro_private.prooflock_capture_receipts(
 link_id uuid PRIMARY KEY REFERENCES verivaro_private.requirement_evidence_links(link_id),
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,actor_id uuid NOT NULL,request_id uuid NOT NULL,
 window_id uuid NOT NULL REFERENCES verivaro_private.prooflock_windows(window_id),
 milestone_revision_id uuid NOT NULL REFERENCES verivaro_private.prooflock_milestones(revision_id),
 evidence_id uuid NOT NULL REFERENCES verivaro_private.evidence_objects(evidence_id),
 received_at timestamptz NOT NULL DEFAULT clock_timestamp(),deadline_at timestamptz,
 FOREIGN KEY(tenant_id,project_id) REFERENCES verivaro.projects(tenant_id,id),
 UNIQUE(tenant_id,actor_id,request_id),UNIQUE(evidence_id));
REVOKE ALL ON verivaro_private.prooflock_capture_receipts FROM PUBLIC;
CREATE TRIGGER capture_receipt_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.prooflock_capture_receipts FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER capture_receipt_archive_guard BEFORE INSERT ON verivaro_private.prooflock_capture_receipts FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_project_write();

CREATE FUNCTION verivaro_private.capture_context(t uuid,p uuid,w uuid,v uuid,m uuid) RETURNS verivaro_private.prooflock_milestones
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $context$
DECLARE q verivaro_private.requirement_versions%ROWTYPE;win verivaro_private.prooflock_windows%ROWTYPE;stage verivaro_private.prooflock_milestones%ROWTYPE;
BEGIN
 PERFORM verivaro_private.graph_actor(t,p,'submitter');
 SELECT * INTO win FROM verivaro_private.prooflock_windows WHERE tenant_id=t AND project_id=p AND window_id=w AND version_id=v;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM verivaro_private.prooflock_window_reviews x WHERE x.window_id=w AND x.decision='approved') THEN RAISE EXCEPTION 'capture denied' USING ERRCODE='42501';END IF;
 q:=verivaro_private.graph_current(t,p,v);
 IF q.applicability NOT IN ('required','optional') OR NOT EXISTS(SELECT 1 FROM verivaro_private.requirement_reviews x WHERE x.version_id=v AND x.decision='approved') THEN RAISE EXCEPTION 'capture denied' USING ERRCODE='42501';END IF;
 SELECT * INTO stage FROM verivaro_private.prooflock_milestones x WHERE x.tenant_id=t AND x.project_id=p AND x.milestone_id=win.milestone_id ORDER BY x.revision DESC LIMIT 1;
 IF NOT FOUND OR stage.revision_id IS DISTINCT FROM m THEN RAISE EXCEPTION 'stale capture schedule' USING ERRCODE='23505';END IF;
 RETURN stage;
END $context$;
REVOKE ALL ON FUNCTION verivaro_private.capture_context(uuid,uuid,uuid,uuid,uuid) FROM PUBLIC;
CREATE FUNCTION verivaro_ingestion.authorize_capture(t uuid,p uuid,w uuid,v uuid,m uuid,r uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $auth$
DECLARE c text[];
BEGIN
 c:=verivaro_private.graph_actor(t,p,'submitter');
 IF EXISTS(SELECT 1 FROM verivaro_private.prooflock_capture_receipts x JOIN verivaro_private.requirement_evidence_links l ON l.link_id=x.link_id
 WHERE x.tenant_id=t AND x.project_id=p AND x.actor_id=c[2]::uuid AND x.request_id=r AND x.window_id=w AND x.milestone_revision_id=m AND l.version_id=v) THEN RETURN true;END IF;
 PERFORM verivaro_private.capture_context(t,p,w,v,m);RETURN true;
END $auth$;
CREATE FUNCTION verivaro_ingestion.commit_capture(t uuid,p uuid,r uuid,e uuid,h text,n integer,k text,sealed bytea,media text,w uuid,v uuid,m uuid)
RETURNS TABLE(id uuid,sha256 text,bytes integer,link_id uuid)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $capture$
DECLARE c text[];prior verivaro_private.prooflock_capture_receipts%ROWTYPE;obj verivaro_private.evidence_objects%ROWTYPE;stage verivaro_private.prooflock_milestones%ROWTYPE;stored record;lead integer;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'submitter');
 IF r IS NULL OR w IS NULL OR v IS NULL OR m IS NULL THEN RAISE EXCEPTION 'invalid capture' USING ERRCODE='22023';END IF;
 SELECT * INTO prior FROM verivaro_private.prooflock_capture_receipts x WHERE x.tenant_id=t AND x.actor_id=c[2]::uuid AND x.request_id=r;
 IF FOUND THEN
  SELECT * INTO obj FROM verivaro_private.evidence_objects x WHERE x.evidence_id=prior.evidence_id;
  IF prior.project_id<>p OR prior.window_id<>w OR prior.milestone_revision_id<>m OR NOT EXISTS(SELECT 1 FROM verivaro_private.requirement_evidence_links l WHERE l.link_id=prior.link_id AND l.version_id=v)
  OR obj.sha256 IS DISTINCT FROM h OR obj.bytes IS DISTINCT FROM n OR obj.media_type IS DISTINCT FROM media OR obj.cipher_digest IS DISTINCT FROM verivaro_private.digest(obj.envelope,'sha256') THEN RAISE EXCEPTION 'capture conflict' USING ERRCODE='23505';END IF;
  RETURN QUERY SELECT obj.evidence_id,obj.sha256,obj.bytes,prior.link_id;RETURN;
 END IF;
 stage:=verivaro_private.capture_context(t,p,w,v,m);
 IF EXISTS(SELECT 1 FROM verivaro_private.evidence_objects x WHERE x.tenant_id=t AND x.actor_id=c[2]::uuid AND x.request_id=r) THEN RAISE EXCEPTION 'capture request already used' USING ERRCODE='23505';END IF;
 SELECT * INTO stored FROM verivaro_ingestion.commit_upload_v2(t,p,r,e,h,n,k,sealed,media);
 PERFORM verivaro_verification.link_evidence(t,p,v,r,stored.id,h);
 SELECT lead_minutes INTO lead FROM verivaro_private.prooflock_windows x WHERE x.window_id=w;
 INSERT INTO verivaro_private.prooflock_capture_receipts(link_id,tenant_id,project_id,actor_id,request_id,window_id,milestone_revision_id,evidence_id,deadline_at)
 VALUES(r,t,p,c[2]::uuid,r,w,m,stored.id,stage.stage_at-make_interval(mins=>lead));
 RETURN QUERY SELECT stored.id,stored.sha256,stored.bytes,r;
END $capture$;
REVOKE ALL ON FUNCTION verivaro_ingestion.authorize_capture(uuid,uuid,uuid,uuid,uuid,uuid),verivaro_ingestion.commit_capture(uuid,uuid,uuid,uuid,text,integer,text,bytea,text,uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_ingestion.authorize_capture(uuid,uuid,uuid,uuid,uuid,uuid),verivaro_ingestion.commit_capture(uuid,uuid,uuid,uuid,text,integer,text,bytea,text,uuid,uuid,uuid) TO verivaro_evidence_ingestor;
COMMIT;
