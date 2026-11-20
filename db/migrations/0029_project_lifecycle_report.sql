BEGIN;
ALTER TABLE verivaro.projects ADD COLUMN archived_at timestamptz;
CREATE TABLE verivaro_private.project_archive_receipts(
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,actor_id uuid NOT NULL,session_id uuid NOT NULL,request_id uuid NOT NULL,
 expected_revision integer NOT NULL,result_revision integer NOT NULL CHECK(result_revision=expected_revision+1),
 archived_at timestamptz NOT NULL,PRIMARY KEY(tenant_id,actor_id,request_id),UNIQUE(tenant_id,project_id)
);
REVOKE ALL ON verivaro_private.project_archive_receipts FROM PUBLIC;
CREATE TRIGGER project_archive_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.project_archive_receipts FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE FUNCTION verivaro_private.require_open_project(t uuid,p uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $guard$
BEGIN
 PERFORM 1 FROM verivaro.projects q WHERE q.tenant_id=t AND q.id=p AND q.archived_at IS NULL FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'project closed or unavailable' USING ERRCODE='42501';END IF;
END $guard$;
CREATE FUNCTION verivaro_private.guard_project_write() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $guard$
DECLARE t uuid;p uuid;
BEGIN
 IF TG_TABLE_NAME='projects' THEN
  IF OLD.archived_at IS NOT NULL THEN RAISE EXCEPTION 'archived project is immutable' USING ERRCODE='42501';END IF;
  IF TG_OP='DELETE' THEN RETURN OLD;END IF;
  RETURN NEW;
 ELSIF TG_TABLE_NAME='project_members' THEN
  IF TG_OP='UPDATE' AND OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL AND NEW.role=OLD.role AND NEW.expires_at IS NOT DISTINCT FROM OLD.expires_at THEN RETURN NEW;END IF;
  t:=NEW.tenant_id;p:=NEW.project_id;
 ELSIF TG_TABLE_NAME IN ('evidence_release_reviews','evidence_release_receipts') THEN
  SELECT tenant_id,project_id INTO t,p FROM verivaro_private.evidence_release_requests WHERE request_id=NEW.request_id;
 ELSIF TG_TABLE_NAME='share_grants' THEN
  SELECT tenant_id,project_id INTO t,p FROM verivaro_private.released_exports WHERE export_id=NEW.export_id;
 ELSE t:=NEW.tenant_id;p:=NEW.project_id;
 END IF;
 PERFORM verivaro_private.require_open_project(t,p);RETURN NEW;
END $guard$;
REVOKE ALL ON FUNCTION verivaro_private.require_open_project(uuid,uuid),verivaro_private.guard_project_write() FROM PUBLIC;
CREATE TRIGGER archived_project_guard BEFORE UPDATE OR DELETE ON verivaro.projects FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_project_write();
CREATE TRIGGER archive_evidence_guard BEFORE INSERT ON verivaro.evidence FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_project_write();
CREATE TRIGGER archive_member_guard BEFORE INSERT OR UPDATE ON verivaro.project_members FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_project_write();
CREATE TRIGGER archive_request_guard BEFORE INSERT ON verivaro_private.evidence_release_requests FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_project_write();
CREATE TRIGGER archive_review_guard BEFORE INSERT ON verivaro_private.evidence_release_reviews FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_project_write();
CREATE TRIGGER archive_receipt_guard BEFORE INSERT ON verivaro_private.evidence_release_receipts FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_project_write();
CREATE TRIGGER archive_export_guard BEFORE INSERT ON verivaro_private.released_exports FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_project_write();
CREATE TRIGGER archive_share_guard BEFORE INSERT ON verivaro_private.share_grants FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_project_write();
CREATE FUNCTION verivaro_mutation.archive_project(t uuid,p uuid,r uuid,expected integer) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $archive$
DECLARE c text[];q verivaro.projects%ROWTYPE;prior verivaro_private.project_archive_receipts%ROWTYPE;n timestamptz;
BEGIN
 c:=verivaro_private.release_actor(t,p,'owner');
 IF r IS NULL OR expected IS NULL OR expected<0 OR expected>=2147483647 THEN RAISE EXCEPTION 'invalid archive' USING ERRCODE='22023';END IF;
 SELECT * INTO q FROM verivaro.projects WHERE tenant_id=t AND id=p FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'archive denied' USING ERRCODE='42501';END IF;
 PERFORM verivaro_private.release_actor(t,p,'owner');
 SELECT * INTO prior FROM verivaro_private.project_archive_receipts WHERE tenant_id=t AND actor_id=c[2]::uuid AND request_id=r;
 IF FOUND THEN
 IF prior.project_id<>p OR prior.expected_revision<>expected THEN RAISE EXCEPTION 'archive conflict' USING ERRCODE='23505';END IF;
 RETURN jsonb_build_object('revision',prior.result_revision,'archivedAt',prior.archived_at);END IF;
 IF q.archived_at IS NOT NULL OR q.revision<>expected THEN RAISE EXCEPTION 'archive conflict' USING ERRCODE='23505';END IF;
 n:=clock_timestamp();
 UPDATE verivaro.projects SET archived_at=n,revision=revision+1 WHERE tenant_id=t AND id=p;
 WITH changed AS (UPDATE verivaro_private.released_exports SET revoked_at=n WHERE tenant_id=t AND project_id=p AND revoked_at IS NULL RETURNING export_id)
 INSERT INTO verivaro_private.share_events(export_id,action,actor_id) SELECT export_id,'export_revoked',c[2]::uuid FROM changed;
 INSERT INTO verivaro_private.project_archive_receipts VALUES(t,p,c[2]::uuid,c[3]::uuid,r,expected,expected+1,n);
 RETURN jsonb_build_object('revision',expected+1,'archivedAt',n);
END $archive$;
CREATE FUNCTION verivaro_mutation.project_report(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $report$
DECLARE c text[];tr text;pr text;q verivaro.projects%ROWTYPE;items jsonb;reviews jsonb;summary jsonb;
BEGIN
 c:=verivaro.bound_context();
 IF c IS NULL OR t IS NULL OR p IS NULL OR c[1]<>t::text OR NOT verivaro.active_identity() THEN RAISE EXCEPTION 'report denied' USING ERRCODE='42501';END IF;
 SELECT m.role,pm.role INTO tr,pr FROM verivaro.memberships m JOIN verivaro.project_members pm ON pm.tenant_id=m.tenant_id AND pm.actor_id=m.actor_id
 WHERE m.tenant_id=t AND m.actor_id=c[2]::uuid AND pm.project_id=p AND m.revoked_at IS NULL AND pm.revoked_at IS NULL AND (pm.expires_at IS NULL OR pm.expires_at>statement_timestamp());
 IF NOT FOUND OR NOT ((tr='owner' AND pr='owner') OR (tr='reviewer' AND pr='reviewer')) THEN RAISE EXCEPTION 'report denied' USING ERRCODE='42501';END IF;
 SELECT * INTO q FROM verivaro.projects WHERE tenant_id=t AND id=p;
 IF NOT FOUND THEN RAISE EXCEPTION 'report denied' USING ERRCODE='42501';END IF;
 IF (SELECT count(*) FROM verivaro.evidence WHERE tenant_id=t AND project_id=p)>4096 OR (SELECT count(*) FROM verivaro_private.evidence_release_requests WHERE tenant_id=t AND project_id=p)>2048 THEN RAISE EXCEPTION 'report exceeds capacity' USING ERRCODE='54000';END IF;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('id',e.id,'sha256',e.sha256,'registeredAt',e.created_at,'bytes',o.bytes,'mediaType',o.media_type,'scanPolicy',o.scan_policy,'storage',CASE WHEN o.evidence_id IS NULL THEN 'legacy' ELSE 'encrypted' END) ORDER BY e.id),'[]'::jsonb) INTO items
 FROM verivaro.evidence e LEFT JOIN verivaro_private.evidence_objects o ON o.evidence_id=e.id WHERE e.tenant_id=t AND e.project_id=p;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('id',r.request_id,'evidenceId',r.evidence_id,'sha256',r.sha256,'submittedAt',r.created_at,'reviewedAt',v.reviewed_at,'decision',v.decision,'reason',v.reason,'releasedAt',z.released_at,'state',
 CASE WHEN x.revoked_at IS NOT NULL THEN 'revoked' WHEN z.export_id IS NOT NULL THEN 'released' WHEN v.decision='rejected' THEN 'rejected'
 WHEN q.archived_at IS NOT NULL THEN 'closed' WHEN r.created_at<statement_timestamp()-interval '7 days' OR v.reviewed_at<statement_timestamp()-interval '24 hours' THEN 'expired'
 WHEN v.decision='approved' THEN 'approved' ELSE 'pending' END) ORDER BY r.request_id),'[]'::jsonb) INTO reviews
 FROM verivaro_private.evidence_release_requests r LEFT JOIN verivaro_private.evidence_release_reviews v USING(request_id)
 LEFT JOIN verivaro_private.evidence_release_receipts z USING(request_id) LEFT JOIN verivaro_private.released_exports x ON x.export_id=z.export_id WHERE r.tenant_id=t AND r.project_id=p;
 SELECT jsonb_build_object('evidence',jsonb_array_length(items),'encrypted',(SELECT count(*) FROM jsonb_array_elements(items) i WHERE i->>'storage'='encrypted'),
 'bytes',(SELECT COALESCE(sum((i->>'bytes')::bigint),0) FROM jsonb_array_elements(items) i),'requests',jsonb_array_length(reviews),
 'states',COALESCE((SELECT jsonb_object_agg(s,n) FROM (SELECT i->>'state' s,count(*) n FROM jsonb_array_elements(reviews) i GROUP BY 1) counts),'{}'::jsonb)) INTO summary;
 RETURN jsonb_build_object('version',1,'generatedAt',statement_timestamp(),'tenantId',t,'project',jsonb_build_object('id',p,'name',left(q.name,256),'revision',q.revision,'archivedAt',q.archived_at),'summary',summary,'evidence',items,'reviews',reviews,'attestation','unsigned database snapshot; not an independently signed custody checkpoint');
END $report$;
CREATE OR REPLACE FUNCTION verivaro_sharing.preflight_approved_export(t uuid,p uuid,r uuid,e uuid,h text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $publish$
DECLARE c text[];req verivaro_private.evidence_release_requests%ROWTYPE;review verivaro_private.evidence_release_reviews%ROWTYPE;receipt verivaro_private.evidence_release_receipts%ROWTYPE;
BEGIN
 c:=verivaro_private.release_actor(t,p,'owner');
 PERFORM verivaro_private.require_open_project(t,p);
 SELECT * INTO req FROM verivaro_private.evidence_release_requests WHERE request_id=r AND tenant_id=t AND project_id=p FOR UPDATE;
 IF NOT FOUND OR req.evidence_id IS DISTINCT FROM e OR req.sha256 IS DISTINCT FROM h OR req.submitter_id=c[2]::uuid THEN RAISE EXCEPTION 'release denied' USING ERRCODE='42501';END IF;
 SELECT * INTO review FROM verivaro_private.evidence_release_reviews WHERE request_id=r;
 IF NOT FOUND OR review.decision<>'approved' OR review.reviewer_id=c[2]::uuid OR review.reviewer_id=req.submitter_id
 OR req.submitter_generation IS DISTINCT FROM verivaro_private.release_generation(t,p,req.submitter_id,'submitter')
 OR review.reviewer_generation IS DISTINCT FROM verivaro_private.release_generation(t,p,review.reviewer_id,'reviewer')
 OR NOT EXISTS(SELECT 1 FROM verivaro_private.evidence_objects o WHERE o.evidence_id=req.evidence_id AND o.tenant_id=t AND o.project_id=p AND o.sha256=h AND o.cipher_digest=verivaro_private.digest(o.envelope,'sha256'))
 THEN RAISE EXCEPTION 'release denied' USING ERRCODE='42501';END IF;
 SELECT * INTO receipt FROM verivaro_private.evidence_release_receipts WHERE request_id=r;
 IF FOUND THEN
 IF receipt.released_by<>c[2]::uuid OR NOT EXISTS(SELECT 1 FROM verivaro_private.released_exports x WHERE x.export_id=receipt.export_id AND x.revoked_at IS NULL) THEN RAISE EXCEPTION 'release conflict' USING ERRCODE='23505';END IF;
 RETURN true;
 END IF;
 IF review.reviewed_at<clock_timestamp()-interval '24 hours' OR req.created_at<clock_timestamp()-interval '7 days' THEN RAISE EXCEPTION 'release denied' USING ERRCODE='42501';END IF;
 RETURN true;
END $publish$;

CREATE OR REPLACE FUNCTION verivaro_sharing.workspace_issue_recipient(t uuid,p uuid,e uuid,s uuid,d bytea,recipient uuid) RETURNS timestamptz
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $issue$
DECLARE c text[];g verivaro_private.share_grants%ROWTYPE;expires timestamptz;
BEGIN
 c:=verivaro_private.release_actor(t,p,'owner');
 PERFORM verivaro_private.require_open_project(t,p);
 IF s IS NULL OR recipient IS NULL OR recipient=c[2]::uuid OR d IS NULL OR octet_length(d)<>32 THEN RAISE EXCEPTION 'share denied' USING ERRCODE='42501';END IF;
 PERFORM 1 FROM verivaro_private.released_exports x JOIN verivaro_private.evidence_release_receipts z ON x.export_id=z.export_id
 WHERE x.export_id=e AND x.tenant_id=t AND x.project_id=p AND x.revoked_at IS NULL AND NOT x.bearer_allowed FOR UPDATE OF x;
 IF NOT FOUND THEN RAISE EXCEPTION 'share denied' USING ERRCODE='42501';END IF;
 SELECT * INTO g FROM verivaro_private.share_grants WHERE share_id=s;
 IF FOUND THEN
 IF g.export_id<>e OR g.issuer_id<>c[2]::uuid OR g.token_digest<>d OR g.recipient_id IS DISTINCT FROM recipient OR g.revoked_at IS NOT NULL OR g.expires_at<=clock_timestamp()
 OR g.owner_generation IS DISTINCT FROM verivaro_private.share_owner_generation(t,p,c[2]::uuid)
 OR g.recipient_generation IS DISTINCT FROM verivaro_private.recipient_generation(recipient)
 THEN RAISE EXCEPTION 'share conflict' USING ERRCODE='23505';END IF;
 RETURN g.expires_at;END IF;
 IF (SELECT count(*) FROM verivaro_private.share_grants WHERE export_id=e)>=32 THEN RAISE EXCEPTION 'share capacity exhausted' USING ERRCODE='54000';END IF;
 expires:=clock_timestamp()+interval '15 minutes';
 PERFORM verivaro_sharing.issue_recipient_share(e,s,d,expires,recipient);
 RETURN expires;
END $issue$;
CREATE OR REPLACE FUNCTION verivaro_ingestion.authorize_upload(t uuid,p uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $auth$
BEGIN PERFORM verivaro_private.check_ingest_scope(t,p);PERFORM verivaro_private.require_open_project(t,p);RETURN true;END $auth$;

REVOKE ALL ON FUNCTION verivaro_mutation.archive_project(uuid,uuid,uuid,integer),verivaro_mutation.project_report(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_mutation.archive_project(uuid,uuid,uuid,integer),verivaro_mutation.project_report(uuid,uuid) TO verivaro_runtime;
COMMIT;
