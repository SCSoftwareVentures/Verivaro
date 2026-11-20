BEGIN;
CREATE TABLE verivaro_private.evidence_release_requests(
 request_id uuid PRIMARY KEY,evidence_id uuid NOT NULL REFERENCES verivaro_private.evidence_objects(evidence_id),
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,sha256 text NOT NULL CHECK(sha256~'^[0-9a-f]{64}$'),
 submitter_id uuid NOT NULL,session_id uuid NOT NULL,submitter_generation uuid[] NOT NULL CHECK(cardinality(submitter_generation)=3 AND array_position(submitter_generation,NULL) IS NULL),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE verivaro_private.evidence_release_reviews(
 request_id uuid PRIMARY KEY REFERENCES verivaro_private.evidence_release_requests(request_id),
 reviewer_id uuid NOT NULL,session_id uuid NOT NULL,reviewer_generation uuid[] NOT NULL CHECK(cardinality(reviewer_generation)=3 AND array_position(reviewer_generation,NULL) IS NULL),
 decision text NOT NULL CHECK(decision IN ('approved','rejected')),
 reason text NOT NULL CHECK(reason IN ('verified','integrity_concern','insufficient_evidence','policy_denied')),
 reviewed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK((decision='approved')=(reason='verified'))
);
CREATE TABLE verivaro_private.evidence_release_receipts(
 request_id uuid PRIMARY KEY REFERENCES verivaro_private.evidence_release_reviews(request_id),
 export_id uuid NOT NULL UNIQUE REFERENCES verivaro_private.released_exports(export_id),
 released_by uuid NOT NULL,session_id uuid NOT NULL,release_login name NOT NULL DEFAULT session_user,
 released_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON verivaro_private.evidence_release_requests,verivaro_private.evidence_release_reviews,verivaro_private.evidence_release_receipts FROM PUBLIC;
CREATE TRIGGER evidence_release_request_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.evidence_release_requests FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER evidence_release_review_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.evidence_release_reviews FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER evidence_release_receipt_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.evidence_release_receipts FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
-- Disable pre-workflow exports: prior approvals cannot be inferred.
WITH revoked AS (UPDATE verivaro_private.released_exports SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL RETURNING export_id)
INSERT INTO verivaro_private.share_events(export_id,action) SELECT export_id,'export_revoked' FROM revoked;
REVOKE EXECUTE ON FUNCTION verivaro_sharing.register_export(uuid,uuid,uuid,uuid,text,boolean) FROM verivaro_release_service;
-- Lock membership rows and identity lifecycle when checking permission.
CREATE FUNCTION verivaro_private.release_generation(t uuid,p uuid,a uuid,required text) RETURNS uuid[]
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $generation$
DECLARE tg uuid;pg uuid;ag uuid;
BEGIN
 PERFORM verivaro_private.lock_identity(a);
 SELECT m.share_generation INTO tg FROM verivaro.memberships m WHERE m.tenant_id=t AND m.actor_id=a AND m.revoked_at IS NULL
 AND (m.role=required OR (required='submitter' AND m.role IN ('owner','contributor','reviewer'))) FOR SHARE;
 IF NOT FOUND THEN RETURN NULL;END IF;
 SELECT m.share_generation INTO pg FROM verivaro.project_members m WHERE m.tenant_id=t AND m.project_id=p AND m.actor_id=a AND m.revoked_at IS NULL
 AND (m.expires_at IS NULL OR m.expires_at>clock_timestamp())
 AND (m.role=required OR (required='submitter' AND m.role IN ('owner','contributor','reviewer'))) FOR SHARE;
 IF NOT FOUND OR EXISTS(SELECT 1 FROM verivaro_private.disabled_actors WHERE actor_id=a) THEN RETURN NULL;END IF;
 SELECT generation INTO ag FROM verivaro_private.actor_share_generations WHERE actor_id=a;
 RETURN ARRAY[tg,pg,COALESCE(ag,'00000000-0000-0000-0000-000000000000'::uuid)];
END $generation$;
CREATE FUNCTION verivaro_private.release_actor(t uuid,p uuid,required text) RETURNS text[]
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $actor$
DECLARE c text[];
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR t IS NULL OR p IS NULL THEN RAISE EXCEPTION 'release denied' USING ERRCODE='42501';END IF;
 c:=verivaro.bound_context();
 IF c IS NULL OR c[1]<>t::text OR verivaro_private.release_generation(t,p,c[2]::uuid,required) IS NULL
 OR NOT EXISTS(SELECT 1 FROM verivaro_private.identity_sessions i WHERE i.session_id=c[3]::uuid AND i.actor_id=c[2]::uuid AND i.revoked_at IS NULL AND i.expires_at>clock_timestamp())
 THEN RAISE EXCEPTION 'release denied' USING ERRCODE='42501';END IF;
 RETURN c;
END $actor$;
REVOKE ALL ON FUNCTION verivaro_private.release_generation(uuid,uuid,uuid,text),verivaro_private.release_actor(uuid,uuid,text) FROM PUBLIC;
CREATE FUNCTION verivaro_sharing.request_evidence_release(t uuid,p uuid,e uuid,r uuid,h text) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $request$
DECLARE c text[];prior verivaro_private.evidence_release_requests%ROWTYPE;g uuid[];
BEGIN
 c:=verivaro_private.release_actor(t,p,'submitter');
 IF r IS NULL OR h IS NULL OR NOT EXISTS(SELECT 1 FROM verivaro_private.evidence_objects o WHERE o.evidence_id=e AND o.tenant_id=t AND o.project_id=p AND o.actor_id=c[2]::uuid AND o.sha256=h)
 THEN RAISE EXCEPTION 'release denied' USING ERRCODE='42501';END IF;
 g:=verivaro_private.release_generation(t,p,c[2]::uuid,'submitter');
 SELECT * INTO prior FROM verivaro_private.evidence_release_requests WHERE request_id=r;
 IF FOUND THEN
 IF prior.tenant_id<>t OR prior.project_id<>p OR prior.evidence_id<>e OR prior.submitter_id<>c[2]::uuid OR prior.sha256<>h OR prior.submitter_generation IS DISTINCT FROM g
 THEN RAISE EXCEPTION 'release conflict' USING ERRCODE='23505';END IF;
 RETURN r;
 END IF;
 PERFORM pg_advisory_xact_lock(740129816154::bigint);
 IF (SELECT count(*) FROM verivaro_private.evidence_release_requests)>=16384 OR (SELECT count(*) FROM verivaro_private.evidence_release_requests WHERE evidence_id=e)>=8 THEN RAISE EXCEPTION 'review capacity exhausted' USING ERRCODE='54000';END IF;
 INSERT INTO verivaro_private.evidence_release_requests(request_id,evidence_id,tenant_id,project_id,sha256,submitter_id,session_id,submitter_generation)
 VALUES(r,e,t,p,h,c[2]::uuid,c[3]::uuid,g);
 RETURN r;
END $request$;
CREATE FUNCTION verivaro_sharing.review_evidence_release(t uuid,p uuid,r uuid,h text,d text,why text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $review$
DECLARE c text[];req verivaro_private.evidence_release_requests%ROWTYPE;prior verivaro_private.evidence_release_reviews%ROWTYPE;g uuid[];
BEGIN
 c:=verivaro_private.release_actor(t,p,'reviewer');
 SELECT * INTO req FROM verivaro_private.evidence_release_requests WHERE request_id=r AND tenant_id=t AND project_id=p FOR UPDATE;
 IF NOT FOUND OR req.submitter_id=c[2]::uuid OR req.sha256 IS DISTINCT FROM h OR d IS NULL OR why IS NULL
 OR d NOT IN ('approved','rejected') OR why NOT IN ('verified','integrity_concern','insufficient_evidence','policy_denied') OR (d='approved')<>(why='verified')
 THEN RAISE EXCEPTION 'review denied' USING ERRCODE='42501';END IF;
 g:=verivaro_private.release_generation(t,p,c[2]::uuid,'reviewer');
 SELECT * INTO prior FROM verivaro_private.evidence_release_reviews WHERE request_id=r;
 IF FOUND THEN
 IF prior.reviewer_id<>c[2]::uuid OR prior.decision<>d OR prior.reason<>why OR prior.reviewer_generation IS DISTINCT FROM g THEN RAISE EXCEPTION 'review conflict' USING ERRCODE='23505';END IF;
 RETURN true;
 END IF;
 IF req.created_at<clock_timestamp()-interval '7 days' OR req.submitter_generation IS DISTINCT FROM verivaro_private.release_generation(t,p,req.submitter_id,'submitter')
 THEN RAISE EXCEPTION 'review denied' USING ERRCODE='42501';END IF;
 INSERT INTO verivaro_private.evidence_release_reviews(request_id,reviewer_id,session_id,reviewer_generation,decision,reason) VALUES(r,c[2]::uuid,c[3]::uuid,g,d,why);
 RETURN true;
END $review$;
CREATE FUNCTION verivaro_sharing.register_approved_export(t uuid,p uuid,r uuid,e uuid,h text) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $publish$
DECLARE c text[];req verivaro_private.evidence_release_requests%ROWTYPE;review verivaro_private.evidence_release_reviews%ROWTYPE;receipt verivaro_private.evidence_release_receipts%ROWTYPE;
BEGIN
 c:=verivaro_private.release_actor(t,p,'owner');
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
 RETURN receipt.export_id;
 END IF;
 IF review.reviewed_at<clock_timestamp()-interval '24 hours' OR req.created_at<clock_timestamp()-interval '7 days' THEN RAISE EXCEPTION 'release denied' USING ERRCODE='42501';END IF;
 -- Only exact approved bytes, never arbitrary artifacts or bearer access.
 INSERT INTO verivaro_private.released_exports(export_id,tenant_id,project_id,artifact_id,sha256,bearer_allowed) VALUES(r,t,p,req.evidence_id,h,false);
 INSERT INTO verivaro_private.evidence_release_receipts(request_id,export_id,released_by,session_id) VALUES(r,r,c[2]::uuid,c[3]::uuid);
 RETURN r;
END $publish$;
REVOKE ALL ON FUNCTION verivaro_sharing.request_evidence_release(uuid,uuid,uuid,uuid,text),verivaro_sharing.review_evidence_release(uuid,uuid,uuid,text,text,text),verivaro_sharing.register_approved_export(uuid,uuid,uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_sharing.request_evidence_release(uuid,uuid,uuid,uuid,text),verivaro_sharing.review_evidence_release(uuid,uuid,uuid,text,text,text) TO verivaro_runtime;
GRANT EXECUTE ON FUNCTION verivaro_sharing.register_approved_export(uuid,uuid,uuid,uuid,text) TO verivaro_release_service;
COMMIT;
