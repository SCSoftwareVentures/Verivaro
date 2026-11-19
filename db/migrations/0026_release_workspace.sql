BEGIN;
CREATE FUNCTION verivaro_sharing.workspace_tenants() RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $tenants$
DECLARE c text[];
BEGIN
 c:=verivaro.bound_context();
 IF c IS NULL OR c[1]<>'00000000-0000-0000-0000-000000000000' OR EXISTS(SELECT 1 FROM verivaro_private.disabled_actors WHERE actor_id=c[2]::uuid)
 THEN RAISE EXCEPTION 'workspace denied' USING ERRCODE='42501';END IF;
 RETURN COALESCE((SELECT jsonb_agg(to_jsonb(q) ORDER BY q.id) FROM (
 SELECT t.id,left(t.name,256) AS name,m.role FROM verivaro.tenants t JOIN verivaro.memberships m ON m.tenant_id=t.id
 WHERE m.actor_id=c[2]::uuid AND m.revoked_at IS NULL ORDER BY t.id LIMIT 200) q),'[]'::jsonb);
END $tenants$;
CREATE FUNCTION verivaro_sharing.release_workspace(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $workspace$
DECLARE c text[];a uuid;tr text;pr text;
BEGIN
 c:=verivaro.bound_context();
 IF c IS NULL OR t IS NULL OR p IS NULL OR c[1]<>t::text THEN RAISE EXCEPTION 'workspace denied' USING ERRCODE='42501'; END IF;
 a:=c[2]::uuid;
 SELECT m.role,pm.role INTO tr,pr FROM verivaro.memberships m JOIN verivaro.project_members pm ON pm.tenant_id=m.tenant_id AND pm.actor_id=m.actor_id
 WHERE m.tenant_id=t AND m.actor_id=a AND pm.project_id=p AND m.revoked_at IS NULL AND pm.revoked_at IS NULL
 AND (pm.expires_at IS NULL OR pm.expires_at>statement_timestamp()) AND NOT EXISTS(SELECT 1 FROM verivaro_private.disabled_actors WHERE actor_id=a);
 IF NOT FOUND THEN RAISE EXCEPTION 'workspace denied' USING ERRCODE='42501'; END IF;
 RETURN jsonb_build_object('tenantRole',tr,'projectRole',pr,
 'evidence',COALESCE((SELECT jsonb_agg(to_jsonb(q) ORDER BY q.id) FROM (
 SELECT o.evidence_id AS id,o.sha256,o.bytes,o.media_type AS "mediaType",(o.actor_id=a AND tr IN ('owner','reviewer','contributor') AND pr IN ('owner','reviewer','contributor')) AS "canSubmit"
 FROM verivaro_private.evidence_objects o WHERE o.tenant_id=t AND o.project_id=p ORDER BY o.evidence_id LIMIT 200) q),'[]'::jsonb),
 'requests',COALESCE((SELECT jsonb_agg(to_jsonb(q) ORDER BY q."createdAt" DESC,q.id) FROM (
 SELECT r.request_id AS id,r.evidence_id AS "evidenceId",r.sha256,r.created_at AS "createdAt",
 CASE WHEN x.revoked_at IS NOT NULL THEN 'revoked' WHEN z.export_id IS NOT NULL THEN 'released'
 WHEN v.decision='rejected' THEN 'rejected' WHEN r.created_at<statement_timestamp()-interval '7 days' OR v.reviewed_at<statement_timestamp()-interval '24 hours' THEN 'expired'
 WHEN v.decision='approved' THEN 'approved' ELSE 'pending' END AS state,v.reason,z.export_id AS "exportId",
 (v.request_id IS NULL AND r.submitter_id<>a AND tr='reviewer' AND pr='reviewer' AND r.created_at>=statement_timestamp()-interval '7 days') AS "canReview",
 (v.decision='approved' AND z.request_id IS NULL AND r.submitter_id<>a AND v.reviewer_id<>a AND tr='owner' AND pr='owner' AND r.created_at>=statement_timestamp()-interval '7 days' AND v.reviewed_at>=statement_timestamp()-interval '24 hours') IS TRUE AS "canPublish"
 FROM verivaro_private.evidence_release_requests r
 LEFT JOIN verivaro_private.evidence_release_reviews v USING(request_id)
 LEFT JOIN verivaro_private.evidence_release_receipts z USING(request_id)
 LEFT JOIN verivaro_private.released_exports x ON x.export_id=z.export_id
 WHERE r.tenant_id=t AND r.project_id=p AND (r.submitter_id=a OR (tr='reviewer' AND pr='reviewer') OR (tr='owner' AND pr='owner'))
 ORDER BY r.created_at DESC,r.request_id LIMIT 200) q),'[]'::jsonb));
END $workspace$;
CREATE FUNCTION verivaro_sharing.preflight_approved_export(t uuid,p uuid,r uuid,e uuid,h text) RETURNS boolean
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
 RETURN true;
 END IF;
 IF review.reviewed_at<clock_timestamp()-interval '24 hours' OR req.created_at<clock_timestamp()-interval '7 days' THEN RAISE EXCEPTION 'release denied' USING ERRCODE='42501';END IF;
 RETURN true;
END $publish$;

REVOKE ALL ON FUNCTION verivaro_sharing.workspace_tenants(),verivaro_sharing.release_workspace(uuid,uuid),verivaro_sharing.preflight_approved_export(uuid,uuid,uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_sharing.workspace_tenants(),verivaro_sharing.release_workspace(uuid,uuid) TO verivaro_runtime;
GRANT EXECUTE ON FUNCTION verivaro_sharing.preflight_approved_export(uuid,uuid,uuid,uuid,text) TO verivaro_release_service;
COMMIT;
