BEGIN;
CREATE ROLE verivaro_signer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
SET LOCAL ROLE verivaro_owner;
CREATE SCHEMA vv_api AUTHORIZATION verivaro_owner;
REVOKE ALL ON SCHEMA vv_api FROM PUBLIC;
GRANT USAGE ON SCHEMA vv_api TO verivaro_runtime,verivaro_signer;
-- Trusted identity gateway only. It must verify the OIDC JWT before passing issuer/subject.
-- Runtime and signer must be distinct database login identities in any deployment.
CREATE FUNCTION vv_api.issue_context(p_issuer text,p_subject text,p_tenant uuid,p_project uuid,p_tx text,p_key uuid,p_token_exp bigint)
RETURNS TABLE(context text,signature text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_crypto AS $$
DECLARE a uuid; mv integer; pv integer; k bytea; raw text; n bigint;
BEGIN
 n:=floor(extract(epoch FROM statement_timestamp()))::bigint;
 IF p_issuer IS NULL OR length(p_issuer) NOT BETWEEN 1 AND 512 OR p_subject IS NULL OR length(p_subject) NOT BETWEEN 1 AND 512 OR p_tx IS NULL OR p_tx !~ '^[1-9][0-9]{0,19}$' OR p_token_exp IS NULL OR p_token_exp<=n THEN
 RAISE EXCEPTION 'context denied' USING ERRCODE='42501'; END IF;
 SELECT i.id,m.version,p.version INTO a,mv,pv
 FROM vv_private.identity i JOIN vv_private.membership m ON m.actor_id=i.id
 JOIN vv_private.project_member p ON p.tenant_id=m.tenant_id AND p.actor_id=m.actor_id
 WHERE i.issuer=p_issuer AND i.subject=p_subject AND m.tenant_id=p_tenant AND p.project_id=p_project AND m.active AND p.active;
 SELECT secret INTO k FROM vv_private.context_key WHERE id=p_key AND active;
 IF a IS NULL OR k IS NULL THEN RAISE EXCEPTION 'context denied' USING ERRCODE='42501'; END IF;
 raw:=jsonb_build_object('tenant',p_tenant,'project',p_project,'actor',a,'tx',p_tx,'key',p_key,'exp',least(p_token_exp,n+60),'member_version',mv,'project_version',pv)::text;
 RETURN QUERY SELECT raw,encode(vv_crypto.hmac(convert_to(raw,'UTF8'),k,'sha256'),'hex');
END $$;
REVOKE ALL ON FUNCTION vv_api.issue_context(text,text,uuid,uuid,text,uuid,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vv_api.issue_context(text,text,uuid,uuid,text,uuid,bigint) TO verivaro_signer;
-- Scoped ingestion intent is metadata only. It never claims storage bytes have arrived.
CREATE TABLE vv_app.upload_intent (
 tenant_id uuid NOT NULL, project_id uuid NOT NULL, id uuid NOT NULL,
 document_id uuid NOT NULL, expected_sha256 text NOT NULL CHECK(expected_sha256 ~ '^[0-9a-f]{64}$'),
 expected_bytes bigint NOT NULL CHECK(expected_bytes BETWEEN 1 AND 52428800),
 media_type text NOT NULL CHECK(media_type IN ('application/pdf','image/jpeg','image/png','text/plain')),
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending')),
 created_by uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,document_id) REFERENCES vv_app.document(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,created_by) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id)
);
ALTER TABLE vv_app.upload_intent ENABLE ROW LEVEL SECURITY;
ALTER TABLE vv_app.upload_intent FORCE ROW LEVEL SECURITY;
CREATE POLICY owner_only ON vv_app.upload_intent TO verivaro_owner USING(true) WITH CHECK(true);
-- Derive the actor from the verified claim; cannot accept an actor from the caller.
CREATE FUNCTION vv_private.capture_actor(t uuid,p uuid) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,vv_private AS $$
DECLARE a uuid; r text;
BEGIN
 IF NOT vv_private.allowed_project(t,p) THEN RAISE EXCEPTION 'action denied' USING ERRCODE='42501'; END IF;
 a:=(current_setting('verivaro.context',true)::jsonb->>'actor')::uuid;
 -- Lock membership rows until commit so revocation cannot race a write.
 SELECT pm.role INTO r FROM vv_private.project_member pm JOIN vv_private.membership m ON m.tenant_id=pm.tenant_id AND m.actor_id=pm.actor_id
 WHERE pm.tenant_id=t AND pm.project_id=p AND pm.actor_id=a AND pm.active AND m.active FOR SHARE OF pm,m;
 IF r IS NULL OR r NOT IN ('owner','manager','reviewer','contributor') OR NOT vv_private.allowed_project(t,p) THEN
 RAISE EXCEPTION 'action denied' USING ERRCODE='42501'; END IF;
 RETURN a;
END $$;
REVOKE ALL ON FUNCTION vv_private.capture_actor(uuid,uuid) FROM PUBLIC;
CREATE FUNCTION vv_api.create_document(t uuid,p uuid,d uuid,doc_title text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid; existing vv_app.document%ROWTYPE;
BEGIN
 a:=vv_private.capture_actor(t,p);
 IF d IS NULL OR doc_title IS NULL OR length(trim(doc_title)) NOT BETWEEN 1 AND 250 THEN RAISE EXCEPTION 'invalid document' USING ERRCODE='22023'; END IF;
 INSERT INTO vv_app.document(tenant_id,project_id,id,title,created_by) VALUES(t,p,d,doc_title,a) ON CONFLICT DO NOTHING;
 SELECT * INTO existing FROM vv_app.document WHERE tenant_id=t AND project_id=p AND id=d;
 IF existing.id IS NULL OR existing.created_by IS DISTINCT FROM a OR existing.title IS DISTINCT FROM doc_title THEN
 RAISE EXCEPTION 'idempotency conflict' USING ERRCODE='23505'; END IF;
 RETURN d;
END $$;
CREATE FUNCTION vv_api.request_upload(t uuid,p uuid,d uuid,u uuid,sha text,bytes bigint,mime text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid; existing vv_app.upload_intent%ROWTYPE;
BEGIN
 a:=vv_private.capture_actor(t,p);
 IF u IS NULL OR d IS NULL OR sha IS NULL OR sha !~ '^[0-9a-f]{64}$' OR bytes IS NULL OR bytes NOT BETWEEN 1 AND 52428800 OR mime IS NULL OR mime NOT IN ('application/pdf','image/jpeg','image/png','text/plain') THEN RAISE EXCEPTION 'invalid upload intent' USING ERRCODE='22023'; END IF;
 IF NOT EXISTS(SELECT 1 FROM vv_app.document WHERE tenant_id=t AND project_id=p AND id=d) THEN RAISE EXCEPTION 'document unavailable' USING ERRCODE='42501'; END IF;
 INSERT INTO vv_app.upload_intent(tenant_id,project_id,id,document_id,expected_sha256,expected_bytes,media_type,created_by)
 VALUES(t,p,u,d,sha,bytes,mime,a) ON CONFLICT DO NOTHING;
 SELECT * INTO existing FROM vv_app.upload_intent WHERE tenant_id=t AND project_id=p AND id=u;
 IF existing.id IS NULL OR existing.created_by IS DISTINCT FROM a OR existing.document_id IS DISTINCT FROM d OR existing.expected_sha256 IS DISTINCT FROM sha OR existing.expected_bytes IS DISTINCT FROM bytes OR existing.media_type IS DISTINCT FROM mime THEN RAISE EXCEPTION 'idempotency conflict' USING ERRCODE='23505'; END IF;
 RETURN u;
END $$;
REVOKE ALL ON FUNCTION vv_api.create_document(uuid,uuid,uuid,text),vv_api.request_upload(uuid,uuid,uuid,uuid,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vv_api.create_document(uuid,uuid,uuid,text),vv_api.request_upload(uuid,uuid,uuid,uuid,text,bigint,text) TO verivaro_runtime;
RESET ROLE;
COMMIT;
