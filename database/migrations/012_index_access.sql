BEGIN;
SET LOCAL ROLE verivaro_owner;
CREATE TABLE vv_app.index_release(
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,id uuid NOT NULL,draft_id uuid NOT NULL,
 generation bigint NOT NULL,payload text NOT NULL CHECK(octet_length(payload)<=1048576),
 sha256 text NOT NULL CHECK(sha256=encode(vv_crypto.digest(convert_to(payload,'UTF8'),'sha256'),'hex')),
 approved_by uuid NOT NULL,approved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,project_id,id),UNIQUE(id),
 FOREIGN KEY(tenant_id,project_id,draft_id) REFERENCES vv_app.handover_draft(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,approved_by) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id)
);
CREATE TABLE vv_private.index_grant(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,project_id uuid NOT NULL,release_id uuid NOT NULL,
 token_hash text NOT NULL UNIQUE CHECK(token_hash~'^[0-9a-f]{64}$'),expires_at timestamptz NOT NULL,
 created_by uuid NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 revoked_at timestamptz,revoked_by uuid,
 FOREIGN KEY(tenant_id,project_id,release_id) REFERENCES vv_app.index_release(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,created_by) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id),
 FOREIGN KEY(tenant_id,project_id,revoked_by) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id),
 CHECK((revoked_at IS NULL)=(revoked_by IS NULL))
);
DO $$ DECLARE rel regclass;BEGIN
 FOREACH rel IN ARRAY ARRAY['vv_app.index_release'::regclass,'vv_private.index_grant'::regclass] LOOP
 EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY',rel);EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY',rel);EXECUTE format('CREATE POLICY owner_only ON %s TO verivaro_owner USING(true) WITH CHECK(true)',rel);END LOOP;
END $$;
CREATE FUNCTION vv_private.release_owner(t uuid,p uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private AS $$
DECLARE a uuid;BEGIN a:=vv_private.graph_lock(t,p);
 IF NOT EXISTS(SELECT 1 FROM vv_private.project_member WHERE tenant_id=t AND project_id=p AND actor_id=a AND role='owner' AND active) THEN RAISE EXCEPTION 'owner required' USING ERRCODE='42501';END IF;
 RETURN a;
END $$;
-- An owner releases only an explicitly selected metadata index, not source text, evidence excerpts,
-- internal findings, legal readiness, financial details or original file bytes.
CREATE FUNCTION vv_api.approve_index(t uuid,p uuid,h uuid,r uuid,expected_generation bigint,selected uuid[]) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app,vv_crypto AS $$
DECLARE a uuid;d vv_app.handover_draft%ROWTYPE;g bigint;cg bigint;w jsonb;items jsonb;body text;old vv_app.index_release%ROWTYPE;
BEGIN a:=vv_private.release_owner(t,p);
 IF r IS NULL OR expected_generation IS NULL OR selected IS NULL OR cardinality(selected) NOT BETWEEN 1 AND 200 OR array_position(selected,NULL) IS NOT NULL OR cardinality(selected)<>(SELECT count(DISTINCT x) FROM unnest(selected) x) THEN RAISE EXCEPTION 'invalid selection' USING ERRCODE='22023';END IF;
 SELECT * INTO d FROM vv_app.handover_draft WHERE tenant_id=t AND project_id=p AND id=h;
 SELECT generation,confirmed_generation INTO g,cg FROM vv_app.scope_checkpoint WHERE tenant_id=t AND project_id=p;
 IF d.id IS NULL THEN RAISE EXCEPTION 'draft unavailable' USING ERRCODE='42501';END IF;
 IF g IS DISTINCT FROM expected_generation OR cg IS DISTINCT FROM g OR d.generation<>g OR NOT d.scope_confirmed THEN RAISE EXCEPTION 'current confirmed draft required' USING ERRCODE='23505';END IF;
 w:=d.payload::jsonb;
 SELECT coalesce(jsonb_agg(jsonb_build_object('documentVersionId',s->>'id','revision',(s->>'revision')::integer,'originalSha256',l->>'originalSha256','textSha256',l->>'textSha256','pageCount',jsonb_array_length(l->'pages')) ORDER BY s->>'id'),'[]'::jsonb) INTO items
 FROM jsonb_array_elements(w->'graph'->'sources') s JOIN jsonb_array_elements(w->'lineage') l ON l->>'id'=s->>'id'
 WHERE (s->>'id')::uuid=ANY(selected) AND (s->>'current')::boolean AND (s->>'reviewed')::boolean AND s->>'scan'='clean';
 IF jsonb_array_length(items)<>cardinality(selected) THEN RAISE EXCEPTION 'selection unavailable' USING ERRCODE='42501';END IF;
 body:=jsonb_build_object('schema','verivaro-selected-document-index-v1','releaseId',r,'draftId',h,'generation',g::text,'documents',items,'label','Approved selected document metadata only; not a released handover package, verification of authenticity, compliance or payment entitlement.')::text;
 SELECT * INTO old FROM vv_app.index_release WHERE tenant_id=t AND project_id=p AND id=r;
 IF FOUND THEN IF old.payload=body AND old.approved_by=a THEN RETURN r;END IF;RAISE EXCEPTION 'release conflict' USING ERRCODE='23505';END IF;
 IF (SELECT count(*) FROM vv_app.index_release WHERE tenant_id=t AND project_id=p)>=100 THEN RAISE EXCEPTION 'release quota' USING ERRCODE='54000';END IF;
 INSERT INTO vv_app.index_release(tenant_id,project_id,id,draft_id,generation,payload,sha256,approved_by)
 VALUES(t,p,r,h,g,body,encode(vv_crypto.digest(convert_to(body,'UTF8'),'sha256'),'hex'),a);
 RETURN r;
END $$;
CREATE FUNCTION vv_api.grant_index(t uuid,p uuid,r uuid,i uuid,secret_digest text,ttl integer) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;
BEGIN a:=vv_private.release_owner(t,p);
 IF i IS NULL OR secret_digest IS NULL OR secret_digest!~'^[0-9a-f]{64}$' OR ttl IS NULL OR ttl NOT BETWEEN 60 AND 604800 THEN RAISE EXCEPTION 'invalid grant' USING ERRCODE='22023';END IF;
 IF NOT EXISTS(SELECT 1 FROM vv_app.index_release r0 JOIN vv_app.scope_checkpoint g ON (g.tenant_id,g.project_id)=(r0.tenant_id,r0.project_id)
 WHERE r0.tenant_id=t AND r0.project_id=p AND r0.id=r AND g.generation=r0.generation AND g.confirmed_generation=g.generation) THEN RAISE EXCEPTION 'release unavailable' USING ERRCODE='42501';END IF;
 IF (SELECT count(*) FROM vv_private.index_grant WHERE tenant_id=t AND project_id=p)>=500 THEN RAISE EXCEPTION 'grant quota' USING ERRCODE='54000';END IF;
 INSERT INTO vv_private.index_grant(id,tenant_id,project_id,release_id,token_hash,expires_at,created_by)
 VALUES(i,t,p,r,secret_digest,clock_timestamp()+make_interval(secs=>ttl),a);
 RETURN i;
END $$;
CREATE FUNCTION vv_api.revoke_index(t uuid,p uuid,i uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private AS $$
DECLARE a uuid;BEGIN a:=vv_private.release_owner(t,p);
 IF NOT EXISTS(SELECT 1 FROM vv_private.index_grant WHERE tenant_id=t AND project_id=p AND id=i) THEN RAISE EXCEPTION 'grant unavailable' USING ERRCODE='42501';END IF;
 UPDATE vv_private.index_grant SET revoked_at=clock_timestamp(),revoked_by=a WHERE tenant_id=t AND project_id=p AND id=i AND revoked_at IS NULL;
 RETURN i;
END $$;
-- Capability access is limited to one immutable allowlisted index, with no project-context privileges.
CREATE FUNCTION vv_api.read_shared_index(r uuid,secret_digest text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE out jsonb;
BEGIN
 IF secret_digest IS NULL OR secret_digest!~'^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'index unavailable' USING ERRCODE='42501';END IF;
 SELECT jsonb_build_object('json',rel.payload,'sha256',rel.sha256,'approvedSelectedIndex',true) INTO out
 FROM vv_private.index_grant gr JOIN vv_app.index_release rel ON (rel.tenant_id,rel.project_id,rel.id)=(gr.tenant_id,gr.project_id,gr.release_id)
 JOIN vv_app.scope_checkpoint g ON (g.tenant_id,g.project_id)=(rel.tenant_id,rel.project_id)
 WHERE gr.token_hash=secret_digest AND gr.release_id=r AND gr.revoked_at IS NULL AND gr.expires_at>clock_timestamp()
 AND g.generation=rel.generation AND g.confirmed_generation=g.generation;
 IF out IS NULL THEN RAISE EXCEPTION 'index unavailable' USING ERRCODE='42501';END IF;
 RETURN out;
END $$;
REVOKE ALL ON FUNCTION vv_private.release_owner(uuid,uuid),vv_api.approve_index(uuid,uuid,uuid,uuid,bigint,uuid[]),vv_api.grant_index(uuid,uuid,uuid,uuid,text,integer),vv_api.revoke_index(uuid,uuid,uuid),vv_api.read_shared_index(uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vv_api.approve_index(uuid,uuid,uuid,uuid,bigint,uuid[]),vv_api.grant_index(uuid,uuid,uuid,uuid,text,integer),vv_api.revoke_index(uuid,uuid,uuid),vv_api.read_shared_index(uuid,text) TO verivaro_runtime;
RESET ROLE;
COMMIT;
