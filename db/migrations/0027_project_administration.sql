BEGIN;
CREATE TABLE verivaro_private.project_admin_events(
 tenant_id uuid NOT NULL,actor_id uuid NOT NULL,request_id uuid NOT NULL,session_id uuid NOT NULL,
 project_id uuid NOT NULL,operation text NOT NULL CHECK(operation IN ('create','assign','revoke')),
 target_id uuid,request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 previous_generation uuid,result_generation uuid,previous_role text,result_role text,
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,actor_id,request_id)
);
REVOKE ALL ON verivaro_private.project_admin_events FROM PUBLIC;
CREATE TRIGGER project_admin_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.project_admin_events FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE FUNCTION verivaro_private.project_admin_actor(t uuid) RETURNS text[]
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $actor$
DECLARE c text[];
BEGIN
 c:=verivaro.bound_context();
 IF current_setting('transaction_isolation')<>'read committed' OR t IS NULL OR c IS NULL OR c[1]<>t::text THEN RAISE EXCEPTION 'administration denied' USING ERRCODE='42501';END IF;
 PERFORM verivaro_private.lock_identity(c[2]::uuid);
 PERFORM 1 FROM verivaro.memberships m WHERE m.tenant_id=t AND m.actor_id=c[2]::uuid AND m.role='owner' AND m.revoked_at IS NULL FOR SHARE;
 IF NOT FOUND OR EXISTS(SELECT 1 FROM verivaro_private.disabled_actors WHERE actor_id=c[2]::uuid)
 OR NOT EXISTS(SELECT 1 FROM verivaro_private.identity_sessions i WHERE i.actor_id=c[2]::uuid AND i.session_id=c[3]::uuid AND i.revoked_at IS NULL AND i.expires_at>clock_timestamp()) THEN RAISE EXCEPTION 'administration denied' USING ERRCODE='42501';END IF;
 RETURN c;
END $actor$;
REVOKE ALL ON FUNCTION verivaro_private.project_admin_actor(uuid) FROM PUBLIC;
CREATE FUNCTION verivaro_mutation.create_project(t uuid,r uuid,n text) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $create$
DECLARE c text[];d bytea;prior verivaro_private.project_admin_events%ROWTYPE;p uuid;
BEGIN
 c:=verivaro_private.project_admin_actor(t);
 IF r IS NULL OR n IS NULL OR char_length(n) NOT BETWEEN 1 AND 128 OR octet_length(n)>512 OR n<>btrim(n) OR n~'[[:cntrl:]]' THEN RAISE EXCEPTION 'invalid project' USING ERRCODE='22023';END IF;
 d:=verivaro_private.digest(convert_to(jsonb_build_array('create',n)::text,'UTF8'),'sha256');
 SELECT * INTO prior FROM verivaro_private.project_admin_events e WHERE e.tenant_id=t AND e.actor_id=c[2]::uuid AND e.request_id=r;
 IF FOUND THEN
 IF prior.request_digest<>d OR prior.operation<>'create' THEN RAISE EXCEPTION 'administration conflict' USING ERRCODE='23505';END IF;
 IF verivaro_private.release_generation(t,prior.project_id,c[2]::uuid,'owner') IS NULL THEN RAISE EXCEPTION 'administration denied' USING ERRCODE='42501';END IF;
 RETURN prior.project_id;END IF;
 PERFORM pg_advisory_xact_lock(740129816155::bigint);
 IF (SELECT count(*) FROM verivaro.projects WHERE tenant_id=t)>=200 OR (SELECT count(*) FROM verivaro_private.project_admin_events)>=32768 THEN RAISE EXCEPTION 'project capacity exhausted' USING ERRCODE='54000';END IF;
 PERFORM verivaro_private.project_admin_actor(t);
 p:=gen_random_uuid();
 INSERT INTO verivaro.projects(id,tenant_id,name) VALUES(p,t,n);
 INSERT INTO verivaro.project_members(tenant_id,project_id,actor_id,role) VALUES(t,p,c[2]::uuid,'owner');
 INSERT INTO verivaro_private.project_admin_events(tenant_id,actor_id,request_id,session_id,project_id,operation,request_digest) VALUES(t,c[2]::uuid,r,c[3]::uuid,p,'create',d);
 RETURN p;
END $create$;
CREATE FUNCTION verivaro_mutation.project_directory(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $directory$
BEGIN
 PERFORM verivaro_private.release_actor(t,p,'owner');
 RETURN COALESCE((SELECT jsonb_agg(to_jsonb(q) ORDER BY q."actorId") FROM (
 SELECT m.actor_id AS "actorId",m.role AS "tenantRole",pm.role AS "projectRole",pm.share_generation AS generation,
 (pm.actor_id IS NOT NULL AND pm.revoked_at IS NULL AND (pm.expires_at IS NULL OR pm.expires_at>statement_timestamp())) AS active,pm.expires_at AS "expiresAt"
 FROM verivaro.memberships m LEFT JOIN verivaro.project_members pm ON pm.tenant_id=m.tenant_id AND pm.actor_id=m.actor_id AND pm.project_id=p
 WHERE m.tenant_id=t AND m.revoked_at IS NULL AND m.role<>'owner' AND NOT EXISTS(SELECT 1 FROM verivaro_private.disabled_actors WHERE actor_id=m.actor_id)
 AND (pm.role IS NULL OR pm.role<>'owner') ORDER BY m.actor_id LIMIT 200) q),'[]'::jsonb);
END $directory$;
CREATE FUNCTION verivaro_mutation.change_project_access(t uuid,p uuid,r uuid,target uuid,desired text,expected uuid) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $access$
DECLARE c text[];tr text;old verivaro.project_members%ROWTYPE;prior verivaro_private.project_admin_events%ROWTYPE;d bytea;g uuid;op text;
BEGIN
 c:=verivaro_private.release_actor(t,p,'owner');
 IF r IS NULL OR target IS NULL OR target=c[2]::uuid OR desired IS NULL OR desired NOT IN ('viewer','contributor','reviewer','revoke') THEN RAISE EXCEPTION 'administration denied' USING ERRCODE='42501';END IF;
 SELECT m.role INTO tr FROM verivaro.memberships m WHERE m.tenant_id=t AND m.actor_id=target AND m.revoked_at IS NULL FOR SHARE;
 IF NOT FOUND OR tr='owner' OR (desired NOT IN ('viewer','revoke') AND desired<>tr) OR EXISTS(SELECT 1 FROM verivaro_private.disabled_actors WHERE actor_id=target) THEN RAISE EXCEPTION 'administration denied' USING ERRCODE='42501';END IF;
 -- Serialize modifications on a project, including initial absent membership.
 PERFORM 1 FROM verivaro.projects q WHERE q.tenant_id=t AND q.id=p FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'administration denied' USING ERRCODE='42501';END IF;
 SELECT * INTO old FROM verivaro.project_members m WHERE m.tenant_id=t AND m.project_id=p AND m.actor_id=target FOR UPDATE;
 IF old.role='owner' THEN RAISE EXCEPTION 'administration denied' USING ERRCODE='42501';END IF;
 op:=CASE WHEN desired='revoke' THEN 'revoke' ELSE 'assign' END;
 d:=verivaro_private.digest(convert_to(jsonb_build_array('access',p,target,desired,expected)::text,'UTF8'),'sha256');
 SELECT * INTO prior FROM verivaro_private.project_admin_events e WHERE e.tenant_id=t AND e.actor_id=c[2]::uuid AND e.request_id=r;
 IF FOUND THEN
 IF prior.request_digest<>d OR prior.operation<>op THEN RAISE EXCEPTION 'administration conflict' USING ERRCODE='23505';END IF;
 RETURN prior.result_generation;END IF;
 IF old.share_generation IS DISTINCT FROM expected OR (desired='revoke' AND (old.actor_id IS NULL OR old.revoked_at IS NOT NULL)) THEN RAISE EXCEPTION 'administration conflict' USING ERRCODE='23505';END IF;
 PERFORM pg_advisory_xact_lock(740129816155::bigint);
 IF (SELECT count(*) FROM verivaro_private.project_admin_events)>=32768 OR (old.actor_id IS NULL AND (SELECT count(*) FROM verivaro.project_members m WHERE m.tenant_id=t AND m.project_id=p)>=200) THEN RAISE EXCEPTION 'project capacity exhausted' USING ERRCODE='54000';END IF;
 PERFORM verivaro_private.release_actor(t,p,'owner');
 IF desired='revoke' THEN
 UPDATE verivaro.project_members m SET revoked_at=clock_timestamp() WHERE m.tenant_id=t AND m.project_id=p AND m.actor_id=target RETURNING share_generation INTO g;
 ELSE
 INSERT INTO verivaro.project_members(tenant_id,project_id,actor_id,role,expires_at) VALUES(t,p,target,desired,clock_timestamp()+interval '30 days')
 ON CONFLICT(tenant_id,project_id,actor_id) DO UPDATE SET role=EXCLUDED.role,expires_at=EXCLUDED.expires_at,revoked_at=NULL RETURNING share_generation INTO g;
 END IF;
 INSERT INTO verivaro_private.project_admin_events(tenant_id,actor_id,request_id,session_id,project_id,operation,target_id,request_digest,previous_generation,result_generation,previous_role,result_role)
 VALUES(t,c[2]::uuid,r,c[3]::uuid,p,op,target,d,old.share_generation,g,old.role,CASE WHEN desired='revoke' THEN NULL ELSE desired END);
 RETURN g;
END $access$;
REVOKE ALL ON FUNCTION verivaro_mutation.create_project(uuid,uuid,text),verivaro_mutation.project_directory(uuid,uuid),verivaro_mutation.change_project_access(uuid,uuid,uuid,uuid,text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_mutation.create_project(uuid,uuid,text),verivaro_mutation.project_directory(uuid,uuid),verivaro_mutation.change_project_access(uuid,uuid,uuid,uuid,text,uuid) TO verivaro_runtime;
COMMIT;
