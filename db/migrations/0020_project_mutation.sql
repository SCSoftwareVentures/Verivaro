BEGIN;
ALTER TABLE verivaro.projects ADD COLUMN revision integer NOT NULL DEFAULT 0 CHECK(revision>=0);
CREATE SCHEMA verivaro_mutation;
REVOKE ALL ON SCHEMA verivaro_mutation FROM PUBLIC;
GRANT USAGE ON SCHEMA verivaro_mutation TO verivaro_runtime;
-- All exposed writes must use a reviewed atomic mutation function. Evidence
-- ingestion will need a separate verified storage workflow.
REVOKE INSERT ON verivaro.evidence FROM verivaro_runtime;
CREATE TABLE verivaro_private.project_mutation_receipts(
 tenant_id uuid NOT NULL, actor_id uuid NOT NULL, request_id uuid NOT NULL,
 project_id uuid NOT NULL, request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 result_revision integer NOT NULL CHECK(result_revision>0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,actor_id,request_id)
);
CREATE TABLE verivaro_private.project_mutation_audit(
 audit_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,actor_id uuid NOT NULL,session_id uuid NOT NULL,
 request_id uuid NOT NULL,operation text NOT NULL CHECK(operation='rename_project'),
 previous_digest bytea NOT NULL CHECK(octet_length(previous_digest)=32),
 new_digest bytea NOT NULL CHECK(octet_length(new_digest)=32),
 previous_revision integer NOT NULL,revision integer NOT NULL CHECK(revision=previous_revision+1),
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,actor_id,request_id),
 FOREIGN KEY(tenant_id,actor_id,request_id) REFERENCES verivaro_private.project_mutation_receipts(tenant_id,actor_id,request_id)
);
REVOKE ALL ON verivaro_private.project_mutation_receipts,verivaro_private.project_mutation_audit FROM PUBLIC;
CREATE TRIGGER project_mutation_receipt_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.project_mutation_receipts
 FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER project_mutation_audit_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.project_mutation_audit
 FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE FUNCTION verivaro_mutation.rename_project(t uuid,p uuid,r uuid,new_name text,expected integer)
RETURNS TABLE(id uuid,name text,revision integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $rename$
DECLARE ctx text[]; a uuid; s uuid; prior verivaro_private.project_mutation_receipts%ROWTYPE;
 old verivaro.projects%ROWTYPE; d bytea; n integer;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR t IS NULL OR p IS NULL OR r IS NULL
 OR new_name IS NULL OR char_length(new_name) NOT BETWEEN 1 AND 128 OR octet_length(new_name)>512
 OR new_name<>btrim(new_name) OR new_name~'[[:cntrl:]]' OR expected IS NULL OR expected<0 OR expected>=2147483647
 THEN RAISE EXCEPTION 'invalid mutation' USING ERRCODE='22023'; END IF;
 ctx:=verivaro.bound_context();
 IF ctx IS NULL OR ctx[1]<>t::text THEN RAISE EXCEPTION 'mutation denied' USING ERRCODE='42501'; END IF;
 a:=ctx[2]::uuid;s:=ctx[3]::uuid;
 PERFORM verivaro_private.lock_identity(a);
 -- Recheck current session and membership after acquiring the lifecycle lock.
 IF NOT EXISTS(SELECT 1 FROM verivaro_private.identity_sessions i WHERE i.actor_id=a AND i.session_id=s AND i.revoked_at IS NULL AND i.expires_at>clock_timestamp())
 OR EXISTS(SELECT 1 FROM verivaro_private.disabled_actors WHERE actor_id=a) THEN RAISE EXCEPTION 'mutation denied' USING ERRCODE='42501'; END IF;
 PERFORM 1 FROM verivaro.memberships m WHERE m.tenant_id=t AND m.actor_id=a AND m.role='owner' AND m.revoked_at IS NULL FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'mutation denied' USING ERRCODE='42501'; END IF;
 PERFORM 1 FROM verivaro.project_members pm WHERE pm.tenant_id=t AND pm.project_id=p AND pm.actor_id=a AND pm.role='owner' AND pm.revoked_at IS NULL
 AND (pm.expires_at IS NULL OR pm.expires_at>clock_timestamp()) FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'mutation denied' USING ERRCODE='42501'; END IF;
 SELECT * INTO old FROM verivaro.projects pr WHERE pr.tenant_id=t AND pr.id=p FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'mutation denied' USING ERRCODE='42501'; END IF;
 IF NOT EXISTS(SELECT 1 FROM verivaro_private.identity_sessions i WHERE i.actor_id=a AND i.session_id=s AND i.revoked_at IS NULL AND i.expires_at>clock_timestamp())
 OR NOT EXISTS(SELECT 1 FROM verivaro.project_members pm WHERE pm.tenant_id=t AND pm.project_id=p AND pm.actor_id=a AND (pm.expires_at IS NULL OR pm.expires_at>clock_timestamp()))
 THEN RAISE EXCEPTION 'mutation denied' USING ERRCODE='42501'; END IF;
 d:=verivaro_private.digest(convert_to(jsonb_build_array('rename_project',p,new_name,expected)::text,'UTF8'),'sha256');
 SELECT * INTO prior FROM verivaro_private.project_mutation_receipts q WHERE q.tenant_id=t AND q.actor_id=a AND q.request_id=r;
 IF FOUND THEN
  IF prior.request_digest<>d THEN RAISE EXCEPTION 'mutation conflict' USING ERRCODE='23505'; END IF;
  RETURN QUERY SELECT p,new_name,prior.result_revision;RETURN;
 END IF;
 IF old.revision<>expected THEN RAISE EXCEPTION 'mutation conflict' USING ERRCODE='23505'; END IF;
 UPDATE verivaro.projects pr SET name=new_name,revision=pr.revision+1 WHERE pr.tenant_id=t AND pr.id=p RETURNING pr.revision INTO n;
 INSERT INTO verivaro_private.project_mutation_receipts(tenant_id,actor_id,request_id,project_id,request_digest,result_revision) VALUES(t,a,r,p,d,n);
 INSERT INTO verivaro_private.project_mutation_audit(tenant_id,project_id,actor_id,session_id,request_id,operation,previous_digest,new_digest,previous_revision,revision)
 VALUES(t,p,a,s,r,'rename_project',verivaro_private.digest(convert_to(old.name,'UTF8'),'sha256'),verivaro_private.digest(convert_to(new_name,'UTF8'),'sha256'),old.revision,n);
 RETURN QUERY SELECT p,new_name,n;
END $rename$;
REVOKE ALL ON FUNCTION verivaro_mutation.rename_project(uuid,uuid,uuid,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_mutation.rename_project(uuid,uuid,uuid,text,integer) TO verivaro_runtime;
COMMIT;
