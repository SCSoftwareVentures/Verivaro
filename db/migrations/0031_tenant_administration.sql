BEGIN;
CREATE ROLE verivaro_tenant_operator NOLOGIN NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE SCHEMA verivaro_tenant_admin;
REVOKE ALL ON SCHEMA verivaro_tenant_admin FROM PUBLIC;
GRANT USAGE ON SCHEMA verivaro_tenant_admin TO verivaro_runtime,verivaro_tenant_operator;
CREATE TABLE verivaro_private.tenant_admin_requests(
 request_id uuid PRIMARY KEY,tenant_id uuid NOT NULL REFERENCES verivaro.tenants(id),owner_id uuid NOT NULL,owner_session uuid NOT NULL,owner_generation uuid NOT NULL,
 kind text NOT NULL CHECK(kind IN ('enroll','transfer')),
 issuer text,subject_digest bytea,target_actor uuid,target_generation uuid,desired_role text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK((kind='enroll' AND issuer IS NOT NULL AND octet_length(issuer) BETWEEN 1 AND 512 AND subject_digest IS NOT NULL AND octet_length(subject_digest)=32 AND target_actor IS NULL AND target_generation IS NULL AND desired_role IN ('viewer','contributor','reviewer'))
 OR (kind='transfer' AND issuer IS NULL AND subject_digest IS NULL AND target_actor IS NOT NULL AND target_actor<>owner_id AND target_generation IS NOT NULL AND desired_role IS NULL))
);
CREATE TABLE verivaro_private.tenant_transfer_acceptances(
 request_id uuid PRIMARY KEY REFERENCES verivaro_private.tenant_admin_requests(request_id),actor_id uuid NOT NULL,session_id uuid NOT NULL,accepted_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE verivaro_private.tenant_admin_receipts(
 request_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,actor_id uuid NOT NULL,operator_login name NOT NULL DEFAULT session_user,
 kind text NOT NULL CHECK(kind IN ('bootstrap','enroll','transfer','access')),case_ref uuid UNIQUE,request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 result_generation uuid NOT NULL,occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON verivaro_private.tenant_admin_requests,verivaro_private.tenant_transfer_acceptances,verivaro_private.tenant_admin_receipts FROM PUBLIC;
CREATE TRIGGER tenant_admin_request_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.tenant_admin_requests FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER tenant_transfer_acceptance_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.tenant_transfer_acceptances FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER tenant_admin_receipt_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.tenant_admin_receipts FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();

-- Serialize the new administration operations. Existing identity/membership
-- locks still fence concurrent logout, disable and project authorization.
CREATE FUNCTION verivaro_private.tenant_admin_lock() RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,verivaro_private AS $lock$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'tenant administration denied' USING ERRCODE='42501';END IF;
 PERFORM pg_advisory_xact_lock(740129816156::bigint);
END $lock$;
CREATE FUNCTION verivaro_private.tenant_admin_capacity() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $cap$
BEGIN
 IF (SELECT count(*) FROM verivaro_private.tenant_admin_requests)>=32768 OR (SELECT count(*) FROM verivaro_private.tenant_admin_receipts)>=32768 THEN RAISE EXCEPTION 'tenant administration capacity' USING ERRCODE='54000';END IF;
 -- Restores remain quarantined; no privileged bootstrap or enrollment bypass.
 IF to_regclass('verivaro_private.restore_quarantine') IS NOT NULL THEN RAISE EXCEPTION 'restore quarantine' USING ERRCODE='42501';END IF;
END $cap$;
CREATE FUNCTION verivaro_private.tenant_admin_member(t uuid,a uuid,s uuid,g uuid,owner_only boolean) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $member$
BEGIN
 PERFORM verivaro_private.lock_identity(a);
 PERFORM 1 FROM verivaro.memberships m WHERE m.tenant_id=t AND m.actor_id=a AND m.revoked_at IS NULL AND m.share_generation=g AND (NOT owner_only OR m.role='owner') FOR SHARE;
 IF NOT FOUND THEN RETURN false;END IF;
 RETURN NOT EXISTS(SELECT 1 FROM verivaro_private.disabled_actors d WHERE d.actor_id=a)
 AND EXISTS(SELECT 1 FROM verivaro_private.identity_sessions i WHERE i.actor_id=a AND i.session_id=s AND i.revoked_at IS NULL AND i.expires_at>clock_timestamp())
 AND EXISTS(SELECT 1 FROM verivaro_private.provider_bindings b WHERE b.actor_id=a AND b.disabled_at IS NULL);
END $member$;
CREATE FUNCTION verivaro_private.tenant_admin_bound_owner(t uuid) RETURNS text[]
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $owner$
DECLARE c text[];g uuid;
BEGIN
 c:=verivaro_private.project_admin_actor(t);
 SELECT share_generation INTO g FROM verivaro.memberships WHERE tenant_id=t AND actor_id=c[2]::uuid;
 IF NOT verivaro_private.tenant_admin_member(t,c[2]::uuid,c[3]::uuid,g,true) THEN RAISE EXCEPTION 'tenant administration denied' USING ERRCODE='42501';END IF;
 RETURN c;
END $owner$;
REVOKE ALL ON FUNCTION verivaro_private.tenant_admin_lock(),verivaro_private.tenant_admin_capacity(),verivaro_private.tenant_admin_member(uuid,uuid,uuid,uuid,boolean),verivaro_private.tenant_admin_bound_owner(uuid) FROM PUBLIC;

-- Only the trusted operator can bootstrap a tenant. Identity verification
-- occurs separately; the case reference is an audit correlation, not proof.
CREATE FUNCTION verivaro_tenant_admin.bootstrap(t uuid,r uuid,n text,iss text,h bytea,case_id uuid) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $boot$
DECLARE a uuid;g uuid;d bytea;prior verivaro_private.tenant_admin_receipts%ROWTYPE;
BEGIN
 PERFORM verivaro_private.tenant_admin_lock();PERFORM verivaro_private.tenant_admin_capacity();
 IF t IS NULL OR r IS NULL OR case_id IS NULL OR n IS NULL OR char_length(n) NOT BETWEEN 1 AND 128 OR octet_length(n)>512 OR n<>btrim(n) OR n~'[[:cntrl:]]'
 OR iss IS NULL OR octet_length(iss) NOT BETWEEN 1 AND 512 OR h IS NULL OR octet_length(h)<>32 THEN RAISE EXCEPTION 'bootstrap denied' USING ERRCODE='42501';END IF;
 d:=verivaro_private.digest(convert_to(jsonb_build_array(t,n,iss,encode(h,'hex'),case_id)::text,'UTF8'),'sha256');
 SELECT * INTO prior FROM verivaro_private.tenant_admin_receipts WHERE request_id=r;
 IF FOUND THEN
 IF prior.kind<>'bootstrap' OR prior.request_digest<>d THEN RAISE EXCEPTION 'tenant conflict' USING ERRCODE='23505';END IF;
 RETURN prior.actor_id;END IF;
 IF EXISTS(SELECT 1 FROM verivaro.tenants WHERE id=t) OR EXISTS(SELECT 1 FROM verivaro_private.tenant_admin_requests WHERE request_id=r)
 OR (SELECT count(*) FROM verivaro.tenants)>=1024 THEN RAISE EXCEPTION 'bootstrap denied' USING ERRCODE='42501';END IF;
 SELECT actor_id INTO a FROM verivaro_private.provider_bindings WHERE issuer=iss AND subject_digest=h AND disabled_at IS NULL FOR SHARE;
 IF NOT FOUND THEN a:=gen_random_uuid();END IF;
 PERFORM verivaro_private.lock_identity(a);
 IF EXISTS(SELECT 1 FROM verivaro_private.disabled_actors WHERE actor_id=a) THEN RAISE EXCEPTION 'bootstrap denied' USING ERRCODE='42501';END IF;
 INSERT INTO verivaro.tenants(id,name) VALUES(t,n);
 INSERT INTO verivaro.memberships(tenant_id,actor_id,role) VALUES(t,a,'owner') RETURNING share_generation INTO g;
 IF NOT EXISTS(SELECT 1 FROM verivaro_private.provider_bindings WHERE actor_id=a) THEN PERFORM verivaro_identity.provision_binding(iss,h,a,r);END IF;
 INSERT INTO verivaro_private.tenant_admin_receipts(request_id,tenant_id,actor_id,kind,case_ref,request_digest,result_generation) VALUES(r,t,a,'bootstrap',case_id,d,g);
 RETURN a;
END $boot$;
CREATE FUNCTION verivaro_tenant_admin.request_enrollment(t uuid,r uuid,iss text,h bytea,desired text) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $enroll$
DECLARE c text[];g uuid;q verivaro_private.tenant_admin_requests%ROWTYPE;
BEGIN
 PERFORM verivaro_private.tenant_admin_lock();PERFORM verivaro_private.tenant_admin_capacity();c:=verivaro_private.tenant_admin_bound_owner(t);
 IF r IS NULL OR iss IS NULL OR octet_length(iss) NOT BETWEEN 1 AND 512 OR h IS NULL OR octet_length(h)<>32 OR desired IS NULL OR desired NOT IN ('viewer','contributor','reviewer') THEN RAISE EXCEPTION 'enrollment denied' USING ERRCODE='42501';END IF;
 SELECT share_generation INTO g FROM verivaro.memberships WHERE tenant_id=t AND actor_id=c[2]::uuid;
 SELECT * INTO q FROM verivaro_private.tenant_admin_requests WHERE request_id=r;
 IF FOUND THEN
 IF q.tenant_id<>t OR q.owner_id<>c[2]::uuid OR q.owner_generation<>g OR q.kind<>'enroll' OR q.issuer<>iss OR q.subject_digest<>h OR q.desired_role<>desired THEN RAISE EXCEPTION 'tenant conflict' USING ERRCODE='23505';END IF;
 RETURN r;END IF;
 IF EXISTS(SELECT 1 FROM verivaro_private.tenant_admin_receipts WHERE request_id=r) THEN RAISE EXCEPTION 'tenant conflict' USING ERRCODE='23505';END IF;
 INSERT INTO verivaro_private.tenant_admin_requests(request_id,tenant_id,owner_id,owner_session,owner_generation,kind,issuer,subject_digest,desired_role) VALUES(r,t,c[2]::uuid,c[3]::uuid,g,'enroll',iss,h,desired);
 RETURN r;
END $enroll$;
CREATE FUNCTION verivaro_tenant_admin.approve_enrollment(t uuid,r uuid,iss text,h bytea,case_id uuid) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $approve$
DECLARE q verivaro_private.tenant_admin_requests%ROWTYPE;prior verivaro_private.tenant_admin_receipts%ROWTYPE;a uuid;g uuid;d bytea;
BEGIN
 PERFORM verivaro_private.tenant_admin_lock();PERFORM verivaro_private.tenant_admin_capacity();
 SELECT * INTO q FROM verivaro_private.tenant_admin_requests WHERE request_id=r AND tenant_id=t AND kind='enroll';
 IF NOT FOUND OR case_id IS NULL OR q.issuer IS DISTINCT FROM iss OR q.subject_digest IS DISTINCT FROM h OR NOT verivaro_private.tenant_admin_member(t,q.owner_id,q.owner_session,q.owner_generation,true) THEN RAISE EXCEPTION 'enrollment denied' USING ERRCODE='42501';END IF;
 d:=verivaro_private.digest(convert_to(jsonb_build_array(t,r,iss,encode(h,'hex'),case_id)::text,'UTF8'),'sha256');
 SELECT * INTO prior FROM verivaro_private.tenant_admin_receipts WHERE request_id=r;
 IF FOUND THEN
 IF prior.kind<>'enroll' OR prior.request_digest<>d THEN RAISE EXCEPTION 'tenant conflict' USING ERRCODE='23505';END IF;
 RETURN prior.actor_id;END IF;
 IF q.created_at<clock_timestamp()-interval '15 minutes' OR (SELECT count(*) FROM verivaro.memberships WHERE tenant_id=t)>=200 THEN RAISE EXCEPTION 'enrollment denied' USING ERRCODE='42501';END IF;
 SELECT actor_id INTO a FROM verivaro_private.provider_bindings WHERE issuer=iss AND subject_digest=h AND disabled_at IS NULL FOR SHARE;
 IF NOT FOUND THEN a:=gen_random_uuid();END IF;
 PERFORM verivaro_private.lock_identity(a);
 IF EXISTS(SELECT 1 FROM verivaro_private.disabled_actors WHERE actor_id=a) OR EXISTS(SELECT 1 FROM verivaro.memberships WHERE tenant_id=t AND actor_id=a)
 THEN RAISE EXCEPTION 'enrollment denied' USING ERRCODE='42501';END IF;
 INSERT INTO verivaro.memberships(tenant_id,actor_id,role) VALUES(t,a,q.desired_role) RETURNING share_generation INTO g;
 IF NOT EXISTS(SELECT 1 FROM verivaro_private.provider_bindings WHERE actor_id=a) THEN PERFORM verivaro_identity.provision_binding(iss,h,a,r);END IF;
 INSERT INTO verivaro_private.tenant_admin_receipts(request_id,tenant_id,actor_id,kind,case_ref,request_digest,result_generation) VALUES(r,t,a,'enroll',case_id,d,g);
 RETURN a;
END $approve$;
CREATE FUNCTION verivaro_tenant_admin.directory(t uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $directory$
BEGIN
 PERFORM verivaro_private.tenant_admin_bound_owner(t);
 RETURN COALESCE((SELECT jsonb_agg(to_jsonb(q) ORDER BY q."actorId") FROM (
 SELECT m.actor_id AS "actorId",m.role,m.share_generation AS generation,(m.revoked_at IS NULL AND NOT EXISTS(SELECT 1 FROM verivaro_private.disabled_actors d WHERE d.actor_id=m.actor_id)) AS active,
 EXISTS(SELECT 1 FROM verivaro_private.provider_bindings b WHERE b.actor_id=m.actor_id AND b.disabled_at IS NULL) AS "bound"
 FROM verivaro.memberships m WHERE m.tenant_id=t ORDER BY m.actor_id LIMIT 200) q),'[]'::jsonb);
END $directory$;
CREATE FUNCTION verivaro_tenant_admin.change_access(t uuid,r uuid,target uuid,desired text,g uuid) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $access$
DECLARE c text[];m verivaro.memberships%ROWTYPE;prior verivaro_private.tenant_admin_receipts%ROWTYPE;d bytea;next_g uuid;
BEGIN
 PERFORM verivaro_private.tenant_admin_lock();PERFORM verivaro_private.tenant_admin_capacity();c:=verivaro_private.tenant_admin_bound_owner(t);
 IF r IS NULL OR target IS NULL OR target=c[2]::uuid OR g IS NULL OR desired IS NULL OR desired NOT IN ('viewer','contributor','reviewer','revoke') THEN RAISE EXCEPTION 'tenant access denied' USING ERRCODE='42501';END IF;
 PERFORM verivaro_private.lock_identity(target);
 SELECT * INTO m FROM verivaro.memberships WHERE tenant_id=t AND actor_id=target FOR UPDATE;
 IF NOT FOUND OR m.role='owner' THEN RAISE EXCEPTION 'tenant access denied' USING ERRCODE='42501';END IF;
 d:=verivaro_private.digest(convert_to(jsonb_build_array(t,r,c[2],target,desired,g)::text,'UTF8'),'sha256');
 SELECT * INTO prior FROM verivaro_private.tenant_admin_receipts WHERE request_id=r;
 IF FOUND THEN
 IF prior.kind<>'access' OR prior.request_digest<>d THEN RAISE EXCEPTION 'tenant conflict' USING ERRCODE='23505';END IF;
 RETURN prior.result_generation;END IF;
 IF EXISTS(SELECT 1 FROM verivaro_private.tenant_admin_requests WHERE request_id=r) OR m.share_generation<>g OR m.revoked_at IS NOT NULL THEN RAISE EXCEPTION 'tenant conflict' USING ERRCODE='23505';END IF;
 IF desired<>'revoke' AND EXISTS(SELECT 1 FROM verivaro_private.disabled_actors WHERE actor_id=target) THEN RAISE EXCEPTION 'tenant access denied' USING ERRCODE='42501';END IF;
 -- Never implicitly resurrect old project grants after a tenant role change.
 UPDATE verivaro.project_members SET revoked_at=clock_timestamp() WHERE tenant_id=t AND actor_id=target AND revoked_at IS NULL;
 UPDATE verivaro.memberships SET role=CASE WHEN desired='revoke' THEN m.role ELSE desired END,revoked_at=CASE WHEN desired='revoke' THEN clock_timestamp() ELSE NULL END WHERE tenant_id=t AND actor_id=target RETURNING share_generation INTO next_g;
 INSERT INTO verivaro_private.tenant_admin_receipts(request_id,tenant_id,actor_id,kind,request_digest,result_generation) VALUES(r,t,target,'access',d,next_g);
 RETURN next_g;
END $access$;
CREATE FUNCTION verivaro_tenant_admin.request_transfer(t uuid,r uuid,target uuid,g uuid) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $request$
DECLARE c text[];og uuid;q verivaro_private.tenant_admin_requests%ROWTYPE;
BEGIN
 PERFORM verivaro_private.tenant_admin_lock();PERFORM verivaro_private.tenant_admin_capacity();c:=verivaro_private.tenant_admin_bound_owner(t);
 IF r IS NULL OR target IS NULL OR target=c[2]::uuid OR g IS NULL THEN RAISE EXCEPTION 'transfer denied' USING ERRCODE='42501';END IF;
 PERFORM verivaro_private.lock_identity(target);
 IF NOT EXISTS(SELECT 1 FROM verivaro.memberships WHERE tenant_id=t AND actor_id=target AND share_generation=g AND revoked_at IS NULL AND role<>'owner')
 OR NOT EXISTS(SELECT 1 FROM verivaro_private.provider_bindings WHERE actor_id=target AND disabled_at IS NULL) OR EXISTS(SELECT 1 FROM verivaro_private.disabled_actors WHERE actor_id=target)
 THEN RAISE EXCEPTION 'transfer denied' USING ERRCODE='42501';END IF;
 SELECT share_generation INTO og FROM verivaro.memberships WHERE tenant_id=t AND actor_id=c[2]::uuid;
 SELECT * INTO q FROM verivaro_private.tenant_admin_requests WHERE request_id=r;
 IF FOUND THEN
 IF q.kind<>'transfer' OR q.tenant_id<>t OR q.owner_id<>c[2]::uuid OR q.owner_generation<>og OR q.target_actor<>target OR q.target_generation<>g THEN RAISE EXCEPTION 'tenant conflict' USING ERRCODE='23505';END IF;
 RETURN r;END IF;
 IF EXISTS(SELECT 1 FROM verivaro_private.tenant_admin_receipts WHERE request_id=r) THEN RAISE EXCEPTION 'tenant conflict' USING ERRCODE='23505';END IF;
 INSERT INTO verivaro_private.tenant_admin_requests(request_id,tenant_id,owner_id,owner_session,owner_generation,kind,target_actor,target_generation) VALUES(r,t,c[2]::uuid,c[3]::uuid,og,'transfer',target,g);
 RETURN r;
END $request$;
CREATE FUNCTION verivaro_tenant_admin.accept_transfer(t uuid,r uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $accept$
DECLARE c text[];q verivaro_private.tenant_admin_requests%ROWTYPE;
BEGIN
 PERFORM verivaro_private.tenant_admin_lock();PERFORM verivaro_private.tenant_admin_capacity();c:=verivaro.bound_context();
 SELECT * INTO q FROM verivaro_private.tenant_admin_requests WHERE request_id=r AND tenant_id=t AND kind='transfer';
 IF NOT FOUND OR c IS NULL OR c[1]<>t::text OR q.target_actor<>c[2]::uuid OR q.created_at<clock_timestamp()-interval '15 minutes'
 OR NOT verivaro_private.tenant_admin_member(t,q.target_actor,c[3]::uuid,q.target_generation,false)
 OR NOT verivaro_private.tenant_admin_member(t,q.owner_id,q.owner_session,q.owner_generation,true)
 THEN RAISE EXCEPTION 'transfer denied' USING ERRCODE='42501';END IF;
 INSERT INTO verivaro_private.tenant_transfer_acceptances(request_id,actor_id,session_id) VALUES(r,c[2]::uuid,c[3]::uuid) ON CONFLICT(request_id) DO NOTHING;
 RETURN EXISTS(SELECT 1 FROM verivaro_private.tenant_transfer_acceptances WHERE request_id=r AND actor_id=c[2]::uuid AND session_id=c[3]::uuid);
END $accept$;
CREATE FUNCTION verivaro_tenant_admin.complete_transfer(t uuid,r uuid,case_id uuid) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $transfer$
DECLARE q verivaro_private.tenant_admin_requests%ROWTYPE;v verivaro_private.tenant_transfer_acceptances%ROWTYPE;prior verivaro_private.tenant_admin_receipts%ROWTYPE;d bytea;ng uuid;
BEGIN
 PERFORM verivaro_private.tenant_admin_lock();PERFORM verivaro_private.tenant_admin_capacity();
 SELECT * INTO q FROM verivaro_private.tenant_admin_requests WHERE request_id=r AND tenant_id=t AND kind='transfer';
 IF NOT FOUND OR case_id IS NULL THEN RAISE EXCEPTION 'transfer denied' USING ERRCODE='42501';END IF;
 d:=verivaro_private.digest(convert_to(jsonb_build_array(t,r,case_id)::text,'UTF8'),'sha256');
 SELECT * INTO prior FROM verivaro_private.tenant_admin_receipts WHERE request_id=r;
 IF FOUND THEN
 IF prior.kind<>'transfer' OR prior.request_digest<>d THEN RAISE EXCEPTION 'tenant conflict' USING ERRCODE='23505';END IF;
 RETURN prior.actor_id;END IF;
 SELECT * INTO v FROM verivaro_private.tenant_transfer_acceptances WHERE request_id=r;
 IF NOT FOUND OR v.actor_id<>q.target_actor OR q.created_at<clock_timestamp()-interval '15 minutes'
 OR NOT verivaro_private.tenant_admin_member(t,q.owner_id,q.owner_session,q.owner_generation,true)
 OR NOT verivaro_private.tenant_admin_member(t,q.target_actor,v.session_id,q.target_generation,false)
 THEN RAISE EXCEPTION 'transfer denied' USING ERRCODE='42501';END IF;
 -- Archive invariants are not weakened for succession. Dedicated historical
 -- custody handover will be required if the outgoing owner owns an archive.
 IF EXISTS(SELECT 1 FROM verivaro.project_members m JOIN verivaro.projects p ON p.tenant_id=m.tenant_id AND p.id=m.project_id WHERE m.tenant_id=t AND m.actor_id=q.owner_id AND m.role='owner' AND m.revoked_at IS NULL AND p.archived_at IS NOT NULL)
 THEN RAISE EXCEPTION 'archived ownership requires separate handover' USING ERRCODE='42501';END IF;
 -- Copy only current, unexpired project-owner assignments. Lock project rows
 -- so archival cannot race the promotion. No raw evidence is copied.
 PERFORM 1 FROM verivaro.projects p WHERE p.tenant_id=t ORDER BY p.id FOR UPDATE;
 UPDATE verivaro.memberships SET role='owner' WHERE tenant_id=t AND actor_id=q.target_actor RETURNING share_generation INTO ng;
 INSERT INTO verivaro.project_members(tenant_id,project_id,actor_id,role)
 SELECT tenant_id,project_id,q.target_actor,'owner' FROM verivaro.project_members WHERE tenant_id=t AND actor_id=q.owner_id AND role='owner' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp())
 ON CONFLICT(tenant_id,project_id,actor_id) DO UPDATE SET role='owner',expires_at=NULL,revoked_at=NULL;
 UPDATE verivaro.project_members SET revoked_at=clock_timestamp() WHERE tenant_id=t AND actor_id=q.owner_id AND revoked_at IS NULL;
 UPDATE verivaro.memberships SET role='viewer',revoked_at=clock_timestamp() WHERE tenant_id=t AND actor_id=q.owner_id;
 INSERT INTO verivaro_private.tenant_admin_receipts(request_id,tenant_id,actor_id,kind,case_ref,request_digest,result_generation) VALUES(r,t,q.target_actor,'transfer',case_id,d,ng);
 RETURN q.target_actor;
END $transfer$;
CREATE FUNCTION verivaro_tenant_admin.pending_transfers(t uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $pending$
DECLARE c text[];
BEGIN
 c:=verivaro.bound_context();
 IF c IS NULL OR c[1]<>t::text OR NOT verivaro.active_identity() OR NOT EXISTS(SELECT 1 FROM verivaro.memberships WHERE tenant_id=t AND actor_id=c[2]::uuid AND revoked_at IS NULL) THEN RAISE EXCEPTION 'transfer denied' USING ERRCODE='42501';END IF;
 RETURN COALESCE((SELECT jsonb_agg(to_jsonb(q) ORDER BY q.id) FROM (
 SELECT r.request_id AS id,r.owner_id AS "fromActor",r.target_actor AS "toActor",r.created_at AS "createdAt",v.accepted_at AS "acceptedAt",z.occurred_at AS "completedAt"
 FROM verivaro_private.tenant_admin_requests r LEFT JOIN verivaro_private.tenant_transfer_acceptances v USING(request_id) LEFT JOIN verivaro_private.tenant_admin_receipts z USING(request_id)
 WHERE r.tenant_id=t AND r.kind='transfer' AND (r.owner_id=c[2]::uuid OR r.target_actor=c[2]::uuid) ORDER BY r.created_at DESC LIMIT 200) q),'[]'::jsonb);
END $pending$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA verivaro_tenant_admin FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_tenant_admin.bootstrap(uuid,uuid,text,text,bytea,uuid),verivaro_tenant_admin.approve_enrollment(uuid,uuid,text,bytea,uuid),verivaro_tenant_admin.complete_transfer(uuid,uuid,uuid) TO verivaro_tenant_operator;
GRANT EXECUTE ON FUNCTION verivaro_tenant_admin.request_enrollment(uuid,uuid,text,bytea,text),verivaro_tenant_admin.directory(uuid),verivaro_tenant_admin.change_access(uuid,uuid,uuid,text,uuid),verivaro_tenant_admin.request_transfer(uuid,uuid,uuid,uuid),verivaro_tenant_admin.accept_transfer(uuid,uuid),verivaro_tenant_admin.pending_transfers(uuid) TO verivaro_runtime;
COMMIT;
