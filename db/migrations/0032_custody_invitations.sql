BEGIN;
CREATE TABLE verivaro_private.archive_custody_handover(
 request_id uuid NOT NULL REFERENCES verivaro_private.tenant_admin_requests(request_id),
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,from_actor uuid NOT NULL,to_actor uuid NOT NULL,
 from_generation uuid NOT NULL,previous_target_generation uuid,archive_revision integer NOT NULL,transaction_id xid8 NOT NULL,
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(request_id,project_id),
 FOREIGN KEY(tenant_id,project_id) REFERENCES verivaro.projects(tenant_id,id),CHECK(from_actor<>to_actor)
);
CREATE TABLE verivaro_private.tenant_invitations(
 request_id uuid PRIMARY KEY REFERENCES verivaro_private.tenant_admin_requests(request_id),actor_id uuid NOT NULL,
 code_digest bytea NOT NULL UNIQUE CHECK(octet_length(code_digest)=32),case_ref uuid NOT NULL UNIQUE,
 operator_login name NOT NULL DEFAULT session_user,issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),expires_at timestamptz NOT NULL,
 CHECK(expires_at>issued_at)
);
CREATE TABLE verivaro_private.tenant_invitation_cancellations(
 request_id uuid PRIMARY KEY REFERENCES verivaro_private.tenant_invitations(request_id),actor_id uuid NOT NULL,session_id uuid NOT NULL,cancelled_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON verivaro_private.archive_custody_handover,verivaro_private.tenant_invitations,verivaro_private.tenant_invitation_cancellations FROM PUBLIC;
CREATE TRIGGER archive_custody_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.archive_custody_handover FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER tenant_invitation_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.tenant_invitations FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER tenant_invitation_cancel_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.tenant_invitation_cancellations FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE OR REPLACE FUNCTION verivaro_private.guard_project_write() RETURNS trigger
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
  -- Only an exact transaction-bound handover receipt created by the approved
  -- succession function may add an archived custodian. No caller GUC or role
  -- alone enables this exception.
  IF NEW.role='owner' AND NEW.revoked_at IS NULL AND NEW.expires_at IS NULL AND EXISTS(
   SELECT 1 FROM verivaro_private.archive_custody_handover h
   JOIN verivaro.projects ap ON ap.tenant_id=h.tenant_id AND ap.id=h.project_id
   JOIN verivaro_private.tenant_admin_requests r ON r.request_id=h.request_id
   JOIN verivaro_private.tenant_transfer_acceptances a ON a.request_id=h.request_id AND a.actor_id=h.to_actor
   JOIN verivaro.project_members src ON src.tenant_id=h.tenant_id AND src.project_id=h.project_id AND src.actor_id=h.from_actor
   JOIN verivaro.memberships dst ON dst.tenant_id=h.tenant_id AND dst.actor_id=h.to_actor
   WHERE h.tenant_id=t AND h.project_id=ap.id AND h.project_id=NEW.project_id AND h.to_actor=NEW.actor_id
   AND h.transaction_id=pg_current_xact_id_if_assigned() AND ap.archived_at IS NOT NULL AND ap.revision=h.archive_revision
   AND r.kind='transfer' AND r.owner_id=h.from_actor AND r.target_actor=h.to_actor
   AND src.role='owner' AND src.revoked_at IS NULL AND src.share_generation=h.from_generation
   AND (src.expires_at IS NULL OR src.expires_at>clock_timestamp()) AND dst.role='owner' AND dst.revoked_at IS NULL
   AND NOT EXISTS(SELECT 1 FROM verivaro_private.tenant_admin_receipts z WHERE z.request_id=h.request_id)
   AND (TG_OP='INSERT' OR h.previous_target_generation=OLD.share_generation)
  ) THEN RETURN NEW;END IF;
 ELSIF TG_TABLE_NAME IN ('evidence_release_reviews','evidence_release_receipts') THEN
  SELECT tenant_id,project_id INTO t,p FROM verivaro_private.evidence_release_requests WHERE request_id=NEW.request_id;
 ELSIF TG_TABLE_NAME='share_grants' THEN
  SELECT tenant_id,project_id INTO t,p FROM verivaro_private.released_exports WHERE export_id=NEW.export_id;
 ELSE t:=NEW.tenant_id;p:=NEW.project_id;
 END IF;
 PERFORM verivaro_private.require_open_project(t,p);RETURN NEW;
END $guard$;
CREATE OR REPLACE FUNCTION verivaro_tenant_admin.complete_transfer(t uuid,r uuid,case_id uuid) RETURNS uuid
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
 -- Lock projects before capturing exact historical custody assignments.
 PERFORM 1 FROM verivaro.projects p WHERE p.tenant_id=t ORDER BY p.id FOR UPDATE;
 INSERT INTO verivaro_private.archive_custody_handover(request_id,tenant_id,project_id,from_actor,to_actor,from_generation,previous_target_generation,archive_revision,transaction_id)
 SELECT r,t,p.id,q.owner_id,q.target_actor,m.share_generation,dst.share_generation,p.revision,pg_current_xact_id()
 FROM verivaro.project_members m JOIN verivaro.projects p ON p.tenant_id=m.tenant_id AND p.id=m.project_id
 LEFT JOIN verivaro.project_members dst ON dst.tenant_id=t AND dst.project_id=p.id AND dst.actor_id=q.target_actor
 WHERE m.tenant_id=t AND m.actor_id=q.owner_id AND m.role='owner' AND m.revoked_at IS NULL AND (m.expires_at IS NULL OR m.expires_at>clock_timestamp()) AND p.archived_at IS NOT NULL;
 UPDATE verivaro.memberships SET role='owner' WHERE tenant_id=t AND actor_id=q.target_actor RETURNING share_generation INTO ng;
 INSERT INTO verivaro.project_members(tenant_id,project_id,actor_id,role)
 SELECT tenant_id,project_id,q.target_actor,'owner' FROM verivaro.project_members WHERE tenant_id=t AND actor_id=q.owner_id AND role='owner' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp())
 ON CONFLICT(tenant_id,project_id,actor_id) DO UPDATE SET role='owner',expires_at=NULL,revoked_at=NULL;
 UPDATE verivaro.project_members SET revoked_at=clock_timestamp() WHERE tenant_id=t AND actor_id=q.owner_id AND revoked_at IS NULL;
 UPDATE verivaro.memberships SET role='viewer',revoked_at=clock_timestamp() WHERE tenant_id=t AND actor_id=q.owner_id;
 INSERT INTO verivaro_private.tenant_admin_receipts(request_id,tenant_id,actor_id,kind,initiated_by,initiating_session,case_ref,request_digest,result_generation) VALUES(r,t,q.target_actor,'transfer',q.owner_id,q.owner_session,case_id,d,ng);
 RETURN q.target_actor;
END $transfer$;
CREATE OR REPLACE FUNCTION verivaro_tenant_admin.approve_enrollment(t uuid,r uuid,iss text,h bytea,case_id uuid) RETURNS uuid
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
 IF EXISTS(SELECT 1 FROM verivaro_private.tenant_invitations v WHERE v.request_id=r) THEN RAISE EXCEPTION 'invitation already issued' USING ERRCODE='42501';END IF;
 IF q.created_at<clock_timestamp()-interval '15 minutes' OR (SELECT count(*) FROM verivaro.memberships WHERE tenant_id=t)>=200 THEN RAISE EXCEPTION 'enrollment denied' USING ERRCODE='42501';END IF;
 SELECT actor_id INTO a FROM verivaro_private.provider_bindings WHERE issuer=iss AND subject_digest=h AND disabled_at IS NULL FOR SHARE;
 IF NOT FOUND THEN a:=gen_random_uuid();END IF;
 PERFORM verivaro_private.lock_identity(a);
 IF EXISTS(SELECT 1 FROM verivaro_private.disabled_actors WHERE actor_id=a) OR EXISTS(SELECT 1 FROM verivaro.memberships WHERE tenant_id=t AND actor_id=a)
 THEN RAISE EXCEPTION 'enrollment denied' USING ERRCODE='42501';END IF;
 INSERT INTO verivaro.memberships(tenant_id,actor_id,role) VALUES(t,a,q.desired_role) RETURNING share_generation INTO g;
 IF NOT EXISTS(SELECT 1 FROM verivaro_private.provider_bindings WHERE actor_id=a) THEN PERFORM verivaro_identity.provision_binding(iss,h,a,r);END IF;
 INSERT INTO verivaro_private.tenant_admin_receipts(request_id,tenant_id,actor_id,kind,initiated_by,initiating_session,case_ref,request_digest,result_generation) VALUES(r,t,a,'enroll',q.owner_id,q.owner_session,case_id,d,g);
 RETURN a;
END $approve$;
CREATE OR REPLACE FUNCTION verivaro_tenant_admin.enrollment_requests(t uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $list$
BEGIN
 PERFORM verivaro_private.tenant_admin_bound_owner(t);
 RETURN COALESCE((SELECT jsonb_agg(to_jsonb(q) ORDER BY q."createdAt" DESC,q.id) FROM (
 SELECT r.request_id AS id,r.desired_role AS role,r.created_at AS "createdAt",z.actor_id AS "actorId",
 CASE WHEN z.request_id IS NOT NULL THEN 'enrolled' WHEN EXISTS(SELECT 1 FROM verivaro_private.tenant_invitation_cancellations c WHERE c.request_id=r.request_id) THEN 'cancelled' WHEN r.created_at<clock_timestamp()-interval '15 minutes' OR EXISTS(SELECT 1 FROM verivaro_private.tenant_invitations i WHERE i.request_id=r.request_id AND i.expires_at<=clock_timestamp()) THEN 'expired' WHEN EXISTS(SELECT 1 FROM verivaro_private.tenant_invitations i WHERE i.request_id=r.request_id) THEN 'invited' ELSE 'awaiting operator' END AS state
 FROM verivaro_private.tenant_admin_requests r LEFT JOIN verivaro_private.tenant_admin_receipts z USING(request_id)
 WHERE r.tenant_id=t AND r.kind='enroll' ORDER BY r.created_at DESC LIMIT 200) q),'[]'::jsonb);
END $list$;

-- Operator verifies issuer and original subject out of band. Issuance creates
-- a binding for sign-in only; no membership is granted until redemption.
CREATE FUNCTION verivaro_tenant_admin.issue_invitation(t uuid,r uuid,iss text,h bytea,code bytea,case_id uuid) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $issue$
DECLARE q verivaro_private.tenant_admin_requests%ROWTYPE;v verivaro_private.tenant_invitations%ROWTYPE;a uuid;deadline timestamptz;
BEGIN
 PERFORM verivaro_private.tenant_admin_lock();PERFORM verivaro_private.tenant_admin_capacity();
 SELECT * INTO q FROM verivaro_private.tenant_admin_requests WHERE request_id=r AND tenant_id=t AND kind='enroll';
 IF NOT FOUND OR case_id IS NULL OR code IS NULL OR octet_length(code)<>32 OR q.issuer IS DISTINCT FROM iss OR q.subject_digest IS DISTINCT FROM h
 OR NOT verivaro_private.tenant_admin_member(t,q.owner_id,q.owner_session,q.owner_generation,true) THEN RAISE EXCEPTION 'invitation denied' USING ERRCODE='42501';END IF;
 SELECT * INTO v FROM verivaro_private.tenant_invitations WHERE request_id=r;
 IF FOUND THEN
 IF v.code_digest<>code OR v.case_ref<>case_id THEN RAISE EXCEPTION 'invitation conflict' USING ERRCODE='23505';END IF;
 IF v.expires_at<=clock_timestamp() OR EXISTS(SELECT 1 FROM verivaro_private.tenant_invitation_cancellations WHERE request_id=r) THEN RAISE EXCEPTION 'invitation denied' USING ERRCODE='42501';END IF;
 RETURN v.actor_id;END IF;
 SELECT LEAST(q.created_at+interval '15 minutes',s.expires_at) INTO deadline FROM verivaro_private.identity_sessions s WHERE s.session_id=q.owner_session;
 IF deadline<=clock_timestamp() OR EXISTS(SELECT 1 FROM verivaro_private.tenant_admin_receipts WHERE request_id=r OR case_ref=case_id) THEN RAISE EXCEPTION 'invitation denied' USING ERRCODE='42501';END IF;
 SELECT actor_id INTO a FROM verivaro_private.provider_bindings WHERE issuer=iss AND subject_digest=h AND disabled_at IS NULL FOR SHARE;
 IF NOT FOUND THEN
  IF EXISTS(SELECT 1 FROM verivaro_private.provider_bindings WHERE issuer=iss AND subject_digest=h) OR (SELECT count(*) FROM verivaro_private.provider_bindings)>=32768 THEN RAISE EXCEPTION 'invitation denied' USING ERRCODE='42501';END IF;
  a:=gen_random_uuid();
  -- This narrow operator-only pathway intentionally provisions a login with
  -- zero tenant access. No password, email matching or arbitrary actor binding.
  INSERT INTO verivaro_private.provider_bindings(issuer,subject_digest,actor_id,provision_ref) VALUES(iss,h,a,r);
 END IF;
 PERFORM verivaro_private.lock_identity(a);
 IF EXISTS(SELECT 1 FROM verivaro_private.disabled_actors WHERE actor_id=a) OR EXISTS(SELECT 1 FROM verivaro.memberships WHERE tenant_id=t AND actor_id=a) THEN RAISE EXCEPTION 'invitation denied' USING ERRCODE='42501';END IF;
 INSERT INTO verivaro_private.tenant_invitations(request_id,actor_id,code_digest,case_ref,expires_at) VALUES(r,a,code,case_id,deadline);
 RETURN a;
END $issue$;
CREATE FUNCTION verivaro_tenant_admin.cancel_invitation(t uuid,r uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $cancel$
DECLARE c text[];
BEGIN
 PERFORM verivaro_private.tenant_admin_lock();PERFORM verivaro_private.tenant_admin_capacity();c:=verivaro_private.tenant_admin_bound_owner(t);
 IF NOT EXISTS(SELECT 1 FROM verivaro_private.tenant_invitations v JOIN verivaro_private.tenant_admin_requests q USING(request_id) WHERE v.request_id=r AND q.tenant_id=t)
 OR EXISTS(SELECT 1 FROM verivaro_private.tenant_admin_receipts WHERE request_id=r) THEN RAISE EXCEPTION 'invitation denied' USING ERRCODE='42501';END IF;
 INSERT INTO verivaro_private.tenant_invitation_cancellations(request_id,actor_id,session_id) VALUES(r,c[2]::uuid,c[3]::uuid) ON CONFLICT(request_id) DO NOTHING;
 RETURN true;
END $cancel$;
CREATE FUNCTION verivaro_tenant_admin.redeem_invitation(t uuid,r uuid,code bytea) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $redeem$
DECLARE c text[];q verivaro_private.tenant_admin_requests%ROWTYPE;v verivaro_private.tenant_invitations%ROWTYPE;prior verivaro_private.tenant_admin_receipts%ROWTYPE;g uuid;d bytea;
BEGIN
 PERFORM verivaro_private.tenant_admin_lock();PERFORM verivaro_private.tenant_admin_capacity();c:=verivaro.bound_context();
 IF c IS NULL OR c[1]<>t::text OR code IS NULL OR octet_length(code)<>32 THEN RAISE EXCEPTION 'invitation denied' USING ERRCODE='42501';END IF;
 SELECT * INTO q FROM verivaro_private.tenant_admin_requests WHERE request_id=r AND tenant_id=t AND kind='enroll';
 IF NOT FOUND THEN RAISE EXCEPTION 'invitation denied' USING ERRCODE='42501';END IF;
 SELECT * INTO v FROM verivaro_private.tenant_invitations WHERE request_id=r AND actor_id=c[2]::uuid AND code_digest=code;
 IF NOT FOUND THEN RAISE EXCEPTION 'invitation denied' USING ERRCODE='42501';END IF;
 PERFORM verivaro_private.lock_identity(v.actor_id);
 IF EXISTS(SELECT 1 FROM verivaro_private.disabled_actors WHERE actor_id=v.actor_id)
 OR NOT EXISTS(SELECT 1 FROM verivaro_private.identity_sessions s WHERE s.actor_id=v.actor_id AND s.session_id=c[3]::uuid AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp())
 OR NOT EXISTS(SELECT 1 FROM verivaro_private.provider_bindings b WHERE b.actor_id=v.actor_id AND b.issuer=q.issuer AND b.subject_digest=q.subject_digest AND b.disabled_at IS NULL)
 THEN RAISE EXCEPTION 'invitation denied' USING ERRCODE='42501';END IF;
 SELECT * INTO prior FROM verivaro_private.tenant_admin_receipts WHERE request_id=r;
 IF FOUND THEN
 IF prior.kind<>'enroll' OR prior.actor_id<>v.actor_id OR NOT EXISTS(SELECT 1 FROM verivaro.memberships m WHERE m.tenant_id=t AND m.actor_id=v.actor_id AND m.revoked_at IS NULL AND m.share_generation=prior.result_generation)
 THEN RAISE EXCEPTION 'invitation denied' USING ERRCODE='42501';END IF;
 RETURN prior.result_generation;END IF;
 IF v.expires_at<=clock_timestamp() OR EXISTS(SELECT 1 FROM verivaro_private.tenant_invitation_cancellations WHERE request_id=r)
 OR NOT verivaro_private.tenant_admin_member(t,q.owner_id,q.owner_session,q.owner_generation,true)
 OR EXISTS(SELECT 1 FROM verivaro.memberships WHERE tenant_id=t AND actor_id=v.actor_id)
 OR (SELECT count(*) FROM verivaro.memberships WHERE tenant_id=t)>=200 THEN RAISE EXCEPTION 'invitation denied' USING ERRCODE='42501';END IF;
 d:=verivaro_private.digest(convert_to(jsonb_build_array('invitation',t,r,v.actor_id,v.case_ref)::text,'UTF8'),'sha256');
 INSERT INTO verivaro.memberships(tenant_id,actor_id,role) VALUES(t,v.actor_id,q.desired_role) RETURNING share_generation INTO g;
 INSERT INTO verivaro_private.tenant_admin_receipts(request_id,tenant_id,actor_id,operator_login,kind,initiated_by,initiating_session,case_ref,request_digest,result_generation)
 VALUES(r,t,v.actor_id,v.operator_login,'enroll',q.owner_id,q.owner_session,v.case_ref,d,g);
 RETURN g;
END $redeem$;
REVOKE ALL ON FUNCTION verivaro_tenant_admin.issue_invitation(uuid,uuid,text,bytea,bytea,uuid),verivaro_tenant_admin.cancel_invitation(uuid,uuid),verivaro_tenant_admin.redeem_invitation(uuid,uuid,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_tenant_admin.issue_invitation(uuid,uuid,text,bytea,bytea,uuid) TO verivaro_tenant_operator;
GRANT EXECUTE ON FUNCTION verivaro_tenant_admin.cancel_invitation(uuid,uuid),verivaro_tenant_admin.redeem_invitation(uuid,uuid,bytea) TO verivaro_runtime;
COMMIT;
