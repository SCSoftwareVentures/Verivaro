-- G1: independently approved, single-use recovery tied to a specific lockdown.
BEGIN;
CREATE ROLE verivaro_recovery_approver NOLOGIN NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
GRANT USAGE ON SCHEMA verivaro_identity TO verivaro_recovery_approver;
ALTER TABLE verivaro_private.disabled_actors ADD COLUMN lockdown_id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE;

-- Provisioned by a trusted administrator, never by the recovery executor.
-- Distinct PostgreSQL login principals must map to distinct verified people.
CREATE TABLE verivaro_private.recovery_operators(
 login_name name PRIMARY KEY,
 actor_id uuid NOT NULL UNIQUE,
 active boolean NOT NULL DEFAULT true
);
CREATE TABLE verivaro_private.recovery_requests(
 request_id uuid PRIMARY KEY,
 actor_id uuid NOT NULL,
 lockdown_id uuid NOT NULL,
 requested_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 CHECK(expires_at>requested_at)
);
CREATE TABLE verivaro_private.recovery_approvals(
 request_id uuid NOT NULL REFERENCES verivaro_private.recovery_requests(request_id),
 approver_id uuid NOT NULL,
 approved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(request_id,approver_id)
);
REVOKE ALL ON verivaro_private.recovery_operators,verivaro_private.recovery_requests,verivaro_private.recovery_approvals FROM PUBLIC;
CREATE TRIGGER recovery_requests_immutable BEFORE UPDATE OR DELETE OR TRUNCATE
 ON verivaro_private.recovery_requests FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER recovery_approvals_immutable BEFORE UPDATE OR DELETE OR TRUNCATE
 ON verivaro_private.recovery_approvals FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();

CREATE FUNCTION verivaro_identity.request_recovery(a uuid,r uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $req$
DECLARE lockdown uuid; n timestamptz;
BEGIN
 PERFORM verivaro_private.lock_identity(a);
 SELECT d.lockdown_id INTO lockdown FROM verivaro_private.disabled_actors d WHERE d.actor_id=a;
 IF NOT FOUND OR r IS NULL THEN RAISE EXCEPTION 'recovery request denied' USING ERRCODE='42501'; END IF;
 n:=clock_timestamp();
 INSERT INTO verivaro_private.recovery_requests VALUES(r,a,lockdown,n,n+interval '15 minutes');
END $req$;

CREATE FUNCTION verivaro_identity.approve_recovery(r uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $approve$
DECLARE req verivaro_private.recovery_requests%ROWTYPE; operator_id uuid;
BEGIN
 SELECT * INTO req FROM verivaro_private.recovery_requests WHERE request_id=r;
 IF NOT FOUND THEN RAISE EXCEPTION 'recovery approval denied' USING ERRCODE='42501'; END IF;
 PERFORM verivaro_private.lock_identity(req.actor_id);
 SELECT actor_id INTO operator_id FROM verivaro_private.recovery_operators
 WHERE login_name=session_user AND active;
 IF operator_id IS NULL OR operator_id=req.actor_id OR req.expires_at<=clock_timestamp()
 OR NOT EXISTS(SELECT 1 FROM verivaro_private.disabled_actors d WHERE d.actor_id=req.actor_id AND d.lockdown_id=req.lockdown_id)
 OR EXISTS(SELECT 1 FROM verivaro_private.identity_events WHERE authorization_ref=r)
 THEN RAISE EXCEPTION 'recovery approval denied' USING ERRCODE='42501'; END IF;
 INSERT INTO verivaro_private.recovery_approvals(request_id,approver_id) VALUES(r,operator_id);
END $approve$;

-- Replace the old UUID-only authorization interface; no legacy bypass remains.
CREATE OR REPLACE FUNCTION verivaro_identity.recover_actor(a uuid,approval uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $recover$
DECLARE n timestamptz; req verivaro_private.recovery_requests%ROWTYPE; approved_count integer;
BEGIN
 PERFORM verivaro_private.lock_identity(a);
 SELECT * INTO req FROM verivaro_private.recovery_requests WHERE request_id=approval AND actor_id=a;
 IF NOT FOUND OR req.expires_at<=clock_timestamp()
 OR NOT EXISTS(SELECT 1 FROM verivaro_private.disabled_actors d WHERE d.actor_id=a AND d.lockdown_id=req.lockdown_id)
 OR EXISTS(SELECT 1 FROM verivaro_private.identity_events WHERE authorization_ref=approval)
 THEN RAISE EXCEPTION 'recovery denied' USING ERRCODE='42501'; END IF;
 -- Lock participating operator rows through commit; concurrent deactivation
 -- cannot slip between the approval decision and recovery.
 PERFORM o.actor_id FROM verivaro_private.recovery_operators o
 JOIN verivaro_private.recovery_approvals p ON p.approver_id=o.actor_id
 WHERE p.request_id=approval ORDER BY o.actor_id FOR SHARE OF o;
 SELECT count(*) INTO approved_count
 FROM verivaro_private.recovery_approvals p JOIN verivaro_private.recovery_operators o ON o.actor_id=p.approver_id
 WHERE p.request_id=approval AND o.active AND p.approver_id<>a
 AND p.approved_at>=req.requested_at AND p.approved_at<req.expires_at;
 n:=clock_timestamp();
 IF approved_count<2 OR n>=req.expires_at THEN RAISE EXCEPTION 'recovery denied' USING ERRCODE='42501'; END IF;
 UPDATE verivaro_private.identity_sessions SET revoked_at=n WHERE actor_id=a AND revoked_at IS NULL;
 INSERT INTO verivaro_private.identity_fences(actor_id,authenticated_after) VALUES(a,n)
 ON CONFLICT(actor_id) DO UPDATE SET authenticated_after=GREATEST(verivaro_private.identity_fences.authenticated_after,EXCLUDED.authenticated_after);
 INSERT INTO verivaro_private.identity_events(actor_id,kind,authorization_ref) VALUES(a,'actor_recovered',approval);
 DELETE FROM verivaro_private.disabled_actors WHERE actor_id=a AND lockdown_id=req.lockdown_id;
END $recover$;

REVOKE ALL ON FUNCTION verivaro_identity.request_recovery(uuid,uuid),verivaro_identity.approve_recovery(uuid),verivaro_identity.recover_actor(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_identity.request_recovery(uuid,uuid),verivaro_identity.recover_actor(uuid,uuid) TO verivaro_recovery_service;
GRANT EXECUTE ON FUNCTION verivaro_identity.approve_recovery(uuid) TO verivaro_recovery_approver;
COMMIT;
