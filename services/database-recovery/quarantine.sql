-- Restore-only; execute as isolated migration owner, before any non-admin access.
BEGIN;
CREATE TABLE verivaro_private.restore_quarantine(
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 backup_id uuid NOT NULL, quarantined_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON verivaro_private.restore_quarantine FROM PUBLIC;
INSERT INTO verivaro_private.restore_quarantine(backup_id) VALUES(:'backup_id'::uuid);
-- All pre-restore credentials are conservatively invalidated, including
-- recovery approvals tied to old lockdown IDs and restored operator generations.
WITH revoked AS (
 UPDATE verivaro_private.identity_sessions SET revoked_at=GREATEST(clock_timestamp(),created_at)
 WHERE revoked_at IS NULL RETURNING actor_id,session_id
)
INSERT INTO verivaro_private.identity_events(actor_id,session_id,kind)
 SELECT actor_id,session_id,'session_revoked' FROM revoked;
WITH actors AS (
 SELECT actor_id FROM verivaro.memberships UNION SELECT actor_id FROM verivaro.project_members
 UNION SELECT actor_id FROM verivaro_private.identity_sessions UNION SELECT actor_id FROM verivaro_private.disabled_actors
 UNION SELECT actor_id FROM verivaro_private.recovery_operators
 UNION SELECT actor_id FROM verivaro_private.provider_bindings
), disabled AS (
 INSERT INTO verivaro_private.disabled_actors(actor_id) SELECT actor_id FROM actors
 ON CONFLICT(actor_id) DO UPDATE SET lockdown_id=gen_random_uuid() RETURNING actor_id
)
INSERT INTO verivaro_private.identity_events(actor_id,kind) SELECT actor_id,'actor_disabled' FROM disabled;
UPDATE verivaro_private.recovery_operators SET active=false;
DELETE FROM verivaro_private.login_challenges;
DELETE FROM verivaro_private.browser_flows;
DELETE FROM verivaro_private.browser_sessions;
DELETE FROM verivaro_private.auth_telemetry;
DELETE FROM verivaro_private.api_rate_keys;
UPDATE verivaro_private.api_rate_state SET bucket=-1,requests=0;
WITH revoked AS (
 UPDATE verivaro_private.share_grants SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL RETURNING export_id,share_id,issuer_id
)
INSERT INTO verivaro_private.share_events(export_id,share_id,action,actor_id) SELECT export_id,share_id,'revoked',issuer_id FROM revoked;
UPDATE verivaro_private.context_key SET key_bytes=verivaro_private.gen_random_bytes(32);
-- Preserve durable resource leases for human reconciliation. Never resend old alerts.
UPDATE verivaro_private.alert_outbox SET state='dead',claim_id=NULL,claimed_by=NULL,claim_until=NULL
 WHERE state IN ('pending','sending');
UPDATE verivaro_private.monitor_state SET evaluated_at=NULL;
-- Explicitly remove the test-only signer if present; production never uses it.
DROP FUNCTION IF EXISTS verivaro_private.ci_sign(uuid,uuid,integer,text,integer);

CREATE TABLE verivaro_private.restoration_reviews(
 reviewer_login name PRIMARY KEY DEFAULT session_user,
 backup_id uuid NOT NULL, catalogue_sha256 text NOT NULL CHECK(catalogue_sha256 ~ '^[0-9a-f]{64}$'),
 inventory_sha256 text NOT NULL CHECK(inventory_sha256 ~ '^[0-9a-f]{64}$'),
 case_ref uuid NOT NULL UNIQUE,
 reviewed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER restoration_reviews_immutable BEFORE UPDATE OR DELETE OR TRUNCATE
 ON verivaro_private.restoration_reviews FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
REVOKE ALL ON verivaro_private.restoration_reviews FROM PUBLIC;
-- Approval attests to external review; the DB cannot prove the review or the
-- filesystem. A trusted administrator records the verified evidence receipt.
CREATE TABLE verivaro_private.restoration_evidence_receipt(
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 backup_id uuid NOT NULL, catalogue_sha256 text NOT NULL CHECK(catalogue_sha256 ~ '^[0-9a-f]{64}$'),
 inventory_sha256 text NOT NULL CHECK(inventory_sha256 ~ '^[0-9a-f]{64}$'),
 verified_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
-- Check receipt inventory against actual restored business rows, not a
-- caller-selected subset. UUID/hash alphabets make the canonical JSON exact.
CREATE FUNCTION verivaro_private.check_restoration_receipt() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $receipt$
DECLARE expected text; n bigint; unique_n bigint;
BEGIN
 SELECT encode(verivaro_private.digest(convert_to('['||COALESCE(string_agg(
 format('{"id":"%s","sha256":"%s"}',id,sha256),',' ORDER BY id,sha256),'')||']','UTF8'),'sha256'),'hex'),
 count(*),count(DISTINCT id) INTO expected,n,unique_n
 FROM (SELECT id,sha256 FROM verivaro.evidence UNION SELECT artifact_id,sha256 FROM verivaro_private.released_exports) q;
 IF n>4096 OR n<>unique_n OR expected<>NEW.inventory_sha256
 OR NOT EXISTS(SELECT 1 FROM verivaro_private.restore_quarantine WHERE backup_id=NEW.backup_id)
 THEN RAISE EXCEPTION 'restore receipt inventory mismatch' USING ERRCODE='42501'; END IF;
 RETURN NEW;
END $receipt$;
REVOKE ALL ON FUNCTION verivaro_private.check_restoration_receipt() FROM PUBLIC;
CREATE TRIGGER restoration_receipt_check BEFORE INSERT ON verivaro_private.restoration_evidence_receipt
 FOR EACH ROW EXECUTE FUNCTION verivaro_private.check_restoration_receipt();
CREATE TRIGGER restoration_receipt_immutable BEFORE UPDATE OR DELETE OR TRUNCATE
 ON verivaro_private.restoration_evidence_receipt FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
REVOKE ALL ON verivaro_private.restoration_evidence_receipt FROM PUBLIC;
CREATE FUNCTION verivaro_recovery.attest_review(b uuid,c text,h text,r uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $review$
BEGIN
 IF r IS NULL OR NOT EXISTS(SELECT 1 FROM verivaro_private.restore_quarantine q
 JOIN verivaro_private.restoration_evidence_receipt e ON e.backup_id=q.backup_id
 WHERE q.backup_id=b AND e.catalogue_sha256=c AND e.inventory_sha256=h)
 THEN RETURN false; END IF;
 INSERT INTO verivaro_private.restoration_reviews(backup_id,catalogue_sha256,inventory_sha256,case_ref)
 VALUES(b,c,h,r) ON CONFLICT(reviewer_login) DO NOTHING;
 RETURN FOUND;
END $review$;
CREATE FUNCTION verivaro_recovery.review_status() RETURNS TABLE(review_count bigint,review_ready boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $status$
 SELECT count(*),count(*)>=2 FROM verivaro_private.restoration_reviews v
 JOIN verivaro_private.restoration_evidence_receipt e ON e.backup_id=v.backup_id AND e.catalogue_sha256=v.catalogue_sha256 AND e.inventory_sha256=v.inventory_sha256
 JOIN pg_catalog.pg_roles p ON p.rolname=v.reviewer_login
 WHERE p.rolcanlogin AND NOT p.rolsuper AND pg_has_role(p.oid,'verivaro_restore_reviewer','MEMBER')
$status$;
REVOKE ALL ON FUNCTION verivaro_recovery.attest_review(uuid,text,text,uuid),verivaro_recovery.review_status() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_recovery.attest_review(uuid,text,text,uuid),verivaro_recovery.review_status() TO verivaro_restore_reviewer;

COMMIT;
