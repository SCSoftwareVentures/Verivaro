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
), disabled AS (
 INSERT INTO verivaro_private.disabled_actors(actor_id) SELECT actor_id FROM actors
 ON CONFLICT(actor_id) DO UPDATE SET lockdown_id=gen_random_uuid() RETURNING actor_id
)
INSERT INTO verivaro_private.identity_events(actor_id,kind) SELECT actor_id,'actor_disabled' FROM disabled;
UPDATE verivaro_private.recovery_operators SET active=false;
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
COMMIT;
