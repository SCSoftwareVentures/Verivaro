-- v2 is mandatory after migration. Previous signed contexts are deliberately invalid.
BEGIN;
CREATE TABLE verivaro_private.identity_sessions (
 session_id uuid PRIMARY KEY,
 actor_id uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL,
 revoked_at timestamptz,
 CHECK (expires_at>created_at),
 CHECK (revoked_at IS NULL OR revoked_at>=created_at)
);
CREATE INDEX identity_sessions_actor_idx ON verivaro_private.identity_sessions(actor_id);
REVOKE ALL ON verivaro_private.identity_sessions FROM PUBLIC,verivaro_runtime;
-- An existing identifier cannot be reactivated or reassigned. Recovery uses a new session.
CREATE FUNCTION verivaro_private.guard_session_history() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'session deletion prohibited' USING ERRCODE='42501'; END IF;
 IF NEW.session_id IS DISTINCT FROM OLD.session_id OR NEW.actor_id IS DISTINCT FROM OLD.actor_id
 OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
 OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL
 THEN RAISE EXCEPTION 'session history is immutable except initial revocation' USING ERRCODE='42501'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION verivaro_private.guard_session_history() FROM PUBLIC;
CREATE TRIGGER session_history BEFORE UPDATE OR DELETE ON verivaro_private.identity_sessions
 FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_session_history();
CREATE OR REPLACE FUNCTION verivaro.bound_context() RETURNS text[]
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, verivaro_private
AS $$
DECLARE raw text; parts text[]; payload text; k bytea; expected bytea; now_epoch bigint;
BEGIN
  raw := current_setting('verivaro.signed_context', true);
  IF raw IS NULL OR length(raw) > 240 OR raw !~ '^v2[|][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[|][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[|][1-9][0-9]{0,9}[|][1-9][0-9]{0,19}[|][1-9][0-9]{0,11}[|][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[|][0-9a-f]{64}$' THEN
    RETURN NULL;
  END IF;
  parts := string_to_array(raw, '|');
  IF parts[4] IS DISTINCT FROM pg_backend_pid()::text
     OR parts[5] IS DISTINCT FROM pg_current_xact_id_if_assigned()::text THEN RETURN NULL; END IF;
  now_epoch := floor(extract(epoch FROM statement_timestamp()))::bigint;
  IF parts[6]::bigint <= now_epoch OR parts[6]::bigint > now_epoch + 60 THEN RETURN NULL; END IF;
  SELECT key_bytes INTO k FROM verivaro_private.context_key WHERE singleton;
  IF k IS NULL THEN RETURN NULL; END IF;
  payload := array_to_string(parts[1:7], '|');
  expected := verivaro_private.hmac(convert_to(payload, 'UTF8'), k, 'sha256');
  -- Double HMAC prevents a caller from choosing a comparison prefix.
  IF verivaro_private.hmac(decode(parts[8], 'hex'), k, 'sha256')
     IS DISTINCT FROM verivaro_private.hmac(expected, k, 'sha256') THEN RETURN NULL; END IF;
  IF NOT EXISTS (SELECT 1 FROM verivaro_private.identity_sessions s
    WHERE s.session_id=parts[7]::uuid AND s.actor_id=parts[3]::uuid
      AND s.revoked_at IS NULL AND s.expires_at>statement_timestamp()
      AND to_timestamp(parts[6]::bigint)<=s.expires_at) THEN RETURN NULL; END IF;
  RETURN ARRAY[parts[2], parts[3], parts[7]];
END $$;
REVOKE ALL ON FUNCTION verivaro.bound_context() FROM PUBLIC;
COMMIT;
