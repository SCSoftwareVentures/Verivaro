-- CI: positive authorization, tampering, replay, expired/future scopes, stale identity.
BEGIN;
SELECT verivaro_private.ci_sign('22222222-2222-4222-8222-222222222222','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',pg_backend_pid(),pg_current_xact_id()::text) AS valid,
       verivaro_private.ci_sign('22222222-2222-4222-8222-222222222222','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',pg_backend_pid(),pg_current_xact_id()::text,-1) AS expired,
       verivaro_private.ci_sign('22222222-2222-4222-8222-222222222222','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',pg_backend_pid(),pg_current_xact_id()::text,600) AS future,
       verivaro_private.ci_sign('22222222-2222-4222-8222-222222222222','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',pg_backend_pid()+1,pg_current_xact_id()::text) AS wrong_backend
\gset
SET ROLE verivaro_runtime;
SELECT set_config('verivaro.signed_context', :'valid', true);
DO $$ BEGIN
 IF (SELECT count(*) FROM verivaro.projects WHERE id='44444444-4444-4444-8444-444444444444') <> 1 OR
    (SELECT count(*) FROM verivaro.projects) <> 1 THEN RAISE EXCEPTION 'valid context not isolated'; END IF;
END $$;
SELECT set_config('verivaro.signed_context', replace(:'valid','22222222-2222-4222-8222-222222222222','11111111-1111-4111-8111-111111111111'), true);
DO $$ BEGIN IF EXISTS(SELECT 1 FROM verivaro.projects) THEN RAISE EXCEPTION 'tampered tenant accepted'; END IF; END $$;
SELECT set_config('verivaro.signed_context', :'expired', true);
DO $$ BEGIN IF EXISTS(SELECT 1 FROM verivaro.projects) THEN RAISE EXCEPTION 'expired context accepted'; END IF; END $$;
SELECT set_config('verivaro.signed_context', :'future', true);
DO $$ BEGIN IF EXISTS(SELECT 1 FROM verivaro.projects) THEN RAISE EXCEPTION 'overlong context accepted'; END IF; END $$;
SELECT set_config('verivaro.signed_context', :'wrong_backend', true);
DO $$ BEGIN IF EXISTS(SELECT 1 FROM verivaro.projects) THEN RAISE EXCEPTION 'wrong backend accepted'; END IF; END $$;
COMMIT;
BEGIN;
SELECT pg_current_xact_id();
SELECT set_config('verivaro.signed_context', :'valid', true);
DO $$ BEGIN IF EXISTS(SELECT 1 FROM verivaro.projects) THEN RAISE EXCEPTION 'transaction replay accepted'; END IF; END $$;
ROLLBACK;
RESET ROLE;
