-- Disposable PostgreSQL integration checks. Run only against ephemeral CI database.
ALTER ROLE verivaro_runtime LOGIN PASSWORD 'ci-only-not-a-secret'; -- ephemeral CI only
INSERT INTO verivaro.tenants(id,name) VALUES
 ('11111111-1111-4111-8111-111111111111','Tenant A'),
 ('22222222-2222-4222-8222-222222222222','Tenant B');
INSERT INTO verivaro.memberships(tenant_id,actor_id,role) VALUES
 ('11111111-1111-4111-8111-111111111111','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','contributor'),
 ('22222222-2222-4222-8222-222222222222','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','viewer');
INSERT INTO verivaro.projects(id,tenant_id,name) VALUES
 ('33333333-3333-4333-8333-333333333333','11111111-1111-4111-8111-111111111111','A project'),
 ('44444444-4444-4444-8444-444444444444','22222222-2222-4222-8222-222222222222','B project');
INSERT INTO verivaro.project_members(tenant_id,project_id,actor_id,role) VALUES
 ('11111111-1111-4111-8111-111111111111','33333333-3333-4333-8333-333333333333','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','contributor'),
 ('22222222-2222-4222-8222-222222222222','44444444-4444-4444-8444-444444444444','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','viewer');
SET ROLE verivaro_runtime;
DO $
DECLARE n integer;
BEGIN
  SELECT count(*) INTO n FROM verivaro.projects;
  IF n <> 0 THEN RAISE EXCEPTION 'fail-open without context'; END IF;
END $$;
BEGIN;
RESET ROLE;
SELECT verivaro_private.ci_sign('11111111-1111-4111-8111-111111111111','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',pg_backend_pid(),pg_current_xact_id()::text) AS signed \gset
SET ROLE verivaro_runtime;
SELECT set_config('verivaro.signed_context', :'signed', true);
DO $$
DECLARE n integer;
BEGIN
 SELECT count(*) INTO n FROM verivaro.projects;
 IF n <> 1 THEN RAISE EXCEPTION 'tenant A isolation failed: %', n; END IF;
END $$;
INSERT INTO verivaro.evidence(id,tenant_id,project_id,sha256,storage_ref,created_by)
VALUES ('55555555-5555-4555-8555-555555555555','11111111-1111-4111-8111-111111111111',
'33333333-3333-4333-8333-333333333333',repeat('a',64),'quarantine://synthetic/a',
'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa');
DO $$
BEGIN
 BEGIN
  UPDATE verivaro.evidence SET storage_ref='changed' WHERE id='55555555-5555-4555-8555-555555555555';
  RAISE EXCEPTION 'mutation unexpectedly succeeded';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;
COMMIT;
-- SET LOCAL must not leak tenant context into a subsequent transaction.
DO $$
DECLARE n integer;
BEGIN
 SELECT count(*) INTO n FROM verivaro.projects;
 IF n <> 0 THEN RAISE EXCEPTION 'transaction context leaked'; END IF;
END $$;
RESET ROLE;
UPDATE verivaro.memberships SET revoked_at=now()
WHERE actor_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
SET ROLE verivaro_runtime;
BEGIN;
RESET ROLE;
SELECT verivaro_private.ci_sign('11111111-1111-4111-8111-111111111111','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',pg_backend_pid(),pg_current_xact_id()::text) AS signed \gset
SET ROLE verivaro_runtime;
SELECT set_config('verivaro.signed_context', :'signed', true);
DO $$
DECLARE n integer;
BEGIN
 SELECT count(*) INTO n FROM verivaro.projects;
 IF n <> 0 THEN RAISE EXCEPTION 'revoked actor retained access'; END IF;
END $$;
ROLLBACK;
RESET ROLE;
