-- Explicit same-tenant project assignment, role intersection and active revocation.
INSERT INTO verivaro.projects(id,tenant_id,name) VALUES
 ('88888888-8888-4888-8888-888888888888','11111111-1111-4111-8111-111111111111','Restricted A project');
INSERT INTO verivaro.evidence(id,tenant_id,project_id,sha256,storage_ref,created_by) VALUES
 ('99999999-9999-4999-8999-999999999999','11111111-1111-4111-8111-111111111111','88888888-8888-4888-8888-888888888888',repeat('f',64),'quarantine://synthetic/hidden','cccccccc-cccc-4ccc-8ccc-cccccccccccc');
-- Give tenant B viewer a project owner role; tenant permission must still cap authority.
UPDATE verivaro.project_members SET role='owner' WHERE actor_id='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
BEGIN;
SELECT verivaro_private.ci_sign('11111111-1111-4111-8111-111111111111','cccccccc-cccc-4ccc-8ccc-cccccccccccc',pg_backend_pid(),pg_current_xact_id()::text) AS signed \gset
SET ROLE verivaro_runtime;
SELECT set_config('verivaro.signed_context',:'signed',true);
DO $$ BEGIN
 IF (SELECT count(*) FROM verivaro.projects)<>1 OR
 EXISTS(SELECT 1 FROM verivaro.evidence WHERE project_id='88888888-8888-4888-8888-888888888888')
 THEN RAISE EXCEPTION 'same-tenant project leakage'; END IF;
 IF NOT verivaro.project_access('11111111-1111-4111-8111-111111111111','33333333-3333-4333-8333-333333333333','contribute')
 OR verivaro.project_access('11111111-1111-4111-8111-111111111111','33333333-3333-4333-8333-333333333333','review')
 THEN RAISE EXCEPTION 'contributor permission mismatch'; END IF;
 BEGIN
 INSERT INTO verivaro.evidence(id,tenant_id,project_id,sha256,storage_ref,created_by) VALUES
 ('77777777-7777-4777-8777-777777777777','11111111-1111-4111-8111-111111111111','88888888-8888-4888-8888-888888888888',repeat('e',64),'quarantine://synthetic/forbidden','cccccccc-cccc-4ccc-8ccc-cccccccccccc');
 RAISE EXCEPTION 'unassigned project write succeeded';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
-- Separate privileged connection revokes project grant while the runtime transaction is open.
\! psql -X -v ON_ERROR_STOP=1 -c "UPDATE verivaro.project_members SET revoked_at=clock_timestamp() WHERE actor_id='cccccccc-cccc-4ccc-8ccc-cccccccccccc'"
DO $$ BEGIN IF EXISTS(SELECT 1 FROM verivaro.projects) THEN RAISE EXCEPTION 'project revocation not observed'; END IF; END $$;
ROLLBACK;
RESET ROLE;
BEGIN;
SELECT verivaro_private.ci_sign('22222222-2222-4222-8222-222222222222','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',pg_backend_pid(),pg_current_xact_id()::text) AS signed \gset
SET ROLE verivaro_runtime;
SELECT set_config('verivaro.signed_context',:'signed',true);
DO $$ BEGIN
 IF (SELECT count(*) FROM verivaro.projects)<>1 OR
 verivaro.project_access('22222222-2222-4222-8222-222222222222','44444444-4444-4444-8444-444444444444','contribute')
 THEN RAISE EXCEPTION 'tenant role cap broken'; END IF;
END $$;
\! psql -X -v ON_ERROR_STOP=1 -c "INSERT INTO verivaro_private.disabled_actors(actor_id) VALUES ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb')"
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM verivaro.projects) OR EXISTS(SELECT 1 FROM verivaro.memberships) OR EXISTS(SELECT 1 FROM verivaro.tenants)
 THEN RAISE EXCEPTION 'disabled identity retained access'; END IF;
END $$;
ROLLBACK;
RESET ROLE;
-- Snapshot isolation is deliberately denied, even with a valid principal.
BEGIN ISOLATION LEVEL REPEATABLE READ;
SELECT verivaro_private.ci_sign('11111111-1111-4111-8111-111111111111','dddddddd-dddd-4ddd-8ddd-dddddddddddd',pg_backend_pid(),pg_current_xact_id()::text) AS signed \gset
SET ROLE verivaro_runtime;
SELECT set_config('verivaro.signed_context',:'signed',true);
DO $$ BEGIN IF EXISTS(SELECT 1 FROM verivaro.projects) THEN RAISE EXCEPTION 'stale-snapshot access enabled'; END IF; END $$;
ROLLBACK;
RESET ROLE;
