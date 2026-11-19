-- Upgrade regression: old grants fail closed and reinstatement never restores shares.
SET ROLE verivaro_release_service;
SELECT verivaro_sharing.register_export('85000000-0000-4000-8000-000000000001','11111111-1111-4111-8111-111111111111','33333333-3333-4333-8333-333333333333','86000000-0000-4000-8000-000000000001',repeat('d',64),true);
RESET ROLE;
-- Simulate a pre-upgrade legacy grant for an otherwise accessible export.
INSERT INTO verivaro_private.share_grants(share_id,export_id,issuer_id,token_digest,created_at,expires_at) VALUES
 ('87000000-0000-4000-8000-000000000001','85000000-0000-4000-8000-000000000001','81000000-0000-4000-8000-000000000001',decode(repeat('61',32),'hex'),clock_timestamp(),clock_timestamp()+interval '10 minutes');
BEGIN;
SELECT verivaro_private.ci_sign('11111111-1111-4111-8111-111111111111','81000000-0000-4000-8000-000000000001',pg_backend_pid(),pg_current_xact_id()::text) AS signed \gset
SET ROLE verivaro_runtime;
SELECT set_config('verivaro.signed_context',:'signed',true);
SELECT verivaro_sharing.issue_share('85000000-0000-4000-8000-000000000001','87000000-0000-4000-8000-000000000002',decode(repeat('62',32),'hex'),clock_timestamp()+interval '10 minutes');
COMMIT;
RESET ROLE;
SET ROLE verivaro_share_gateway;
DO $initial$
BEGIN
 IF EXISTS(SELECT 1 FROM verivaro_sharing.resolve_share(decode(repeat('61',32),'hex')))
 OR NOT EXISTS(SELECT 1 FROM verivaro_sharing.resolve_share(decode(repeat('62',32),'hex')))
 THEN RAISE EXCEPTION 'legacy or current share generation mismatch'; END IF;
END $initial$;
RESET ROLE;
UPDATE verivaro.project_members SET revoked_at=clock_timestamp() WHERE actor_id='81000000-0000-4000-8000-000000000001';
UPDATE verivaro.project_members SET revoked_at=NULL WHERE actor_id='81000000-0000-4000-8000-000000000001';
SET ROLE verivaro_share_gateway;
DO $project$
BEGIN
 IF EXISTS(SELECT 1 FROM verivaro_sharing.resolve_share(decode(repeat('62',32),'hex')))
 THEN RAISE EXCEPTION 'project reinstatement revived historical link'; END IF;
END $project$;
RESET ROLE;
BEGIN;
SELECT verivaro_private.ci_sign('11111111-1111-4111-8111-111111111111','81000000-0000-4000-8000-000000000001',pg_backend_pid(),pg_current_xact_id()::text) AS signed \gset
SET ROLE verivaro_runtime;
SELECT set_config('verivaro.signed_context',:'signed',true);
SELECT verivaro_sharing.issue_share('85000000-0000-4000-8000-000000000001','87000000-0000-4000-8000-000000000003',decode(repeat('63',32),'hex'),clock_timestamp()+interval '10 minutes');
COMMIT;
RESET ROLE;
UPDATE verivaro.memberships SET role='viewer' WHERE actor_id='81000000-0000-4000-8000-000000000001';
UPDATE verivaro.memberships SET role='owner' WHERE actor_id='81000000-0000-4000-8000-000000000001';
SET ROLE verivaro_share_gateway;
DO $tenant$
BEGIN
 IF EXISTS(SELECT 1 FROM verivaro_sharing.resolve_share(decode(repeat('63',32),'hex')))
 THEN RAISE EXCEPTION 'tenant role reinstatement revived link'; END IF;
END $tenant$;
RESET ROLE;
BEGIN;
SELECT verivaro_private.ci_sign('11111111-1111-4111-8111-111111111111','81000000-0000-4000-8000-000000000001',pg_backend_pid(),pg_current_xact_id()::text) AS signed \gset
SET ROLE verivaro_runtime;
SELECT set_config('verivaro.signed_context',:'signed',true);
SELECT verivaro_sharing.issue_share('85000000-0000-4000-8000-000000000001','87000000-0000-4000-8000-000000000004',decode(repeat('64',32),'hex'),clock_timestamp()+interval '10 minutes');
COMMIT;
RESET ROLE;
-- Synthetic privileged fixture isolates the generation check from the separately
-- tested dual-approval recovery and session lifecycle.
INSERT INTO verivaro_private.disabled_actors(actor_id) VALUES('81000000-0000-4000-8000-000000000001');
DELETE FROM verivaro_private.disabled_actors WHERE actor_id='81000000-0000-4000-8000-000000000001';
SET ROLE verivaro_share_gateway;
DO $actor$
BEGIN
 IF EXISTS(SELECT 1 FROM verivaro_sharing.resolve_share(decode(repeat('64',32),'hex')))
 THEN RAISE EXCEPTION 'account reinstatement revived link'; END IF;
END $actor$;
RESET ROLE;
BEGIN;
SELECT verivaro_private.ci_sign('11111111-1111-4111-8111-111111111111','81000000-0000-4000-8000-000000000001',pg_backend_pid(),pg_current_xact_id()::text) AS signed \gset
SET ROLE verivaro_runtime;
SELECT set_config('verivaro.signed_context',:'signed',true);
SELECT verivaro_sharing.issue_share('85000000-0000-4000-8000-000000000001','87000000-0000-4000-8000-000000000005',decode(repeat('65',32),'hex'),clock_timestamp()+interval '10 minutes');
COMMIT;
RESET ROLE;
SET ROLE verivaro_share_gateway;
DO $fresh$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM verivaro_sharing.resolve_share(decode(repeat('65',32),'hex')))
 THEN RAISE EXCEPTION 'fresh grant after restoration denied'; END IF;
 IF EXISTS(SELECT 1 FROM verivaro_sharing.resolve_share(decode(repeat('62',32),'hex')))
 OR EXISTS(SELECT 1 FROM verivaro_sharing.resolve_share(decode(repeat('63',32),'hex')))
 OR EXISTS(SELECT 1 FROM verivaro_sharing.resolve_share(decode(repeat('64',32),'hex')))
 THEN RAISE EXCEPTION 'revoked generations resurrected'; END IF;
END $fresh$;
RESET ROLE;
