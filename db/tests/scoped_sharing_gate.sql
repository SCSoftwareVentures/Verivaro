-- Disposable fixtures: one owner and one viewer in same tenant, other tenant export.
INSERT INTO verivaro.memberships(tenant_id,actor_id,role) VALUES
 ('11111111-1111-4111-8111-111111111111','81000000-0000-4000-8000-000000000001','owner'),
 ('11111111-1111-4111-8111-111111111111','81000000-0000-4000-8000-000000000002','viewer');
INSERT INTO verivaro.project_members(tenant_id,project_id,actor_id,role) VALUES
 ('11111111-1111-4111-8111-111111111111','33333333-3333-4333-8333-333333333333','81000000-0000-4000-8000-000000000001','owner'),
 ('11111111-1111-4111-8111-111111111111','33333333-3333-4333-8333-333333333333','81000000-0000-4000-8000-000000000002','viewer');
SET ROLE verivaro_release_service;
SELECT verivaro_sharing.register_export('82000000-0000-4000-8000-000000000001','11111111-1111-4111-8111-111111111111','33333333-3333-4333-8333-333333333333','83000000-0000-4000-8000-000000000001',repeat('a',64),true);
SELECT verivaro_sharing.register_export('82000000-0000-4000-8000-000000000002','22222222-2222-4222-8222-222222222222','44444444-4444-4444-8444-444444444444','83000000-0000-4000-8000-000000000002',repeat('b',64),true);
SELECT verivaro_sharing.register_export('82000000-0000-4000-8000-000000000003','11111111-1111-4111-8111-111111111111','33333333-3333-4333-8333-333333333333','83000000-0000-4000-8000-000000000003',repeat('c',64));
RESET ROLE;
DO $acl$
BEGIN
 IF has_schema_privilege('verivaro_share_gateway','verivaro','USAGE')
 OR has_schema_privilege('verivaro_share_gateway','verivaro_private','USAGE')
 OR has_function_privilege('verivaro_share_gateway','verivaro_sharing.issue_share(uuid,uuid,bytea,timestamptz)','EXECUTE')
 OR has_function_privilege('verivaro_runtime','verivaro_sharing.resolve_share(bytea)','EXECUTE')
 OR has_function_privilege('verivaro_runtime','verivaro_sharing.register_export(uuid,uuid,uuid,uuid,text,boolean)','EXECUTE')
 OR has_table_privilege('verivaro_runtime','verivaro_private.share_grants','SELECT')
 OR has_table_privilege('verivaro_share_gateway','verivaro_private.released_exports','SELECT')
 THEN RAISE EXCEPTION 'share role boundary broken'; END IF;
END $acl$;
BEGIN;
SELECT verivaro_private.ci_sign('11111111-1111-4111-8111-111111111111','81000000-0000-4000-8000-000000000001',pg_backend_pid(),pg_current_xact_id()::text) AS signed \gset
SET ROLE verivaro_runtime;
SELECT set_config('verivaro.signed_context',:'signed',true);
SELECT verivaro_sharing.issue_share('82000000-0000-4000-8000-000000000001','84000000-0000-4000-8000-000000000001',decode(repeat('11',32),'hex'),clock_timestamp()+interval '10 minutes');
SELECT verivaro_sharing.issue_share('82000000-0000-4000-8000-000000000001','84000000-0000-4000-8000-000000000002',decode(repeat('22',32),'hex'),clock_timestamp()+interval '10 minutes');
DO $deny$
BEGIN
 BEGIN
 PERFORM verivaro_sharing.issue_share('82000000-0000-4000-8000-000000000002','84000000-0000-4000-8000-000000000003',decode(repeat('33',32),'hex'),clock_timestamp()+interval '10 minutes');
 RAISE EXCEPTION 'cross-tenant share issued';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN
 PERFORM verivaro_sharing.issue_share('82000000-0000-4000-8000-000000000003','84000000-0000-4000-8000-000000000003',decode(repeat('33',32),'hex'),clock_timestamp()+interval '10 minutes');
 RAISE EXCEPTION 'sensitive export shared as bearer';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN
 PERFORM verivaro_sharing.issue_share('82000000-0000-4000-8000-000000000001','84000000-0000-4000-8000-000000000003',decode(repeat('33',32),'hex'),clock_timestamp()+interval '25 hours');
 RAISE EXCEPTION 'excessive expiry accepted';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $deny$;
SELECT verivaro_sharing.revoke_share('84000000-0000-4000-8000-000000000002');
COMMIT;
RESET ROLE;
BEGIN;
SELECT verivaro_private.ci_sign('11111111-1111-4111-8111-111111111111','81000000-0000-4000-8000-000000000002',pg_backend_pid(),pg_current_xact_id()::text) AS signed \gset
SET ROLE verivaro_runtime;
SELECT set_config('verivaro.signed_context',:'signed',true);
DO $viewer$
BEGIN
 BEGIN
 PERFORM verivaro_sharing.issue_share('82000000-0000-4000-8000-000000000001','84000000-0000-4000-8000-000000000004',decode(repeat('44',32),'hex'),clock_timestamp()+interval '10 minutes');
 RAISE EXCEPTION 'viewer issued share';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN
 PERFORM verivaro_sharing.revoke_share('84000000-0000-4000-8000-000000000001');
 RAISE EXCEPTION 'viewer revoked share';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $viewer$;
ROLLBACK;
RESET ROLE;
INSERT INTO verivaro_private.share_grants(share_id,export_id,issuer_id,token_digest,created_at,expires_at)
 VALUES('84000000-0000-4000-8000-000000000005','82000000-0000-4000-8000-000000000001','81000000-0000-4000-8000-000000000001',decode(repeat('55',32),'hex'),clock_timestamp()-interval '20 minutes',clock_timestamp()-interval '10 minutes');
SET ROLE verivaro_share_gateway;
DO $resolve$
DECLARE n integer; found_id uuid; hash text;
BEGIN
 SELECT count(*) INTO n FROM verivaro_sharing.resolve_share(decode(repeat('11',32),'hex'));
 IF n<>1 THEN RAISE EXCEPTION 'valid share denied'; END IF;
 SELECT artifact_id,sha256 INTO found_id,hash FROM verivaro_sharing.resolve_share(decode(repeat('11',32),'hex'));
 IF found_id<>'83000000-0000-4000-8000-000000000001' OR hash<>repeat('a',64) THEN RAISE EXCEPTION 'wrong export returned'; END IF;
 IF EXISTS(SELECT 1 FROM verivaro_sharing.resolve_share(decode(repeat('22',32),'hex')))
 OR EXISTS(SELECT 1 FROM verivaro_sharing.resolve_share(decode(repeat('55',32),'hex')))
 OR EXISTS(SELECT 1 FROM verivaro_sharing.resolve_share(decode(repeat('ff',32),'hex')))
 OR EXISTS(SELECT 1 FROM verivaro_sharing.resolve_share(decode('aa','hex')))
 THEN RAISE EXCEPTION 'invalid, expired or revoked grant resolved'; END IF;
END $resolve$;
RESET ROLE;
UPDATE verivaro.project_members SET revoked_at=clock_timestamp() WHERE actor_id='81000000-0000-4000-8000-000000000001';
SET ROLE verivaro_share_gateway;
DO $revoked_issuer$
BEGIN
 IF EXISTS(SELECT 1 FROM verivaro_sharing.resolve_share(decode(repeat('11',32),'hex'))) THEN RAISE EXCEPTION 'revoked issuer still shares'; END IF;
END $revoked_issuer$;
RESET ROLE;
UPDATE verivaro.project_members SET revoked_at=NULL WHERE actor_id='81000000-0000-4000-8000-000000000001';
SET ROLE verivaro_release_service;
SELECT verivaro_sharing.revoke_export('82000000-0000-4000-8000-000000000001');
RESET ROLE;
SET ROLE verivaro_share_gateway;
DO $export_revoked$
BEGIN
 IF EXISTS(SELECT 1 FROM verivaro_sharing.resolve_share(decode(repeat('11',32),'hex'))) THEN RAISE EXCEPTION 'revoked export still resolves'; END IF;
END $export_revoked$;
RESET ROLE;
DO $audit$
BEGIN
 IF (SELECT count(*) FROM verivaro_private.share_events WHERE action='issued')<>2
 OR (SELECT count(*) FROM verivaro_private.share_events WHERE action='accessed')<>2
 OR (SELECT count(*) FROM verivaro_private.share_events WHERE action='revoked')<>1
 OR (SELECT count(*) FROM verivaro_private.share_events WHERE action='export_revoked')<>1
 THEN RAISE EXCEPTION 'share audit mismatch'; END IF;
 BEGIN
 DELETE FROM verivaro_private.share_events;
 RAISE EXCEPTION 'share audit history deleted';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $audit$;
