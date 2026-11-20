-- G1 SECURITY GATE: a caller must not be able to impersonate another tenant
-- merely by setting custom PostgreSQL GUCs. Never weaken this assertion.
-- Prior fixture scripts revoked actor A but left actor B active.
SET ROLE verivaro_runtime;
BEGIN;
SELECT set_config('verivaro.tenant_id','22222222-2222-4222-8222-222222222222',true);
SELECT set_config('verivaro.actor_id','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',true);
DO $$
DECLARE visible_projects integer;
BEGIN
 SELECT count(*) INTO visible_projects FROM verivaro.projects;
 IF visible_projects <> 0 THEN
   RAISE EXCEPTION 'SECURITY FAILURE: untrusted runtime SQL can impersonate tenant B (visible projects=%)', visible_projects;
 END IF;
END $$;
ROLLBACK;
RESET ROLE;
