\set ON_ERROR_STOP on
-- Privileged test harness with fictional UUIDs, synthetic data and ephemeral key.
INSERT INTO vv_private.tenant(id,name) VALUES ('00000000-0000-0000-0000-000000000001','A'),('00000000-0000-0000-0000-000000000002','B');
INSERT INTO vv_private.identity VALUES ('10000000-0000-0000-0000-000000000001','synthetic','a'),('10000000-0000-0000-0000-000000000002','synthetic','b');
INSERT INTO vv_private.membership(tenant_id,actor_id,active,tenant_role) VALUES
 ('00000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000001',true,'owner'),
 ('00000000-0000-0000-0000-000000000002','10000000-0000-0000-0000-000000000002',true,'owner');
INSERT INTO vv_app.project(tenant_id,id,name,timezone,created_by) VALUES
 ('00000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000001','A1','Australia/Melbourne','10000000-0000-0000-0000-000000000001'),
 ('00000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000002','A2','Australia/Melbourne','10000000-0000-0000-0000-000000000001'),
 ('00000000-0000-0000-0000-000000000002','20000000-0000-0000-0000-000000000003','B1','Australia/Melbourne','10000000-0000-0000-0000-000000000002');
INSERT INTO vv_private.project_member(tenant_id,project_id,actor_id,role,active) VALUES
 ('00000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000001','owner',true),
 ('00000000-0000-0000-0000-000000000002','20000000-0000-0000-0000-000000000003','10000000-0000-0000-0000-000000000002','owner',true);
INSERT INTO vv_private.context_key VALUES ('30000000-0000-0000-0000-000000000001',vv_crypto.gen_random_bytes(32),true);
-- Test helper remains in temporary schema, never deployed or granted to runtime.
CREATE FUNCTION pg_temp.set_claim(t uuid,p uuid,a uuid, ttl integer DEFAULT 60, mver integer DEFAULT 1,pver integer DEFAULT 1)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE raw text; s bytea;
BEGIN
 raw:=jsonb_build_object('tenant',t,'project',p,'actor',a,'tx',pg_current_xact_id()::text,'key','30000000-0000-0000-0000-000000000001','exp',extract(epoch FROM statement_timestamp())::bigint+ttl,'member_version',mver,'project_version',pver)::text;
 SELECT secret INTO s FROM vv_private.context_key LIMIT 1;
 PERFORM set_config('verivaro.context',raw,true);
 PERFORM set_config('verivaro.signature',encode(vv_crypto.hmac(convert_to(raw,'UTF8'),s,'sha256'),'hex'),true);
END $$;
-- Catalogue and access checks.
DO $$
BEGIN
 IF EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('vv_app','vv_private') AND c.relkind='r' AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity)) THEN RAISE EXCEPTION 'RLS coverage missing'; END IF;
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN ('verivaro_runtime','verivaro_owner') AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcanlogin)) THEN RAISE EXCEPTION 'unsafe role'; END IF;
 IF pg_has_role('verivaro_runtime','verivaro_owner','MEMBER') THEN RAISE EXCEPTION 'owner escalation'; END IF;
 IF EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('vv_app','vv_private') AND c.relkind='r' AND (has_table_privilege('verivaro_runtime',c.oid,'INSERT') OR has_table_privilege('verivaro_runtime',c.oid,'UPDATE') OR has_table_privilege('verivaro_runtime',c.oid,'DELETE'))) THEN RAISE EXCEPTION 'runtime write exposed'; END IF;
 IF EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('vv_app','vv_private') AND c.relkind='r' AND c.oid<>'vv_app.project'::regclass AND has_table_privilege('verivaro_runtime',c.oid,'SELECT')) THEN RAISE EXCEPTION 'unexpected raw read'; END IF;
END $$;
BEGIN;
SET LOCAL ROLE verivaro_runtime;
DO $$ BEGIN IF (SELECT count(*) FROM vv_app.project)<>0 THEN RAISE EXCEPTION 'no-context leak'; END IF; END $$;
SELECT set_config('verivaro.context','{"tenant":"00000000-0000-0000-0000-000000000001"}',true);
SELECT set_config('verivaro.signature',repeat('0',64),true);
DO $$ BEGIN IF (SELECT count(*) FROM vv_app.project)<>0 THEN RAISE EXCEPTION 'forged claim leak'; END IF; END $$;
RESET ROLE;
SELECT pg_temp.set_claim('00000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000001');
SET LOCAL ROLE verivaro_runtime;
DO $$ BEGIN
 IF (SELECT array_agg(name) FROM vv_app.project) IS DISTINCT FROM ARRAY['A1']::text[] THEN RAISE EXCEPTION 'project isolation failed'; END IF;
 IF vv_private.allowed_project('00000000-0000-0000-0000-000000000002','20000000-0000-0000-0000-000000000003') THEN RAISE EXCEPTION 'cross tenant'; END IF;
 BEGIN PERFORM secret FROM vv_private.context_key; RAISE EXCEPTION 'secret leak'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN UPDATE vv_app.project SET name='tamper'; RAISE EXCEPTION 'write succeeded'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
SELECT current_setting('verivaro.context') AS oldclaim,current_setting('verivaro.signature') AS oldsig \gset
SELECT set_config('verivaro.signature',repeat('0',64),true);
DO $$ BEGIN IF (SELECT count(*) FROM vv_app.project)<>0 THEN RAISE EXCEPTION 'signature forgery'; END IF; END $$;
RESET ROLE;
SELECT pg_temp.set_claim('00000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000002','10000000-0000-0000-0000-000000000001');
SET LOCAL ROLE verivaro_runtime;
DO $$ BEGIN IF (SELECT count(*) FROM vv_app.project)<>0 THEN RAISE EXCEPTION 'signed nonmember'; END IF; END $$;
RESET ROLE;
SELECT pg_temp.set_claim('00000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000001',-1);
SET LOCAL ROLE verivaro_runtime;
DO $$ BEGIN IF (SELECT count(*) FROM vv_app.project)<>0 THEN RAISE EXCEPTION 'expired claims'; END IF; END $$;
RESET ROLE;
SELECT pg_temp.set_claim('00000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000001',60,2);
SET LOCAL ROLE verivaro_runtime;
DO $$ BEGIN IF (SELECT count(*) FROM vv_app.project)<>0 THEN RAISE EXCEPTION 'invalid membership version'; END IF; END $$;
RESET ROLE;
SELECT pg_temp.set_claim('00000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000001');
UPDATE vv_private.project_member SET active=false WHERE project_id='20000000-0000-0000-0000-000000000001';
SET LOCAL ROLE verivaro_runtime;
DO $$ BEGIN IF (SELECT count(*) FROM vv_app.project)<>0 THEN RAISE EXCEPTION 'revoked member'; END IF; END $$;
RESET ROLE;
ROLLBACK;
BEGIN;
SELECT pg_current_xact_id();
SET LOCAL ROLE verivaro_runtime;
SELECT set_config('verivaro.context',:'oldclaim',true),set_config('verivaro.signature',:'oldsig',true);
DO $$ BEGIN IF (SELECT count(*) FROM vv_app.project)<>0 THEN RAISE EXCEPTION 'transaction replay'; END IF; END $$;
RESET ROLE;
ROLLBACK;
-- A privileged writer cannot accidentally cross project boundaries through foreign keys.
INSERT INTO vv_app.document(tenant_id,project_id,id,title,created_by) VALUES ('00000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000001','40000000-0000-0000-0000-000000000001','Synthetic doc','10000000-0000-0000-0000-000000000001');
DO $$ BEGIN
 BEGIN INSERT INTO vv_app.document(tenant_id,project_id,id,title,created_by) VALUES ('00000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000002','40000000-0000-0000-0000-000000000002','wrong scope','10000000-0000-0000-0000-000000000001'); RAISE EXCEPTION 'cross project actor'; EXCEPTION WHEN foreign_key_violation THEN NULL; END;
 BEGIN INSERT INTO vv_app.document_version(tenant_id,project_id,id,document_id,revision,content_sha256,scan_state,extracted_text,created_by) VALUES ('00000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000001','50000000-0000-0000-0000-000000000001','40000000-0000-0000-0000-000000000001',1,repeat('a',64),'quarantined','must not parse','10000000-0000-0000-0000-000000000001'); RAISE EXCEPTION 'quarantine content'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
SELECT 'database foundation checks passed' AS result;
