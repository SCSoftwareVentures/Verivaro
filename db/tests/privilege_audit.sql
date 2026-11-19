-- Privilege and FORCE RLS regression checks on disposable CI database.
DO $$
DECLARE t text;
BEGIN
 SELECT rolname INTO t FROM pg_roles WHERE rolname='verivaro_runtime' AND (rolsuper OR rolbypassrls OR rolinherit);
 IF t IS NOT NULL THEN RAISE EXCEPTION 'runtime role has privileged attributes: %',t; END IF;
 FOREACH t IN ARRAY ARRAY['tenants','projects','memberships','evidence','project_members'] LOOP
  IF NOT EXISTS (
   SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='verivaro' AND c.relname=t AND c.relrowsecurity AND c.relforcerowsecurity
  ) THEN RAISE EXCEPTION 'missing FORCE RLS on %',t; END IF;
  IF pg_has_role('verivaro_runtime', (SELECT c.relowner FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='verivaro' AND c.relname=t),'MEMBER')
  THEN RAISE EXCEPTION 'runtime role is table owner/member: %',t; END IF;
  IF has_table_privilege('verivaro_runtime','verivaro.'||t,'TRUNCATE')
  THEN RAISE EXCEPTION 'runtime has TRUNCATE privilege on %',t; END IF;
 END LOOP;
END $$;

DO $$ BEGIN
 IF has_schema_privilege('verivaro_runtime','verivaro_private','USAGE') OR
    has_table_privilege('verivaro_runtime','verivaro_private.context_key','SELECT') OR
    has_function_privilege('verivaro_runtime','verivaro_private.ci_sign(uuid,uuid,integer,text,integer)','EXECUTE')
 THEN RAISE EXCEPTION 'runtime has access to signing boundary'; END IF;
END $$;

DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['tenants','projects','memberships','project_members','evidence'] LOOP
 IF has_table_privilege('verivaro_runtime','verivaro.'||t,'UPDATE') OR
    has_table_privilege('verivaro_runtime','verivaro.'||t,'DELETE') OR
    (t<>'evidence' AND has_table_privilege('verivaro_runtime','verivaro.'||t,'INSERT'))
 THEN RAISE EXCEPTION 'unexpected runtime write privilege on %',t; END IF;
 END LOOP;
 IF has_table_privilege('verivaro_runtime','verivaro_private.disabled_actors','SELECT') OR
 has_table_privilege('verivaro_runtime','verivaro_private.disabled_actors','INSERT') OR
 has_schema_privilege('verivaro_runtime','verivaro','CREATE')
 THEN RAISE EXCEPTION 'runtime can access privileged controls'; END IF;
END $$;
