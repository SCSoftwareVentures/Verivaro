#!/usr/bin/env bash
set -euo pipefail
# Two simultaneous independent connections with incompatible tenant/actor scopes.
# Both must see only their own project. Synthetic data from tenant_isolation.sql.
run_scope() {
  local tenant="$1" actor="$2" expected="$3"
  PGUSER=verivaro_runtime PGPASSWORD=ci-only-not-a-secret psql -X -qAt -v ON_ERROR_STOP=1 <<SQL
BEGIN;
SELECT pg_backend_pid() AS pid, pg_current_xact_id()::text AS xid \\gset
\\setenv VV_PID :pid
\\setenv VV_XID :xid
\\set signed \`PGUSER=postgres PGPASSWORD=ci-only psql -XqAt -v ON_ERROR_STOP=1 -c "SELECT verivaro_private.ci_sign('$tenant','$actor',\$VV_PID,'\$VV_XID')"\`
SELECT set_config('verivaro.signed_context', :'signed', true);
SELECT pg_sleep(1);
DO \$\$
DECLARE actual text;
BEGIN
 SELECT string_agg(id::text,',') INTO actual FROM verivaro.projects;
 IF actual IS DISTINCT FROM '$expected' THEN
   RAISE EXCEPTION 'concurrent tenant scope failure: expected %, got %', '$expected', actual;
 END IF;
END \$\$;
COMMIT;
SQL
}
# Earlier baseline test revoked actor A, so create a fresh active tenant A actor.
psql -X -v ON_ERROR_STOP=1 <<'SQL'
INSERT INTO verivaro.memberships(tenant_id,actor_id,role)
VALUES ('11111111-1111-4111-8111-111111111111','dddddddd-dddd-4ddd-8ddd-dddddddddddd','viewer');
INSERT INTO verivaro.project_members(tenant_id,project_id,actor_id,role) VALUES
 ('11111111-1111-4111-8111-111111111111','33333333-3333-4333-8333-333333333333','dddddddd-dddd-4ddd-8ddd-dddddddddddd','viewer');
SQL
run_scope '11111111-1111-4111-8111-111111111111' 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' '33333333-3333-4333-8333-333333333333' &
a=$!
run_scope '22222222-2222-4222-8222-222222222222' 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' '44444444-4444-4444-8444-444444444444' &
b=$!
wait "$a"
wait "$b"
