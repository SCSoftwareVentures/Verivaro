#!/usr/bin/env bash
# Synthetic disposable Linux smoke only. No existing DB, external IdP, real data or persistent volume.
set -euo pipefail
[[ "$(node --version)" == v22.16.0 ]] || { echo 'Pinned test Node required.' >&2; exit 1; }
[[ -z "${DOCKER_HOST:-}" && -z "${DOCKER_CONTEXT:-}" ]] || { echo 'Overridden Docker host forbidden.' >&2; exit 1; }
[[ "$(docker context inspect --format '{{.Endpoints.docker.Host}}')" == unix://* ]] || { echo 'Local Docker socket required.' >&2; exit 1; }
image="${1:-}"
[[ "$image" =~ ^sha256:[a-f0-9]{64}$ ]] || { echo 'Pass a locally available reviewed PostgreSQL 16 image ID.' >&2; exit 1; }
[[ "$(docker image inspect --format '{{.Id}}' "$image")" == "$image" ]] || exit 1
# The supplied image is a trusted operator input. It is never an arbitrary user-supplied tag.
export POSTGRES_PASSWORD="$(node -e 'process.stdout.write(require("crypto").randomBytes(32).toString("hex"))')"
name="vv-smoke-$(node -e 'process.stdout.write(require("crypto").randomUUID())')"
cleanup(){ docker rm -f "$name" >/dev/null 2>&1 || true; unset POSTGRES_PASSWORD PGPASSWORD; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cid="$(docker run -d --rm --name "$name" --pull=never --publish 127.0.0.1::5432 --tmpfs /var/lib/postgresql/data:rw --env POSTGRES_PASSWORD --env POSTGRES_DB=verivaro_test "$image")"
[[ "$cid" =~ ^[a-f0-9]{64}$ ]] || exit 1
ready=0
for i in $(seq 1 60); do
 if docker exec "$cid" pg_isready -h 127.0.0.1 -U postgres -d verivaro_test >/dev/null 2>&1; then ready=1; break; fi
 sleep 1
done
[[ "$ready" == 1 ]] || { echo 'Disposable database not ready.' >&2; exit 1; }
mapping="$(docker port "$cid" 5432/tcp)"
[[ "$mapping" =~ ^127\.0\.0\.1:([0-9]{1,5})$ ]] || exit 1
export PGPORT="${BASH_REMATCH[1]}" PGHOST=127.0.0.1 PGDATABASE=verivaro_test PGUSER=postgres VV_LIVE_TEST=1
export PGPASSWORD="$POSTGRES_PASSWORD"
[[ "$(docker exec "$cid" psql -X -At -U postgres -d verivaro_test -c 'SHOW server_version_num')" == 16* ]] || exit 1
for migration in database/migrations/*.sql; do docker exec -i "$cid" psql -X -v ON_ERROR_STOP=1 -U postgres -d verivaro_test < "$migration"; done
for fixture in tests/database/foundation.sql tests/database/privilege_matrix.sql tests/database/live_logins.sql; do
 docker exec -i "$cid" psql -X -v ON_ERROR_STOP=1 -U postgres -d verivaro_test < "$fixture"
done
node --experimental-strip-types --test tests/integration/live-browser.test.mjs
echo 'Synthetic acquisition smoke passed; disposable database is removed on exit.'
