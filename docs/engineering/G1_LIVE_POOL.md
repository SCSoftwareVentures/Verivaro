# Live PostgreSQL pool gate

Candidate gate: exact Node version, real node-postgres driver in a separate CI-only package and actual PostgreSQL 16. The production package stays dependency-free. The first bootstrap run emits only the generated package lock for review; commit the lock and remove the fallback before crediting a reproducible gate. No credentials or token are logged by the Node test.

Tests use fresh synthetic actors, a single-connection runtime pool, tenant switching, unauthorized lookups, invalid identity, physical connection disposal and server-side cancellation of a real blocked query. Tests additionally cover project revocation and global actor disable. Cancellation is administered by the test harness; a production cancellation API and scoped session revocation remain outstanding. No production deployment.
