# G1 security boundary and outstanding risks

Status: draft engineering design; NOT production approved.

## Verified in disposable PostgreSQL CI
- PostgreSQL 16 applies migrations 0001 and 0002.
- Tenant scope, revoked membership, actor/role evidence inserts, append-only trigger, concurrent independent sessions, and runtime role attribute checks execute in CI.
- These are narrowly scoped integration tests, not a penetration test or a production security certification.

## Critical design limitation: client-settable GUC identity
The current RLS policies trust `verivaro.tenant_id` and `verivaro.actor_id` values set using `set_config`. Any role that can execute arbitrary SQL can set those custom variables. Therefore **these variables are not authentication**. An SQL injection or untrusted direct database connection could impersonate a different actor, defeating tenant isolation despite green RLS tests. No production deployment until a trusted authentication-to-database context boundary is implemented and adversarially tested. Consider trusted server-side signed session claims verified in a constrained database function, or a narrowly privileged SECURITY DEFINER context setter with cryptographic identity verification; neither is implemented yet. A setter that merely accepts caller-supplied UUIDs is insufficient.

## Privilege boundary
The current CI fixture deliberately grants runtime INSERT/UPDATE/DELETE on projects and evidence to exercise negative tests. Those are **test-only grants**, not recommended production grants. The production runtime role must be non-owner, NOBYPASSRLS, with least-privilege grants. Prefer distinct privileged migration and membership-administration roles; no direct membership writes from the runtime role. Enforce evidence immutability through privilege denial as well as triggers. Explicitly test TRUNCATE, COPY, role switching, transaction context cleanup, connection reuse and revocation.

## Open acceptance gates
1. Trusted identity context with SQL-injection threat model and negative impersonation tests.
2. Project-level authorisation, role grants and membership revocation under concurrency.
3. Storage-level evidence immutability, integrity verification, provenance and audit lineage.
4. Actual application connection-pool integration tests and failure-path cleanup.
5. Independent security review, legal/privacy review and buyer acceptance.

The draft PR must remain unmerged until the applicable gates pass and the owner authorises merge.
