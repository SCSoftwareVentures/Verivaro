# G1 trusted identity remediation — implementation contract

**Status:** design contract, not implemented. Blocking test: `db/tests/identity_spoof_gate.sql`. No release while this test fails.

## Confirmed defect
Runtime role can set `verivaro.tenant_id` and `verivaro.actor_id` using arbitrary SQL, then read another tenant's project. Observed PostgreSQL CI failure: `SECURITY FAILURE: untrusted runtime SQL can impersonate tenant B (visible projects=1)` (run 44407117636, job 135165204800).

## Required trust boundary
1. Verify the incoming identity token **server-side**, including signature, expected issuer, audience, expiry, not-before, nonce/session binding where applicable, and revocation. Never accept client-supplied actor or tenant IDs as authority.
2. Resolve authorised memberships from database records and apply project-level permission checks. A tenant selector is an input, not a proof of membership.
3. Do **not** use freely settable PostgreSQL custom GUC values as authentication. Any database connection that can execute arbitrary SQL can set them.
4. Use a cryptographically verified, transaction-bound database context with a verification key inaccessible to the runtime SQL role, or a different design with equally strong, independently demonstrated trust boundaries. A SECURITY DEFINER setter taking arbitrary UUIDs **does not fix** impersonation.
5. Keep migration/administration roles separate from runtime roles; prohibit BYPASSRLS, table ownership, role escalation, direct membership administration, unsafe SECURITY DEFINER functions, and unrestricted search_path.
6. All pooled requests must use explicit transactions, fail closed when context is missing, clear context on commit/rollback, and reject identity carryover on reused connections.

## Acceptance tests (all mandatory)
- A caller who controls arbitrary SQL **but lacks valid credentials for another actor** cannot obtain another actor's permissions by SET, set_config, forged claims, role SET, prepared statements, or context reuse.
- Tampered signature, wrong issuer/audience, expired or revoked token, changed tenant/project, invalid membership, and stale permission are rejected.
- Tenant A and B execute concurrently on separate sessions; pooled reuse across requests, transaction rollback, errors and cancellations cannot leak identity.
- No UPDATE/DELETE/TRUNCATE of evidence by runtime; no privilege escalation through membership or role changes.
- Tests must run against real PostgreSQL with the same runtime grants and trust-boundary implementation used by the application.

## Implementation sequencing
A. Select and implement authenticated principal binding; document key ownership/rotation and database trust boundary.
B. Replace the vulnerable RLS helper/policies and migration fixtures, preserving audit trail and forward-only migration semantics.
C. Rewrite the spoof test to exercise the new trusted API without relying on a privileged test-only context; keep it blocking.
D. Add integration tests with actual connection-pool client and malicious SQL paths.
E. Run full CI and independent security review. Only then request merge approval.

**No implementation claim:** this document specifies the remediation, not a security fix.
