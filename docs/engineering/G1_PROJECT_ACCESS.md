# G1 project authorization increment

Draft pending exact-head CI. Every project requires an explicit active assignment, including organisation owners. Effective write permission is the intersection of tenant and project role; expired/revoked grants deny access. Runtime group is NOLOGIN by default and has read plus evidence INSERT only. Project creation, editing, membership changes and actor restoration remain privileged workflows, not implemented API endpoints. Existing assignments must be backfilled by an authorised administrator; no automatic broad access.

Emergency actor disable is global and checked at the database on every authorized statement. READ COMMITTED required; REPEATABLE READ and SERIALIZABLE fail closed. Revocation becomes effective at the next statement snapshot, not during an already running statement. Database actor disable is not fully scoped token/session revocation or an IdP integration. Do not remove an emergency disable without a reviewed identity recovery and token invalidation process.

CI fixtures use ephemeral owner privileges only to provision synthetic assignments and sign challenges; runtime cannot access keys or administer privileges. No production deployment or real data. Pool adapter, authenticated management workflows, per-token/session and share revocation, cancellation of active queries, and independent review remain required.
