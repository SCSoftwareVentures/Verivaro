# Engineering status — 0.1.0

Approved design baseline: Verivaro V4.0, 18 November 2026. Source foundation imported from locally tested increment. Synthetic data only. No live AI, production deployment or customer pilot.

## Implementation traceability

| Capability | Implemented slice | Remaining |
|---|---|---|
| F07/F08/F09/F12 | Exact-source quote checks, reviewed scope, revision and contradiction checks | Persistent graph, typed criteria, parsing and reviewer identity |
| F13/F14/F23 | Deterministic coverage and mandatory-blocker preflight | Durable versioned evaluations, waiver policy, UI |
| F15/F16 | Confirmed UTC deadline and irreversibility calculation | Schedule history, timezone/DST, notifications, authority |
| F21 | Findings, reasons and source IDs | Risk ranking, actions and assignments |
| F25/F26/F27 | Direct dependency impact | Transitive invalidation and full/incremental equivalence |
| F31/F32 | Exact AUD totals and tax-basis separation | Verified financial provenance, currencies and milestone links |
| F36/F40/F41 | Canonical draft index and text digest | Binary integrity, PDF/ZIP, signed release workflow |
| F42 | In-memory scope consistency | OIDC, RBAC, revocation, scoped transactions and PostgreSQL RLS |
| F47 | No runtime dependencies, package lock, CI configuration | SBOM, dependency/secret scanning and signed releases |

Other capabilities remain unimplemented. No feature-level full acceptance criterion is asserted as passed. G0 design baseline: 10% gate credit; G1–G6 remain open. Brand clearance outstanding.

## Evidence

Original local increment: 43/43 unit tests passed on Node 22.16.0; strict TypeScript 5.8.3 checking passed for three typed modules. Imported code and tests are byte-for-byte matched against original Git blob fingerprints. Hosted CI is a separate verification step; inspect GitHub Actions for actual results.

## Next

G1 database and identity foundation: PostgreSQL schema and migrations, tenant/project memberships, RLS and scoped transactions, immutable evidence records, quarantine storage contracts, adversarial integration tests. No secrets or real project data in this public repository. Private production infrastructure and independent assessment require separate verification and approval.
