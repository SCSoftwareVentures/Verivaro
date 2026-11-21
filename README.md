# Verivaro — engineering increment 0.1.0

Intelligence. Verified.

**Status:** Engineering prototype and synthetic/test-data verification on an unmerged draft review branch; **not a production-ready or sale-validated application**. The [V4.0 master blueprint](docs/product/MASTER_BLUEPRINT.md) remains the design baseline. The [current engineering status](docs/engineering/STATUS.md), [G1 production trust-boundary and buyer audit](docs/engineering/G1_PRODUCTION_TRUST_BOUNDARY_BUYER_AUDIT_20261121.md), and [machine-readable evidence register](docs/engineering/G1_BUYER_EVIDENCE_MANIFEST_20261121.json) distinguish tested slices from deployment and buyer acceptance.

This public repository is restricted to synthetic examples and source code. Never commit actual project documents, customer records, credentials or confidential data. No license granting redistribution is implied; ownership and license review remain open.

## Local verification

Node.js 22.16.0 is the exact local baseline, not a production security endorsement. The temporary runner uses experimental native TypeScript stripping. There are no runtime dependencies.

```sh
npm ci --ignore-scripts
npm test
npm run demo
npm run demo:buyer
npm run demo:buyer:web
```

The demo prints a blocked finding for a synthetic mismatched equipment serial; it does not host a website.

The separate [synthetic buyer walkthrough](docs/engineering/G1_SYNTHETIC_BUYER_WALKTHROUGH_20261121.md) reproduces missing → conflicting → provisional → reviewed proof and checks a canonical package against self-held hashes. It is **not** a real buyer/mobile session, authenticated release or independent custody claim.

The [read-only browser showcase](docs/engineering/G1_MOBILE_BUYER_SHOWCASE_20261121.md) presents the same fixture as a four-stage mobile-responsive interface. The local preview is **loopback-only** and intended for developer/buyer inspection on a machine running Node; it is not a public website or an iPhone-deployed app. Chromium/WebKit browser CI checks responsive behavior and the non-release safety boundary.

## Components

- Evidence verification: exact-source checks, revision consistency, mandatory submission blockers and dependency impact.
- ProofLock: confirmed UTC evidence deadlines, not a live schedule or notification service.
- Financial rules: exact AUD cents, basis grouping, confirmed milestone deduplication, unknown counts; not legal or payment entitlement.
- Draft snapshots: deterministic index and text digest verification; not a signed or released handover.

## Engineering slices currently in the repository

The original domain-function demo remains limited. Additional **synthetic CI-tested engineering slices** now include a PostgreSQL 16 migration and tenant-isolation gate; identity/session and scoped-transaction code; a local TLS application runtime; evidence quarantine/retrieval/recovery; browser workspace checks in Chromium and WebKit; and reference G1 signed witness, two-reviewer approval and floor-publication components. Consult `docs/engineering/` and the workflows for precise coverage. These pieces **are not evidence of a fully integrated customer product**.

## Security and commercial boundary

The G1 witness publisher, consumption register and floor authority are deliberately **single-host reference implementations**, not independent trust infrastructure. The injected signing capabilities, trusted state, browser identity provider, deployment credentials and real data-custody operation have **not** been proven under a production trust domain. Browser/runtime pathways exist, but a complete product UI and production operating environment do not. No independently verified penetration test, production recovery or customer payment/demand evidence is recorded.

**Do not claim production readiness, fully independent immutable evidence, compliance certification or verified market demand.** Release approval requires separately evidenced gates in the buyer audit and V4.0 blueprint. No real-data ingestion, external deployment, paid infrastructure or automatic merge is authorised. ProfitPilot code and data are not reused.
