# Verivaro — engineering candidate 0.1.0

Intelligence. Verified.

**Status:** Draft engineering branch, synthetic data only. No production release, live customer deployment, independent certification or trademark clearance. The [V4.0 master blueprint](docs/product/MASTER_BLUEPRINT.md) defines the agreed scope. [Acquisition guide](docs/acquisition/HANDOVER.md) describes the implemented architecture and outstanding buyer gates; do not rely on the historical initial status file as current completion.

This public repository contains synthetic examples and source code only. Never commit actual project documents, customer records, credentials or confidential data. No licence granting redistribution is implied; ownership and licence review remain open.

## Verification

Pin Node.js 22.16.0 for reproducible test execution (not a production patch endorsement). PostgreSQL 16 and distinct database role credentials are required for integrated tests. The locked runtime dependency is pg and its transitive packages.

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm test
npm run demo
node --experimental-strip-types tests/benchmarks/run.mjs holdout
node --experimental-strip-types tests/benchmarks/performance.mjs
```

The demo prints a synthetic blocked finding. Hosted CI runs database, HTTP, Chromium, parsing, scanner, isolation, restore and benchmark suites using synthetic fixtures only. See the exact checkout revision and run result; a green prior revision is not a release approval.

## Implemented architecture

Separate scoped PostgreSQL roles and append-only evidence revisions; authenticated HTTP API and mobile reviewer workspace; quarantine and extraction workers; ProofLock schedules and capture; source-grounded advisory intelligence; correction workflows; financial records; internal draft PDF/ZIP/XLSX; separately authorised time-limited metadata/original sharing. External AI remains disabled. Production monitoring, legal and security acceptance gates remain open.

[Candidate packaging and verification](docs/acquisition/HANDOVER.md) includes reproducible source archives, SBOM, dependency licence evidence, dependency advisory gate, and signed candidate integrity verification. No deployment authorised.
