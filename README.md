# Verivaro — engineering increment 0.1.0

Intelligence. Verified.

**Status:** Initial engineering foundation, synthetic data only. Not a production application or release. The approved [V4.0 master blueprint](docs/product/MASTER_BLUEPRINT.md) is the source of truth. The [engineering status](docs/engineering/STATUS.md) records partial implementation and outstanding acceptance gates.

This public repository is restricted to synthetic examples and source code. Never commit actual project documents, customer records, credentials or confidential data. No license granting redistribution is implied; ownership and license review remain open.

## Local verification

Node.js 22.16.0 is the exact local baseline, not a production security endorsement. The temporary runner uses experimental native TypeScript stripping. There are no runtime dependencies.

```sh
npm ci --ignore-scripts
npm test
npm run demo
```

The demo prints a blocked finding for a synthetic mismatched equipment serial; it does not host a website.

## Components

- Evidence verification: exact-source checks, revision consistency, mandatory submission blockers and dependency impact.
- ProofLock: confirmed UTC evidence deadlines, not a live schedule or notification service.
- Financial rules: exact AUD cents, basis grouping, confirmed milestone deduplication, unknown counts; not legal or payment entitlement.
- Draft snapshots: deterministic index and text digest verification; not a signed or released handover.

## Security boundary

The present components are local domain functions, not an authenticated API. Input scope, review, source and scan assertions are supplied by the caller. Real authentication, tenant/project isolation, storage quarantine, scanning, document parsing, authorisation and production operations are outstanding.

No production deployment or real-data ingestion is authorised. ProfitPilot code and data are not reused.
