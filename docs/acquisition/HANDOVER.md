# Verivaro acquisition handover — internal candidate only

## What transfers
Source code, migrations 001–021, synthetic integration fixtures, product blueprint, security model, browser interface, document/correction and financial workflows, worker adapters, internal export and selected access mechanisms, exact dependency lock and CI evidence. The software archive is not a running hosted business, paying customer base, registered trademark, legal compliance certificate, independent audit or production deployment.

## Reproduce and verify
View the successful exact-revision Actions run; candidate job depends on all ten earlier jobs. The artifact contains a deterministic Git source tar, source digest/mode inventory, CycloneDX lock-based SBOM with package tarball integrity hashes, installed dependency licence text and notices, npm advisory JSON, candidate evidence, signed manifest and public key. No installed packages, private key or actual customer data. CI retention seven days. A CI-generated key is synthetic: its signature proves tamper detection relative to the independently obtained public fingerprint, not independent provenance or identity. Do not treat a public key supplied inside an untrusted download as a trust anchor. Compare the expected commit and fingerprint with independently retrieved trusted run logs; do not execute unverified archives.

```sh
node scripts/candidate-verify.mjs CANDIDATE_DIR TRUSTED_PUBLIC_KEY EXPECTED_COMMIT EXPECTED_FINGERPRINT ci-ephemeral
# Only after signature and archive validation:
tar -xf CANDIDATE_DIR/source.tar -C NEW_EMPTY_DIRECTORY
node scripts/verify-unpacked-source.mjs NEW_EMPTY_DIRECTORY/verivaro CANDIDATE_DIR/source-files.json
cd NEW_EMPTY_DIRECTORY/verivaro
npm ci --ignore-scripts --no-audit --no-fund
npm test
npm run demo
```

Buyer offline signing: use a separately generated and securely stored Ed25519 private key; run npm advisory scan into a file outside the checkout, set VV_AUDIT_JSON to its path, and run `node scripts/candidate-build.mjs NEW_DIRECTORY buyer-offline PRIVATE_KEY_PATH`. Approve the fingerprint separately; never commit or upload the private key. Candidate signature is not production approval. Current scan is limited to known credential patterns and locked npm advisories; OS/container CVEs, source review, underlying license rights and secrets history require further assessment. Review all moderate/low advisories; high/critical or unavailable audit fails the candidate job. No exception or bypass is supplied.

## Reproduce the integrated demo
Use a disposable Linux host with Node 22.16.0, PostgreSQL 16, Chromium and optional native Poppler/Tesseract/ClamAV tools. The CI workflow is executable reference for installing exact dependencies, migrating in numeric order, synthetic database fixtures and roles, and running real browser/HTTP tests; never execute fixture scripts on a production database. Set PGHOST=127.0.0.1, PGPORT to the isolated fixture server, PGDATABASE=verivaro_test, PGUSER=postgres, PGPASSWORD to the disposable admin credential and VV_LIVE_TEST=1; use tests/database/foundation.sql and tests/database/live_logins.sql only in a fresh disposable cluster. Run the integration command from the CI workflow. Browser tests launch loopback HTTP with ephemeral keys and synthetic fixture data and tear down. The CI package smoke re-installs dependencies, runs unit tests and the domain demo, then creates a separate disposable PostgreSQL 16 Docker container to run migrations, the privilege matrix and the real mobile-browser workflow from the verified unpacked source. It binds only a random loopback port, uses an ephemeral admin password, uses temporary data storage and removes the container on exit. Buyers can reproduce the smoke with an explicitly reviewed local PostgreSQL 16 image ID via `bash scripts/synthetic-acquisition-smoke.sh sha256:...` on a disposable Linux host with Chromium. The test image tag is not a production supply-chain pin. It is not a persistent turnkey compose demo.

## Deployment boundary
For buyer-operated service, choose supported patched Node/DB/container versions and reconcile lockfile; provision distinct runtime, signer, ingest, parse, recovery and capability logins, isolated private file storage, encrypted backups, real OIDC issuer and key rotation, TLS and rate limits. Scanner failure must never mark files clean. External intelligence must remain disabled until approved; Linux offline container profile is separately tested, not production service integration. Use least privilege, network isolation, lifecycle/retention controls and operational review. No fixture credentials, sample JWT signing keys, or synthetic scanner permitted in deployment.

Startup is an operator task, not enabled automatically. Review packages/api/postgres.mjs, packages/api/http.mjs, packages/worker/maintenance.mjs and packages/worker/extraction.mjs. Before opening access, validate target database roles/RLS, native parsing isolation, scanner freshness, identity revocation, load, recovery and immutable file retrieval. Restore into isolated environment and rotate context keys/revoke capabilities before cutover; follow recovery benchmark. Stop service and workers before quiesced backup; restore test only in disposable environment.

## Remaining gates
- Actual independent source/security/privacy and Australian legal review; inventory of data processing and rights before real data; name and IP clearance.
- Verified protected branch rules, independent reviewer and signing identity, trusted build attestation; no automatically published releases.
- Patched pinned OS/container supply chain and scanner/parser deployment isolation; buyer-owned monitoring, external notifications, IdP and backup infrastructure.
- Complete full-package release orchestration and tenant portability, real-world independent benchmark and deployment smoke; track requirements against blueprint.
- Commercial buyer access and transfer terms, ownership/license review, operational support obligations. No price or certification claim.

This is an acquisition review package, not a final acceptance certificate.

CI #83 found missing bundled licence text for pg-types. Internal source-only evidence packaging records every missing text as a redistribution blocker; no dependencies are bundled in the source tar. Buyer-offline signing remains blocked when licence texts are missing. Declared SPDX metadata does not substitute for actual licence text or legal review. The internal candidate does not approve redistribution.
See [privacy lifecycle](../engineering/PRIVACY_LIFECYCLE.md) for the project export and deletion review boundary.
