# Engineering status — Verivaro 0.1.0 review branch

**Snapshot: 21 November 2026.** Design baseline: [V4.0 master blueprint](../product/MASTER_BLUEPRINT.md). This file replaces the outdated initial-import status narrative for the **audit/G1 review branch**. It is not a release signoff, independent audit, market validation or merge approval.

## What is demonstrably implemented

- **G0 domain core:** deterministic source and dependency calculations, findings, proof deadlines, financial arithmetic and synthetic export checks, with unit tests and demo. Not an autonomous AI analysis engine or validated customer workflow.
- **G1 database and identity slices:** versioned PostgreSQL migrations, tenant/project policies, signed transaction scope, sessions and revocation, TLS identity/runtime plumbing, and real disposable-PostgreSQL integration gates. RLS does not constrain superusers or compromised context-signing authority.
- **G1 storage and evidence slices:** quarantine, scanner integration, bounded parsing/normalization, encrypted artifact and backup/recovery components; scoped read/write and retrieval tests for exercised paths. Tested scanners are not malware certification.
- **G2–G4 partial engineering:** OCR, document/requirement analysis, proof planning, handover/export and browser workspace components with test fixtures. Their presence does **not** demonstrate full V4.0 acceptance or market usability.
- **G1 witness and recovery reference:** signed publisher, hash-chained journal, read-only three-way reconciliation, two-reviewer REVIEW_ONLY approval, single-host consumption register, signed floor publication gate and file-backed reference authority. Synthetic tests include process exits, races, stale heads and simulated partitions; **no independent service, custody, physical power cycle or cross-host consensus**.
- **CI:** The exact immutable SHA `86b9977f322761ba98beb5583e01e8573d793f9a` passed **six of six** tracked workflows: Node core, PostgreSQL G1, Chromium/WebKit, ClamAV, maximum encrypted recovery and synthetic buyer packaging. These are historical evidence for **that SHA only**; subsequent code changes require a new full matrix. None is a production penetration assessment, independent custody proof or buyer pilot.

## Acceptance and asset-sale decision

**Release status: NOT APPROVED. Sale positioning: code/prototype asset, not operational SaaS.** The source contains partial implementation of several G0–G4 areas, but V4.0 G0–G6 completion and end-to-end production acceptance are **not established**. No real production IDP, independent monotonic witness/floor service, external cryptographic key custody, independently measured disaster-recovery targets, production security assessment, independent legal/IP clearance or paid buyer demand validation is evidenced.

Do not infer an overall completion percentage or market value from test count. A buyer must evaluate design, licensing, code provenance, usability, operations and customer fit. For ranked blockers, owner/control requirements and evidence standards, read [production trust-boundary and buyer-readiness audit](G1_PRODUCTION_TRUST_BOUNDARY_BUYER_AUDIT_20261121.md). Structured statuses are in [G1 buyer evidence manifest](G1_BUYER_EVIDENCE_MANIFEST_20261121.json).

## Current engineering control

G1 remains in a **draft, unmerged and undeployed** review PR. The exact SHA must be checked after each coherent change. Successful CI is evidence for exercised code and fixtures, not proof of independent production security or customer acceptance. Do not use any external infrastructure, real customer information, paid service or operations approval without owner authorisation.
