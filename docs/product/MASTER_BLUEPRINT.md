# VERIVARO
## Master product and technical blueprint · V4.0

**Project 002 | 18 November 2026 | Engineering baseline | Working brand**

**Positioning:** Intelligence. Verified.

**Status:** Complete proposed design baseline for the agreed scope; implementation, product benchmarks, independent security assessment and legal clearance are not complete. All capabilities, limits and metrics below are requirements or proposed engineering choices, not achieved results.

## 1. Executive decision and product boundaries

Verivaro is a portable, evidence-driven completion and verification system for organisations that must prove work, resolve documentary deficiencies and deliver trustworthy records. It converts existing documents into traceable requirements, connects evidence to those requirements, warns before time-sensitive evidence is lost, identifies likely submission deficiencies, and produces controlled handover packages. It does not replace the customer's accounting, project management or operational software.

**Primary market:** Australian commercial subcontractors (initial demonstration: HVAC, electrical and plumbing). **Product architecture:** industry-neutral from the outset; requirements, milestones, evidence types, labels and templates are configurable. Later packs can support equipment maintenance, field service, property inspections, manufacturing quality handovers and professional services without changing the core model. Each pack requires its own rule validation. There is no claim of universal domain expertise.

**Business objective:** build and sell the software asset, not operate a live SaaS business. Synthetic demonstration and repeatable tests are the evidence route; no real-business pilots, outreach, paid production services or customer data are assumed. Buyer performs its own market validation. Target asking/negotiation ambition is AUD 15,000–30,000, unvalidated; there may be no buyer. No valuation is implied by completing a milestone.

**Product promise:** identify avoidable errors, preserve evidence and reduce administrative effort. Do not certify workmanship, document authenticity, legal compliance, contractual entitlement, safety or payment recovery. Do not block physical work; only hold the system's readiness designation. No automatic payment, billing, bank access, automated legal advice, CRM, payroll, full scheduling, BIM model or compulsory integration. No network actions, purchases or release approval without owner authority.

**Design principles:** one canonical evidence graph; original files immutable during their retention period; derived findings reproducible and source-linked; explicit unknown/conflict states; human approval of ambiguous requirements and release decisions; default deny; controlled deletion; mobile-first; accessible; minimal manual entry; no AI dependency for essential workflow; cost caps and portability. Security is embedded from the first commit. No feature expansion without an approved scope change.

## 2. Scope and implementation priorities

Every named capability from the agreed V4.0 design is preserved below. Aliases are one implementation, not duplicate modules. P0 denotes essential release slice; P1 denotes full-scope completion; P2 denotes advanced final-scope completion. All are required for the agreed complete product, unless explicitly designated as a provider-dependent adapter. The order is sequencing, not permission to drop features.

**Shared engines:** E1 Document Intelligence; E2 Evidence and Verification; E3 ProofLock; E4 Rejection Prevention; E5 Financial Intelligence; E6 Handover Intelligence; E7 Trust and Security. Shared services: identity, tenancy, storage, queue, document parser, rules, model adapter, notifications, audit, export and jobs. Feature names are presentation labels over these shared services.

### E1 — Document Intelligence

| ID / feature | Required behaviour and efficiency | Release acceptance scenario |
|---|---|---|
| F01 ContractIQ (P0) | Parse contracts, appendices and amendments; extract atomic obligations, evidence criteria, actor, stage and precedence candidates with exact source location. User confirms precedence and applicability; no invented clauses. | Conflicting amendment test displays both clauses; unresolved precedence remains unknown; every approved requirement has source or explicit manual provenance. |
| F02 EvidenceRescue (P0) | Batch import folders; content-hash dedupe within tenant; classify and propose equipment/project links; retain original names and lineage. | Duplicate and conflicting filenames import without silent loss; uncertain files queue for review; source counts reconcile. |
| F03 CertificateVault (P0) | Versioned certificate, warranty, inspection and manual register; expiry and equipment relationships. | Expired/superseded certificate cannot silently satisfy a current requirement; historical package still resolves original retained version. |
| F04 PhotoIQ (P1) | On-device quality/duplicate hints; optional AI relevance and identifier extraction; retain original; strip unnecessary metadata from shared views. | Blurry or duplicate photo is flagged; image alone never certifies installation, location or authenticity. |
| F05 VoiceCapture (P2) | Typed note or recorded audio with separate transcription adapter; draft structured notes, uncertain words and units highlighted; user confirms. | Misheard serial number remains unconfirmed; denied microphone permission offers typed alternative. |
| F06 BuilderDNA (P1) | Tenant-private, versioned counterparty templates, submission conventions and approved feedback; support any organisation type. | Template update never retroactively changes existing project rules; current contract overrides only after review. |

### E2 — Evidence and Verification

| ID / feature | Required behaviour and efficiency | Release acceptance scenario |
|---|---|---|
| F07 EvidenceGraph (P0) | Typed, versioned links from requirement to source, evidence, equipment, stage, finding and approval. Dependency invalidation and cycle checks. | Updating certificate reopens only dependent approvals; prior export unchanged; cross-tenant edge rejected. |
| F08 ProofMatch (P0) | Candidate matching by explicit attributes, identifiers, dates, document type and declared criteria; ambiguous matches reviewed. | Similar serial numbers do not auto-match; one document can satisfy distinct approved criteria without duplicate counting. |
| F09 CertCheck (P0) | Validate required fields, dates, formats, IDs and consistency with register; verify issuer only through approved configured methods. | Wrong serial and expired certificate are flagged; absent issuer adapter yields issuer-unverified, not fraudulent. |
| F10 CrossCheck AI (P1) | Normalise units/identifiers and compare source-linked extracted fields; deterministic mismatch detection first, AI only for semantic suggestions. | Contradictory warranty dates show both source snippets and require resolution; no silent winner. |
| F11 AuthenticityGuard (P1) | SHA-256 original bytes, signed manifest and optional signature/issuer checks; alterations, missing signatures and metadata anomalies are risk signals. | One-byte alteration fails integrity verification; unchanged file hash never implies genuine issuance. |
| F12 DoubleCheck Intelligence (P0) | Separate extraction from verification; schema, span, rule and provenance validation; second model pass only for uncertain supported cases. | Fabricated quote or page reference fails validation; two agreeing AI outputs alone cannot approve a critical finding. |
| F13 EvidenceScore (P0) | Show coverage, verified count, critical blockers and unknowns separately; denominator based on approved applicable requirements. | 99/100 complete with one mandatory blocker remains not ready; zero requirements displays not assessed. |
| F14 CompletionCheck (P0) | Snapshot readiness continuously from current approved rules, evidence and decisions; mark stale results during async reassessment. | New revision cannot leave old readiness marked current; no manual refresh needed after successful job completion. |

### E3 — ProofLock: predictive evidence protection

| ID / capability | Required behaviour and efficiency | Release acceptance scenario |
|---|---|---|
| F15 ProofLock (P0) | Derive evidence capture deadlines from confirmed milestones and review lead times; show next tasks; indefinite/unknown stage requires clarification. | Rescheduled milestone recalculates affected due times without losing history; missing milestone never yields fabricated date. |
| F16 Irreversibility Intelligence (P1) | Classify reversible, costly-to-recreate and potentially irreversible evidence windows using approved template or user rules; escalate late risks. | Concealment tomorrow generates a pre-concealment evidence warning; no claim that work has occurred. |
| F17 Mobile capture (P0) | Scoped capture link or QR, project/requirement context, camera/file/text selection, review and submission. | Unauthorised link cannot browse docs; correct context survives refresh; typing not mandatory for routine photo capture. |
| F18 Offline capture (P1) | Local encrypted or explicitly consented secure-device queue where supported; unique client IDs, retry, conflict resolution and visible sync state. | Network interruption and replay create one logical submission; unsynced evidence never counts as server verified; unsupported browser offers online mode. |
| F19 Intelligent alerts (P1) | Deduplicate by requirement/version, urgency and time window; digest routine items; escalate approved critical risks; preferences and quiet hours. | Repeated job retry sends no duplicate message; quiet-hour exception applied only under configured rules; disabled delivery shows in-app alert. |
| F20 Missed evidence recovery (P1) | Suggest permitted alternative evidence from confirmed rules; request approval for exceptions; preserve missed deadline. | Post-concealment photo cannot automatically replace mandatory inspection; recorded waiver needs authorised evidence. |

### E4 — Rejection Prevention

| ID / feature | Required behaviour and efficiency | Release acceptance scenario |
|---|---|---|
| F21 GapHunter (P0) | Rank open deficiencies by mandatory status, urgency, documented financial relevance and repair effort; explain each ranking. | Critical missing certificate outranks optional naming issue; ties stable; no unverified amount used. |
| F22 RejectPredict (P1) | Rule-based risk indicators from known requirements and approved rejection history; no unsupported probability. | New counterparty without history shows rule-only analysis; no invented rejection prediction. |
| F23 RejectShield (P0) | Structured preflight against approved rules and submission format; printable blocker/warning report. | Incorrect model, missing document and naming issue each detected; zero critical false-ready results in release suite. |
| F24 RejectionDNA (P1) | Import explicit rejection feedback; link source to existing/new correction tasks, identify unclear objections. | Repeated same feedback deduped; approved corrections do not erase prior submission or rejection. |
| F25 ZeroRework (P0) | Dependency-driven incremental recomputation; final full deterministic preflight before release. | Change one source recomputes dependent nodes; full recompute produces identical final result. |
| F26 RevisionGuard (P0) | Track active versus superseded evidence and rule versions; stale package approval invalidation. | Old revision rejected from new package; retained historical release remains reproducible. |
| F27 ChangeImpact (P0) | Show requirements, links, approvals, due dates and package references affected by confirmed changes. | Contract amendment requiring new report reopens only affected obligations and final readiness. |
| F28 AutoCorrect (P1) | Draft correction suggestions and cover sheets; explicit approval; never modify issued/signed evidence. | Incorrect filename can be fixed as export metadata; certificate contents unchanged; proposed correction previewed. |
| F29 SmartChase (P1) | Consolidate missing-evidence requests by responsible party; draft first, send only under explicit permission and supported provider. | No recipient inferred from an untrusted document; preview and consent checked; bounce/unknown states retained. |
| F30 DefectClear (P1) | Record defect, action owner, deadline, resolution evidence and reviewer decision; reopen on relevant change. | Missing mandatory proof blocks closure; disputed closure remains visible and auditable. |

### E5 — Financial Intelligence

| ID / feature | Required behaviour and efficiency | Release acceptance scenario |
|---|---|---|
| F31 PaymentReady (P0) | Map approved documentary conditions to milestones; separate documentary readiness from legal/payment entitlement. | Missing evidence shows an administrative issue, not a finding that payment may lawfully be withheld. |
| F32 MoneyMap (P1) | Link documented milestone amounts and source evidence; exact minor-unit arithmetic; deduplicate shared amounts; separate currency/tax bases. | Two blockers tied to same AUD 10,000 milestone show one amount; mixed currency not summed. |
| F33 RetentionWatch (P1) | Track confirmed retention amounts, dates, conditions and amendments; reminders, not legal deadline determinations. | Changed express release condition reopens review and updates reminder; unknown date remains unknown. |
| F34 DisputeShield (P1) | Generate chronological factual evidence pack, distinguish asserted/verified events and receipt/acceptance. | Contradictory feedback included, not suppressed; no liability finding or invented receipt. |
| F35 ContractorShield (P1) | Independent archive of submission snapshots, acknowledgements, versions, correspondence and disputes; exportable to owner. | Submitted is distinct from delivered and accepted; deleted private records leave only lawful minimum audit metadata. |

### E6 — Handover Intelligence

| ID / feature | Required behaviour and efficiency | Release acceptance scenario |
|---|---|---|
| F36 InstantHandover / OneClick Handover (P0) | Compile indexed PDF cover, evidence register and source attachments from approved snapshot; draft watermarked if blockers. | Package with blocker cannot receive ready label; original signed PDFs preserved as separate attachments. |
| F37 UniversalExport (P1) | Versioned configurable PDF, XLSX, CSV and ZIP templates; names, ordering and manifests; safe path normalisation and spreadsheet escaping. | Two builder formats generated from same snapshot; files and hashes match manifest; no traversal/formula injection. |
| F38 ZeroSwitch (P0) | File/folder and CSV import/export, field mapping preview and error rows; no compulsory migration. | Bad rows separated and counted; no uncontrolled writes into source systems. |
| F39 CustomerAccess (P1) | Expiring, revocable scoped sharing links; explicit recipient access and share preview; optional authenticated sensitive sharing. | Revoked or expired token denies access; viewer cannot enumerate project or download unshared records. |
| F40 ProofPack (P0) | Indexed package, table of contents, document/page references, safe compression; size limits; no alteration of original evidence. | Large documents produce bounded job or actionable error; all manifest entries reconcile; package can be verified offline. |

### E7 — Trust and Security

| ID / feature | Required behaviour and efficiency | Release acceptance scenario |
|---|---|---|
| F41 TrustProof (P0) | Append-only audit events during retention, versioned decisions, signatures where supported, restricted audit storage and verification export. | Tampered audit chain detected; audit cannot be edited by application runtime; approved deletion still possible. |
| F42 Access security (P0) | Tenant isolation, scoped RBAC, OIDC, session and share revocation. | Cross-tenant read/write/download/job/export denied; role escalation denied; revoked session rejected. |
| F43 AI security (P0) | Untrusted document boundary, no model tools or authority, schema and cite validation, provider allowlist and per-job quotas. | Embedded prompt injection cannot trigger communications, shell, network calls, approvals or secret disclosure. |
| F44 File security (P0) | Quarantine, signature/MIME checks, limits, scanning and sandboxed extraction. | EICAR test under approved scanner, archive traversal and oversized/decompression payload rejected or quarantined; scanner outage fails closed. |
| F45 Data protection (P0) | Encryption, minimisation, tenant-scoped storage, retention and deletion lifecycle. | Deletion cascades to derivatives and shares, pending backups age out under policy; restore does not resurrect deleted content. |
| F46 Recovery (P0) | Idempotent work queue, bounded retries, dead letter, backup and restore rehearsal with synthetic data. | Interrupted jobs resume or fail visibly; replay cannot duplicate effect; restored system reconciles revisions. |
| F47 Supply-chain integrity (P0) | Locked dependencies, scanning, SBOM, protected reviews and signed/provenanced release where configured. | Tampered artifact rejected by verifier; unsupported signing is explicit release blocker, not falsely marked passed. |

## 3. End-to-end workflows and screens

Five primary tabs: Overview, Documents, ProofLock, Resolve, Handover. Project switcher, organisation settings, audit and financial details are secondary screens. Screen widths from 360 CSS px; keyboard support, screen reader labels, visible focus, no status conveyed by colour alone. Design for WCAG 2.2 AA verification (not certified). Every empty, loading, permission-denied, partial, stale and error state has a clear action. Never display synthetic values as live ones.

| Workflow | Sequence and success path | Failure / exception |
|---|---|---|
| W01 Setup | Create organisation/project, choose neutral or industry pack, confirm timezone, roles, milestones and rules; upload starter files or use manual mode. | Unconfigured AI defaults to manual extraction; onboarding stops at essential fields, saves draft. |
| W02 Ingestion | Drag/drop or file picker → upload session → quarantine → scan → parse → classify/dedupe → review sources. | Unsupported, encrypted, corrupt or unsafe documents remain unavailable for processing; manual entry allowed with provenance. |
| W03 Requirement review | Review extracted clauses side by side; approve applicability, mandatory flag, source, criterion and stage; freeze rules revision. | Conflicts/uncertainty require disposition; unknown critical applicability blocks ready. |
| W04 Capture | View imminent evidence → tap capture → assign source and criterion → upload/queue → check quality → reviewer confirms. | Offline shown pending; lost link revocation requires new invitation; missed deadline preserved. |
| W05 Resolution | Open prioritised finding → source comparison → assign/correct → upload revision → reassess → approve closure. | Conflicting edits rejected with current version; unresolved item stays open. |
| W06 Financial review | Enter confirmed exact amount, currency, basis, milestone and source; review documentary dependencies. | Unknown legal condition is review-only; no calculations mixing incompatible basis. |
| W07 Rejection | Attach reviewer notice → extract objections → review mapping → correct → create new package. | Unknown feedback held for review; original submission evidence preserved. |
| W08 Handover | Select template → pin source/requirement versions → full preflight → authorised review → generate manifest/package → download or share. | Draft export available with visible blockers; ready release cannot bypass a critical gate; partial export never marked complete. |
| W09 Share and acknowledgement | Scope package, expiry and recipient → confirm → copy secure link or authorised send → record access/explicit acknowledgement separately. | Expired/revoked returns generic denial; no receipt inferred from sent message. |
| W10 Lifecycle | Archive, export, legal hold or delete within policy; revoke links and purge eligible derived data. | Holds require reason/authority; retained backups expire; restore honours deletion ledger. |

Screen acceptance: overview links each blocker to source and action; documents includes version tree and import status; ProofLock shows upcoming/missed/unknown milestones; Resolve supports filters, correction and assignment; Handover offers preview, blockers, manifest, release history and sharing controls. Owner can download a complete tenant export without proprietary tools.

## 4. Technical architecture and repository

**Proposed stack (decision, not existing implementation):** TypeScript monorepo, supported Node.js LTS (pin exact tested version at kickoff), React/Vite responsive PWA, Fastify HTTP API, PostgreSQL with row-level security, S3-compatible private object store, separate sandboxed parsing worker, PostgreSQL-backed durable jobs (avoid Redis initially), local Docker Compose demo using synthetic files. Use pinned, licensed components; avoid paid integrations by default. Native iOS app not required. Production owner configures hosted identity, storage, mail, optional AI and scanning. No live cloud services are assumed for this blueprint.

Architecture flow: browser → reverse proxy/TLS → API (policy and identity) → PostgreSQL + signed upload/download service; quarantined objects → scanner → bounded parser → extraction adapter → schema and source verifier → requirement/evidence graph → rules evaluation → findings/readiness; authorised export worker reads a pinned snapshot and writes a manifest and artifacts to private storage. Worker has no broad network permissions. Optional AI receives minimal authorised source snippets through constrained gateway; no model access to database or privileged tools.

Repository structure: `apps/web`, `apps/api`, `apps/worker`, `packages/domain`, `packages/rules`, `packages/ai-adapter`, `packages/export`, `packages/contracts`, `database/migrations`, `tests/{unit,integration,e2e,security,benchmarks,fixtures}`, `infra/compose`, `docs/{architecture,security,operations,product,acquisition}`, `.github/workflows`. One repo per project; private recommended for acquisition exclusivity. No reuse of sold ProfitPilot-specific code without licence/rights review. Reuse only independently owned or permissively licensed generic components with provenance.

**Concurrency:** tenant-scoped transactions and row versions, optimistic locking on editable entities, unique idempotency key per tenant/operation, transactional outbox for jobs, deterministic ordering in graphs. Job dedupe key includes tenant, input revision, engine/model/rule version and purpose. Worker lease expiry + retry; commit final outputs only if current input revision matches. Stale job results retained as history or discarded under policy; never promote them to current.

**Resource ceilings (initial proposed defaults):** 25 MiB file, 250 files/project import batch, 500 pages/document, 1 GiB/project demo limit, 3 concurrent analysis jobs/tenant. Strict expanded-byte/archive-entry/time limits; no archive nesting in initial version. Adjustable with load and cost validation. Unsupported PDF scans use optional local OCR or manual evidence entry; no promise of complete arbitrary-format extraction. Supported core: PDF, UTF-8 CSV, JPEG, PNG, plain text; DOCX/XLSX parsing only with bounded Office readers and macros/active content disabled. ZIP folder import limited to one level with safe names, no symlinks, no encryption. Verify format from bytes, not extension. External document links are not fetched automatically.

## 5. Canonical data model

All business-owned records include `tenant_id UUID NOT NULL`, `id UUID`, creation timestamps, applicable version and actor reference. Composite unique keys `(tenant_id,id)` and same-tenant foreign keys mandatory; no cross-tenant lookup from caller input. `created_at` UTC, business timezone IANA identifier, explicit local due dates. Use immutable revision tables for sources/requirements/evidence and current pointers; soft visibility changes are distinct from deletion. See domain constraints below.

| Entity | Main fields / relationships |
|---|---|
| Tenant, UserIdentity, Membership | Tenant name, settings; external issuer+subject; tenant role, active/revoked, member version. Global identity minimal and restricted. |
| Project, Counterparty, TemplateVersion | Tenant/project label, pack, timezone, state, rules revision; private counterparty and current approved template. |
| ProjectMember, ShareGrant | Project scope, permissions, expiry/revocation, token digest, exact export reference, access policy. |
| Document, DocumentVersion, Blob | Logical document, original filename, version, supersedes, hash, size, content type, scan status, storage key, retention; blob tenant-scoped. |
| SourceSpan, ExtractionRun | Version, page/section/offset/bounding box, exact text or OCR provenance, source hash, parser/model/prompt versions, status, cost, confidence metadata. |
| Requirement, RequirementVersion | Atomic statement, source span or manual provenance, applicability, mandatory flag, criterion, authority, stage, rule type, approved version. |
| Milestone, EvidenceWindow | Project stage, local due date/time, lead time, irreversibility class, approved rule and confirmed schedule version. |
| EvidenceItem, EvidenceLink | Original record/version, typed attributes, capture provenance; link to requirement version, rationale, state, reviewer, method. |
| AssetRecord | Equipment identity, normalised identifiers, source versions, status; no unchecked uniqueness across different asset contexts. |
| RuleVersion, EvaluationRun, Finding | Rule input/hash, snapshot ID, result code, severity, source IDs, blocker flag, suggested action, run provenance. |
| Task, Defect, Rejection, Decision | Assigned actor, due date, source, workflow state, rationale, linked finding, authorised review and exact input version. |
| FinancialMilestone, RetentionRecord | Confirmed amount minor units, ISO currency, tax basis, source, due conditions, status. Link table dedupes amounts per milestone. |
| ExportTemplate, Snapshot, Package, ManifestEntry | Template version, sorted pinned requirements/files/decisions, canonical hash, export state, signed manifest, artifact reference. |
| Acknowledgement, Communication | Actor/recipient, explicit receipt/acceptance type, source, state; send outcome and provider ID if authorised. |
| Job, OutboxEvent, Notification | Input version, lease, attempts, status, dedupe, delivery state; no raw sensitive payloads in logs. |
| AuditEvent, DeletionRequest, Hold | Tenant/actor/action/result, object reference, timestamp, chain/checkpoint metadata; minimal retention, reason and approved deletion state. |
| ProviderConfig, UsageLedger | Tenant policy, provider key reference (not secret), configuration version, request counts/tokens/cost units and limits. |

**Indexes:** tenant+project+state, tenant+doc+revision, requirement version and reverse evidence links, due dates, job eligibility, unique idempotency/manifest keys, audited event sequence. Search initially PostgreSQL text fields scoped by tenant and project; no global vector store. Migration tests prove constraints and tenant coverage. Foreign keys restrict deletes until intentional lifecycle cleanup; database owner separate from runtime. Avoid cascading accidental deletion of audit history.

## 6. State machines and evaluation rules

Document pipeline: `UPLOADING → QUARANTINED → SCANNED_CLEAN → PARSED → REVIEW_PENDING → REVIEWED`; side states `REJECTED`, `FAILED`, `SUPERSEDED`, `DELETION_PENDING`, `DELETED`. Scanner unavailable remains quarantined. Only current clean reviewed source can satisfy a current requirement; retained historical versions may be read under approved history permission.

Requirement applicability: `DRAFT`, `NEEDS_REVIEW`, `APPLICABLE`, `NOT_APPLICABLE_APPROVED`, `SUPERSEDED`. Evidence result: `MISSING`, `UNKNOWN`, `PROVISIONAL`, `CONFLICTING`, `VERIFIED_CONFIGURED_CHECKS`, `EXCEPTION_APPROVED`. Exception is separate from verified and requires authority plus source. Critical exceptions require independent approval and preflight policy; no blanket override. A requirement with unresolved conflicts is not satisfied even if a document matches.

Finding workflow: `OPEN → ASSIGNED → IN_REVIEW → RESOLVED` or `EXCEPTION_APPROVED`; reopen when input changes. Package: `DRAFT → PREFLIGHT_PENDING → BLOCKED` or `READY_FOR_REVIEW → APPROVED → GENERATING → GENERATED → RELEASED`; `FAILED`, `STALE`, `REVOKED` where appropriate. A package snapshot stays historically immutable; current readiness invalidates when underlying active revision changes. Approval and release compare pinned version atomically. “Released” means authorised export, not delivered/accepted. Acknowledgement must be explicit.

**Readiness algorithm:** (1) choose active approved ruleset and applicable requirement revisions; unresolved critical applicability is blocker; (2) evaluate named deterministic checks on approved inputs; (3) validate source spans and evidence status; (4) count current satisfied requirements; (5) report mandatory blockers for missing, conflicting, unknown, stale, unapproved or invalid mandatory evidence; (6) separately report approved exceptions and noncritical warnings; (7) allow readiness only if nonempty reviewed scope, no pending critical decisions, no mandatory blockers, all required integrity checks pass and snapshot current. No readiness for empty scope. Coverage = satisfied applicable / confirmed applicable; unknown applicability shown separately. Reviewed exceptions disclosed; never counted as verified evidence. Package labels: DRAFT, BLOCKED, READY UNDER CONFIGURED CHECKS (with any permitted exceptions). No generic “certified” badge.

**Financial logic:** accept canonical decimal strings at boundary; convert to integer minor units according to ISO currency configuration; use BigInt/NUMERIC with range checks. Preserve tax basis and currency; no FX conversion initially. Sum unique confirmed milestone IDs within one basis only; retain retention and dispute totals as separate categories, not aggregate potential recoveries. Unknown != zero. Display source/date and clear limitation. No statutory deadline calculator.

**ProofLock deadlines:** confirmed local milestone minus approved lead time, respecting timezone/DST; configurable business calendars with explicit holiday rules, otherwise elapsed time. Past deadline does not imply work took place. Deduped alert by project/requirement version/risk window/channel. Escalations use tenant settings; all automated messages off by default; only in-app notifications without external provisioning.

## 7. API and authorisation contract

REST JSON `/v1`, OpenAPI 3.1 generated/validated from schemas. Bearer OIDC JWT or secure same-site session, tenant selected only from verified membership. UUID resources, request correlation ID, pagination limit 50 default/200 max, stable cursor; no raw errors/secrets. `Idempotency-Key` required for mutation with side effects; `If-Match` revision required for mutable state. JSON financial amounts as strings. Standard problem response `{type,title,status,code,request_id,field_errors}`. Codes: 400 malformed, 401 unauthenticated, 403 action denied, 404 hidden/absent resource, 409 version/idempotency conflict, 413 limits, 422 validation, 429 rate limit, 503 unavailable. No sensitive identifiers in cross-tenant errors.

| Endpoint family | Methods and critical behaviour |
|---|---|
| `/projects`, `/projects/{id}` | GET/POST/PATCH; scoped list/create/edit/archive; role check. |
| `/projects/{id}/uploads`, `/uploads/{id}/complete` | POST one-time scoped upload grant, complete with expected size/hash; server confirms bytes, quarantines. |
| `/projects/{id}/documents`, `/documents/{id}/versions` | GET list/version history, POST new version; authorised short-lived download grant via POST. |
| `/projects/{id}/requirements`, `/requirements/{id}/decisions` | GET/POST/PATCH draft, POST approve/reject applicable revision; exact source and actor. |
| `/projects/{id}/evidence`, `/requirements/{id}/links` | GET/POST evidence and link; review decision separate; no AI approval. |
| `/projects/{id}/milestones`, `/projects/{id}/windows` | GET/POST/PATCH confirmed stage, computed windows; recalc by outbox. |
| `/projects/{id}/runs`, `/runs/{id}`, `/projects/{id}/readiness` | POST bounded evaluation, GET status/result and current snapshot; 202 for job. |
| `/projects/{id}/findings`, `/findings/{id}/decisions`, `/projects/{id}/rejections` | GET list, POST assignment/closure/reopen, POST feedback and classification. |
| `/projects/{id}/financial-milestones`, `/projects/{id}/retentions`, `/projects/{id}/financial-summary` | GET/POST/PATCH confirmed records; grouped exact sums; no payment actions. |
| `/projects/{id}/packages`, `/packages/{id}/approve`, `/packages/{id}/release` | POST pin and preflight, authorised review and atomic release; GET package history and status. |
| `/packages/{id}/shares`, `/shares/{id}/revoke`, `/public/share` | POST scoped expiring share, revoke; public token exchanged for minimal viewer session; no index. |
| `/projects/{id}/communications`, `/communications/{id}/send` | Draft only by default; explicit approval plus configured provider required to send. |
| `/projects/{id}/audit`, `/tenant/exports`, `/tenant/deletions` | Restricted GET audit, POST export/deletion request, explicit policy review. |
| `/jobs/{id}`, `/health/live`, `/health/ready` | Scoped GET job; minimal health outputs, detailed diagnostics admin-only. |

**Role matrix** (A = authorised subject to project scope; R = read; dash = deny). Organisation owner governs tenant membership/settings; admin cannot transfer ownership or bypass security. Capture/share principals are narrower than internal roles; no ACL derived from model output.

| Action | Owner/admin | Project manager | Reviewer | Contributor | Viewer/share |
|---|---|---|---|---|---|
| Tenant membership, retention, provider settings | A (owner-only sensitive actions) | - | - | - | - |
| Project setup, rule drafts, assignment | A | A | R | R | - |
| Upload / capture / suggest correction | A | A | A | A assigned | - |
| Approve requirements/evidence | A with review permission | A if delegated | A | - | - |
| Critical waiver / package approval | A with separation of duties | A if delegated | A review | - | - |
| Release / external send / sharing | A | A if delegated | - | - | - |
| Financial editing / review | A | A if delegated | R if permitted | - | - |
| Read package / export | A | A | A scoped | R assigned | R explicitly shared |
| Audit / delete / export entire tenant | A with policy | R scoped audit | R scoped | - | - |

Critical exceptions and releases require distinct reviewer and release actor in production mode; single-owner demo uses synthetic separate roles and cannot claim production approval. Owner cannot override immutable mandatory policy via ordinary admin endpoints. Revocation checked at API, worker execution and share access; short-lived signed URLs minimise residual access.

## 8. AI and performance architecture

**Model contract:** AI is an optional extraction/categorisation/transcription/suggestion engine, not an authority. Input includes explicit tenant-authorised source excerpts, page metadata, purpose, schema ID and max budget. Output schema: `{candidate_id, kind, value, source_spans[], uncertainty_reason, alternatives[]}`. Verify each span against extracted content/version; reject fabricated references, out-of-schema values, unbounded output and unsupported claims. OCR confidence is per-source metadata, not proof. No model-generated confidence substitutes for validation. No tool calling, network browsing, executable code or side effects from document contents. Deterministic rules run regardless of provider. Manual review and structured entry available offline/no-AI. No AI secret in browser.

Provider abstraction: `extract`, `classify`, `transcribe`, optional `compare`; adapters return model/version, usage, structured error, run ID. Use approved credentials from server secret store. Outbound allowlist, timeouts, max tokens, concurrency and tenant/job cost ceilings, explicit retry policy. Model outage leaves analysis pending/manual; never marks evidence verified. Do not automatically fallback to another provider without data-processing approval. Source minimisation and configurable redaction before API use; buyer verifies retention/training policy and data region. No customer material in automated evaluation fixtures.

**Cache and invalidation:** scope by tenant + hash + parser/model/prompt/schema/rule versions + redaction policy + purpose + context hash. Do not cache across tenants or reuse a result after input/context change. Store source references; selective invalidation through reverse edges; final deterministic full preflight. Hash original bytes once per upload, stream processing, bulk SQL operations, paginated views and async jobs keep UI responsive. Avoid loading huge source documents in memory. Storage quotas and extraction limits visible to owner.

**Proposed benchmark targets:** supported held-out critical error recall ≥98%; false positive rate <5% defined on independently labelled negative item/rule pairs; 100% material findings with valid sources; zero critical false-ready, cross-tenant access, duplicate retry effects and original evidence overwrites in release suite. Guided setup median <5 min; routine capture median <15 sec; changed-document reassessment p95 <30 sec for supported 10-page text PDF excluding initial upload and external queue wait (measure both separately); selected workflow active manual time reduction ≥75% against documented manual baseline; no avoidable AI rerun for unchanged identical cache key; complete manifest/file match. Unknown rate and reviewer correction burden reported; no hiding unknowns to inflate recall or speed. Targets require measured results, not promises.

## 9. Security, privacy and operational hardening

Threat model: hostile tenant, stolen credentials/link, malicious customer upload, insider, compromised model response or provider, compromised dependency, infrastructure outage, job replay, accidental deletion and unsafe exports. Assets: contracts, signatures, addresses, photos, equipment IDs, credentials, audit records, commercial figures and availability. Trust boundaries: browser/API, API/DB, upload/quarantine/parser, worker/AI, sharing/export, build/release, backups. Defensive testing only in authorised isolated fixtures/environments.

| Threat / control ID | Required controls and verification |
|---|---|
| S01 Tenant escape | Enforced RLS and composite FKs, separate non-owner non-BYPASSRLS runtime, transaction-scoped identity from authenticated context, signed/validated context where needed; all endpoints/table/objects tested with two tenants and forged IDs. |
| S02 Identity compromise | OIDC issuer/audience/signature/expiry validation, MFA supported by production IdP, role checks, revocation, session expiry, CSRF protections for cookies, rate limiting; no demo bypass in release. |
| S03 Object exposure | Private buckets, verified tenant/project access before grants, short TTL, opaque keys, no public ACL, encryption at rest; share/download/worker isolation tests. |
| S04 Malicious uploads | Quarantine and real scanner adapter, MIME sniff, file/expanded byte limits, sandbox parser without network or privileged filesystem, resource/time limits, safe preview. No macros, external references, executable content or unsafe HTML rendered. |
| S05 Injection / abuse | Parameterised SQL, strict schemas, escaped display/output, CSP, CORS deny by default, SSRF controls, safe paths and CSV formulas, rate/quota limits; negative tests for malformed input, XSS, traversal, upload abuse. |
| S06 AI manipulation | Treat all source text as data, no tools, structured validation, exact span verification, output escaped, outbound provider policy, no decisions/side effects; prompt injection and secret-exfiltration fixture suite. |
| S07 Integrity / replay | SHA-256, scoped idempotency keys, immutable version snapshots, hash-linked audit with independently protected checkpoints and optional signatures, stale approval invalidation; tamper/replay/concurrent-edit tests. |
| S08 Secrets / encryption | TLS verified, managed secret references, rotation, least-privilege keys, no credentials in source/client/logs/artifacts; backup encryption, key separation, test configuration fails closed. |
| S09 Privacy / deletion | Minimal fields, tenant private templates, explicit AI acceptance, retention categories, consent/authority records; deletion covers originals, derivatives, cache, links, queue, searchable index, object versions and backup expiry. Legal holds restricted and recorded. |
| S10 Supply chain | Lockfiles, pinned actions, dependency and secret scanning, SBOM, reproducible build inputs, protected review, artifact digest/provenance and release signing; no deployment from untrusted PR. |
| S11 Availability / recovery | Backpressure, connection limits, bounded retries, dead letters, idempotent workers, backup/restore procedure, monitored errors and queue age; simulated outage and restore integrity checks. |
| S12 Audit / incident | Minimal structured events for permissions, releases, AI usage, shares and data lifecycle; no full document text in logs; alerting, incident runbook, evidence preservation, owner approval for external notices. |

**Operational defaults (proposed):** private local synthetic demo; production disabled until configured. Audit/security logs 90 days by default subject to customer policy, quarantine rejected files 7 days, project material retained until customer-configured lifecycle, backups 30-day rolling expiry; legal review may change these. Deletion within 30 days of approved request subject to documented holds; immediately revoke access and queue deletion. Minimal audit metadata retained only where permissible and necessary. Restores replay deletion ledger before reopening access. These are design defaults, not legal requirements. Target RPO 24 h, RTO 8 h for initial buyer-operated deployment; unverified until rehearsal. No perpetual immutable customer content.

**Australian privacy/legal:** before real deployment, buyer/owner must review Privacy Act/APP applicability, data handling, processor agreements, overseas disclosure, breach response, jurisdiction-specific record retention and construction/security-of-payment obligations. No statutory compliance claim, ISO certification or legal advice. User-controlled source authority, clear notice, data access/correction/export, deletion and complaints processes. Commercial terms and liability limitations to be professionally reviewed. Domain/trademark/business name clearance outstanding. No real data or external production accounts are required to build synthetic prototype.

## 10. Test and competitive verification plan

Tests are traceable to feature IDs, workflows W01–W10 and security IDs S01–S12. Acceptance register per test records requirement ID, fixture version, commit SHA, environment, command, expected, actual, result, artifact hash, owner and defect. Status values: NOT_STARTED, IN_PROGRESS, PASS, FAIL, BLOCKED, NOT_APPLICABLE_APPROVED; no fake pass, no averaging away failing critical control.

| Suite | Required coverage |
|---|---|
| Unit / property | State transitions, deterministic matching, amounts, dates/DST, cache, risk sorting, graph invalidation, waiver rules, naming, idempotency; randomised seeded tests. |
| Integration | Fresh migrations, RLS catalogue coverage, signed/validated context, API permissions, object isolation, queue, scanner fail-closed, export manifests and retention tasks. |
| UI end-to-end | Mobile widths, keyboard, setup, ingestion, evidence review, ProofLock, correction, export, external link, revocation, offline fallbacks; no unsafe HTML. |
| Adversarial | Two-tenant permutations, role revocation, forged token, upload/MIME/archive abuse, prompt injection, malicious AI output, XSS, CSV formula injection, stale approval, replay and concurrent edits. |
| Resilience | Worker kill, repeated delivery, provider timeout, DB disconnect, scanner outage, failed export, storage quota, backup restoration, deleted-record reconciliation. |
| Performance | p50/p95 processing, peak memory, queue lag, cache hit rate, per-document AI cost, benchmark manual time with fixed hardware/file sizes and versions; compare fresh vs incremental. |
| Acquisition smoke | Clean checkout, documented install, demo login, synthetic scenario, one export, teardown, offline/manual mode and buyer-owned provider config. |

**Synthetic benchmark corpus:** minimum 10 projects across three initial verticals and two non-construction templates (maintenance and field-service acceptance); 200 labelled critical cases and 300 labelled negative item/rule pairs at minimum, independent hold-out split before tuning. Include poor scans, duplicate revisions, conflicting clauses, incorrect IDs, mandatory missing docs, ambiguous obligations, unusual dates, multilingual/unsupported files, prompt injection and clean valid packs. A human-reviewed truth manifest defines each expected finding and readiness outcome; generate fictional names and data; no genuine certificates. Use held-out sets without leaking labels into prompts. Report confusion matrix, precision, recall, false-positive rate, unknown rate, confidence intervals where appropriate, and limitations. Critical false-ready measured per project/snapshot. Test sample success is not proof of zero production errors.

**Competitive benchmark (no customer trials):** compare identical synthetic packs and defined tasks with accessible competitor documentation/demos or permitted direct trials only when authorised. Targets: setup, classification/review time, error recall/precision, traceability, revisions, export portability, privacy configuration, price and cost. Do not invent competitor results or claim market leadership. If paid access is unavailable, mark untested. Synthetic demo demonstrates capability, not adoption or commercial demand. Prior competitive research indicates overlapping features, so differentiation depends on execution of ProofLock + EvidenceGraph + preflight + portable export.

## 11. CI, deployment and operating economics

CI order: format/lint/typecheck → domain tests → build → migration and API RLS/integration → parser/scanner tests → browser E2E → security/regression → benchmark subset → SBOM/license/secret scanning → package digest and release verification. Full benchmark on candidate release. Fork/untrusted PR has no secrets; minimal workflow permissions; pin actions; no automatic production deployment. Record exact revision for each passing test; a green run on earlier SHA is not current evidence. Fix failures before progress credit; approved risk exceptions recorded, critical release failures never waived.

**Local/demo deployment:** Docker Compose with isolated synthetic database, private object storage, API, worker and frontend; deterministic fixture seed/reset; scanner in local demo if provisioned, otherwise explicit quarantine-only or pre-vetted synthetic fixture mode (never accessible in production). Manual-mode demo works without paid AI and mail. Demo admin role separate from production defaults, no shipped real credentials. Browser demo accessible on iPhone via buyer-provided authorised host or locally generated static illustrative prototype; ChatGPT cannot host a persistent production service or silently run future work.

**Production handoff:** buyer selects region, OIDC issuer, TLS, protected database/store, scanner, optional AI and mail, monitoring, backup encryption and secrets. Separate environment, migration dry-run and backup, readiness/health, rollback via forward fixes or tested restore, alert ownership and incident procedure. Track service availability and cost; no production use until release approval and outstanding security/legal controls satisfied.

**Cost model:** no mandatory paid AI or third-party integration during coding; core demo with synthetic files. Production cost = hosting + DB + object storage/egress + scanner + backups/monitoring + optional AI input/output/transcription + email. Enforce quotas; measure actual cost per package by provider, input pages and retry count. Initial commercial suggestion AUD 19–39 per project as hypothesis only; no payment processing implemented. Keep expenses within separately approved budget (no purchases). Production infrastructure and independent testing may exceed the proposed lean budget; those are buyer/owner decisions.

## 12. Development sequencing, release gates and 40% definition

| Gate | Weight | Exit evidence |
|---|---:|---|
| G0 Scope / blueprint | 10% | Approved this baseline, risk/decision register, feature-to-test mapping, name status. |
| G1 Foundation | 15% | Repository, runnable pinned stack, migrations, identity/tenant/file boundaries, CI, synthetic seed and initial negative tests. |
| G2 Core evidence slice | 15% | P0 ingestion, approved requirement/evidence graph, rule evaluation, readiness and draft/ready export integrated end-to-end; E1/E2/E6 acceptance tests and tenant controls pass. |
| G3 End-to-end intelligence | 20% | ProofLock, priority findings, revision/impact/recovery, financial records, review and rejection workflows; mobile capture tested. |
| G4 Complete feature scope | 20% | All F01–F47 applicable acceptance criteria passed on exact candidate including advanced adapters, sharing, offline and export. Optional providers need deterministic contract tests and separate live verification before live use. |
| G5 Hardening / performance | 15% | Full held-out benchmark, security regression, restore, load and accessibility review, all critical defects closed, exact SHA release evidence. |
| G6 Acquisition readiness | 5% | Buyer package, reproducible install, known limitations, transfer/licence inventory, final approval to list. |

Weights are engineering planning allocations, not a measured completion estimate. Count a gate only after its stated exit criteria pass; partial gate effort is tracked by accepted test IDs, not code volume. Project 002 reaches the requested 40% milestone only when G0–G2 pass (10+15+15). No project repository or code has been created in this task. Until G0 approved, actual implementation progress is not established. Preserve ProfitPilot priority; parallel work means alternating active sessions, not background coding.

**Release gates:** engineering candidate requires passing applicable tests, reconciled feature traceability, documented limitations and no unresolved critical/high release-blocking defects. Acquisition-ready may be sold as demonstrable software with explicit production limitations. Production-ready is separate and requires live identity/storage/scanner/AI where used, monitored environment, tested live recovery/network controls, independent penetration test and appropriate privacy/legal review. Certification is separate third-party evidence; do not claim it from synthetic tests. No deployment, listing or transfer without owner's specific approval.

## 13. Acquisition and ownership package

Deliver private source repository or clean archive, tagged release, source and binary hashes, build instructions, schema/migrations, fixture generator, test commands and evidence, architecture diagram, API schema, threat model, privacy/data-flow inventory, runbooks, backup/restore proof, SBOM, licence notices, IP contribution/provenance register, operating cost assumptions, integration configuration guide, limitations/defect register, mobile demo script, product tour, screenshots and buyer handoff checklist. No secrets, real user records, credentials or non-transferable provider accounts. Buyer supplies its own accounts/keys. Document AI-generated code review and third-party licence obligations; no unsupported exclusivity claim. Keep separately owned generic tooling distinct from transferred assets; rights depend on actual sale terms.

**Demo narrative:** fictional equipment installation with one missing stage-critical inspection, two mismatched serials, superseded warranty, duplicate photo and conflicting amendment. Demonstrate import, source-backed review, ProofLock warning, targeted correction, stale approval invalidation, financial milestone grouping, final package and manifest verification, controlled customer link and revocation, and manual mode. Show blocked then ready-under-configured-checks states; never imply actual payment recovered. Acquisition listing claims only tested functionality, test date and scope. Revenue/customer count: none established. Independent testing/production configuration/name clearance remain explicit if outstanding.

## 14. Decision register and residual risks

| Item | Proposed decision / unresolved dependency |
|---|---|
| D01 Market | Industry-neutral schema; construction first for synthetic templates. Cross-industry rules need validation, not generic compliance promises. |
| D02 Brand | Verivaro working name; formal Australian trademark, ASIC and domain clearance not established. |
| D03 Stack | TypeScript/PostgreSQL modular monolith with worker, not microservices; exact versions/licences pinned during G1. |
| D04 AI | Optional provider adapter, manual mode mandatory; pricing and live provider verification unconfirmed. |
| D05 Security | Private repo recommended; live scanner/infrastructure/independent testing required for production. No certification yet. |
| D06 Offline | PWA best effort; browser storage/crypto capabilities vary; fallback online mode and visible pending state. |
| D07 Financial/legal | Documentary readiness only; no statutory/payment entitlement claims. Professional legal review required. |
| D08 Performance | Targets untested; hardware, datasets, budgets and limits may require adjustment before release. |
| D09 Commercial | No customer pilots or real business tests as requested; acquisition demand and actual sale price unvalidated. |
| D10 Authority | Blueprint choices are proposals; approve scope before code, spending, account setup, deployment or listing. |
| D11 IP | Only reusable components with documented rights; no automatic transfer or reuse of ProfitPilot intellectual property. |

**Change control:** a proposed change must state problem, affected feature and gate IDs, security/privacy impact, cost, test changes and owner approval. Existing features may be optimised without expanding scope, provided behaviour and acceptance remain consistent. Maintain a defect register (severity, reproduction, affected versions, fix SHA and tests). Treat architecture choices as reviewable decisions rather than unverifiable claims.

## 15. Final blueprint acceptance

This baseline specifies the complete agreed feature scope as 47 traceable capability IDs across seven engines; related names and security subcontrols have been consolidated without dropping the agreed functionality. It defines product boundaries, workflows, data structures, permissions, state transitions, API families, AI limits, performance objectives, threat controls, tests, deployment and acquisition gates. Detailed OpenAPI schemas, migration SQL, design implementation, exact dependency versions and executable test fixtures are G1–G4 outputs, not claimed completed here.

**Next authorised step:** G0 approval, then G1 repository foundation with synthetic data, security controls and CI. Do not begin implementation by claiming market leadership, production compliance, certification or completed testing. The owner retains release and commercial authority.

**End of baseline · VERIVARO V4.0**
