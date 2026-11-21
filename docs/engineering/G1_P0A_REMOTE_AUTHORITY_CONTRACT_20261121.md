# G1 / P0-A — Remote authority and revocation contract (reference only)

**21 November 2026 · Design and executable protocol checks · NOT A DEPLOYED AUTHORITY**

## Decision and scope

A client cannot establish **independent** recovery-floor trust by trusting a server, its own database, a local writer lock, a self-issued certificate or the same administrator's copy of an allegedly trusted checkpoint. The code in this increment verifies **externally supplied** policy inputs and detects several adversarial behaviours. It does not create, operate or authenticate a remote linearizable authority and is **not** a production security claim.

The new `src/security/provider-witness-authority-trust-policy.mjs` defines a canonical, Ed25519-signed `verivaro-g1-review-floor-trust-policy-v1` statement with:

- issuer, audience, strictly increasing *operator-controlled* policy revision;
- SHA-256 digest of the exact serial-to-key schedule, which is already separately pinned;
- minimum permitted floor `{serial,headHash}` to detect rollback below an externally trusted checkpoint;
- unique, sorted, explicitly revoked Ed25519 public-key fingerprints (including emergency revocation at an unchanged floor serial);
- issuance/expiry timestamps, maximum one-day policy lifetime.

The statement's canonical SHA-256 must match `trustedCheckpoint={revision,digest}` from a **different trust domain**, and its signature must verify under a separately pinned Ed25519 **governance** key distinct from all scheduled authority keys. An opaque verified policy object is returned only after these checks. It is not a source of secret keys and grants no authority to repair, restart, clear locks, or operate recovery.

`verifySignedRecoveryFloorAuthority` checks the policy against the **signed floor receipt's** serial and head hash, exact schedule digest, current timestamp and revoked signer key. A revoked active signer therefore cannot continue producing accepted receipts at the same serial, even with valid nonce and signature. A policy that has expired, that requires a higher floor, or whose schedule differs is rejected, not silently downgraded.

## Required external interface

The existing gate supports `openReferenceRecoveryFloorPublicationGate({...})` with *both* `trustedFloorPolicy` and `readFloorPolicyCheckpoint(scope,{signal})`. If either is missing or a key schedule is not pinned, initialization fails. A caller-provided checkpoint reader must return **exactly** `{revision,digest}` from independently controlled, monotonically advanced storage. It is queried before and after every signed authority read and at the end of publication. In-flight changes or disagreement permanently fault the gate. The test implementation uses synthetic in-memory callbacks only.

An **actual production authority** would additionally need all of the following, as a jointly reviewed cross-domain protocol:

1. Separate operator/IAM custody for governance and authority signing keys, including issuance, two-person approvals, independent time, emergency revocation and audited rotation; neither the app nor tenant database can rewrite policy checkpoints.
2. An independently authenticated, mutually authorised channel with explicit issuer/audience, least privilege, service identity, anti-replay nonce, bounded deadlines, and verified remote public keys. This repository does not supply mTLS production identities or remote endpoints for this authority.
3. A **linearizable**, durably replicated compare-and-swap store for `{serial,headHash,logHash,policyRevision,policyDigest}`; competing writers must be fenced by the authority itself, not by the client or a local `O_EXCL` file lock. A signed response or two reads cannot prove a distributed CAS.
4. **Revocation and CAS must be one atomic authority-side decision**: if a policy is revoked during an in-flight CAS, the authority must reject the commit or prove an ordering in which it preceded the revocation. Client-side pre/post checkpoint checks detect uncertainty but cannot retroactively stop a remote commit.
5. A separately retained, rollback-resistant high-water mark and reconciliation process; reboot, snapshot restoration, loss of acknowledgement, split-brain, loss of clock confidence, revoked credentials or inability to prove remote quorum must stop publication without retrying or lowering the floor.
6. Reproducible operator tests on truly **separate machines and trust domains**: 2+ writers, genuine network partitions, stale replicas, signer compromise, epoch rollover, emergency revocation at unchanged serial, crash/power loss during commit, key rotation and backup restore. Measure external RTO/RPO and preserve incident logs.

## Current automated negative cases

`tests/unit/provider-witness-authority-trust-policy.test.mjs` checks policy signatures, independent pinned checkpoint matching, key-schedule commitments, expired/future policies, same-serial revocation, invalid/gapped or unsigned trust, wrong signer, and refusal to authenticate forged plain policy objects.

`tests/unit/provider-witness-recovery-floor-publication.test.mjs` checks startup with a *simulated* independent checkpoint, pre/post reads, stale checkpoints, a revocation claim at the same serial, and an ambiguous remote commit during policy advancement. These are executable API contract simulations. **They do not demonstrate independent operation or real distributed consensus.**

## Handover criteria

Before production clearance, obtain independent evidence for the complete protocol above and confirm that protected floor/policy state cannot be rolled back by the application operator. Verify the governance signer is not under the same administrative authority, assess emergency-revocation propagation and atomicity, and document who may clear a permanently faulted incident and on what proof.

**Status:** `G1_WITNESS=REFERENCE_ONLY`, `productionSecurityCertified=false`, `approvedForAutomaticRecovery=false`. Draft PR only; no deployment, external credentials, paid service or automatic recovery action.
