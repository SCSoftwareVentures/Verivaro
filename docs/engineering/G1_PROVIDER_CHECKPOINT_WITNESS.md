# G1 separately witnessed provider-key checkpoint — candidate integration contract

**Status:** Implemented as an **optional adapter**, with independent synthetic witness-state fixtures. No actual external authority was connected, approved or certified. Neither a local file nor an in-memory mock constitutes an independently protected production witness.

`src/security/provider-checkpoint-witness.mjs` exports `openWitnessBoundProviderVerifier({store,witness,issuer,audience,authorityKey,requiredAcr,catalogue,signature,...})`. The `store` must be the existing single-active-verifier local checkpoint store. The `witness` must be an *independently governed*, durable and atomic source with `read({issuer,audience})` and `compareAndSwap({issuer,audience,previous,next})`; both return a `{sequence,digest}` checkpoint. It must have separate storage, administration, backup, credentials and failure domains. Do **not** implement it as a second file on the same host, unprotected service variable, Git commit, untrusted HTTP response or ordinary database table owned by the signer.

## Enforced invariants

- Startup requires exact equality between local checkpoint and independent witness **before** accepting a signed provider-key catalogue. It rechecks both sources after binding the sole in-process verifier, rejecting races.
- Signed catalogue validation happens before the store is bound. Any rejected signature or stale catalogue cannot claim the verifier lease.
- Every keyset rotation checks the current witnessed checkpoint, then advances witness via independent atomic compare-and-swap *before* writing the local fsynced disk checkpoint. On a crash between commits, the witness is ahead and restart **fails closed**. This is intentional: operational reconciliation is required rather than silent rollback.
- Any indeterminate witness result, CAS error, local storage failure, disagreement or concurrency failure causes the active verifier to deny subsequent token validation. The witness must never claim a checkpoint is durable before it actually is.
- `verify()` is **synchronous** and only checks the witness at startup and rotation, not per request; this is explicitly a **single-active-service** mechanism, *not* a multi-node key-revocation protocol.

## Synthetic tests

`tests/unit/provider-checkpoint-witness.test.mjs` uses real disk checkpoints plus a separate in-memory fake witness to simulate external monotonic state. It checks local snapshot rollback detection, restart denial, witness-before-disk ordering, absent/stale witness, and a simulated local fsync failure. This proves application handling, **not** independent custody, durability, Byzantine resistance, networking, failover, TLS, secure clock, power-loss resilience or multi-host consensus.

## Operational acceptance still required

Select and separately authorise a real monotonic witness outside the verifier's security domain; configure distinct nonexportable credentials, atomic compare-and-swap semantics, consistent reads, tamper-evident audit trail, incident recovery, high availability and partition behaviour. Independently test post-crash and restored snapshots before declaring production anti-rollback. A signed provider-key catalogue alone cannot provide monotonicity when both checkpoint and catalogue can be rolled back together.

Keep PR review open and do not deploy, purchase, activate a cloud service, or handle production keys without owner approval.
