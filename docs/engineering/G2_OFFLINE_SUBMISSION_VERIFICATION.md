# Offline submission integrity verification (F40)

The dependency-free Node module `src/security/submission-verifier.mjs` verifies the exact canonical STORE ZIP produced by the controlled submission service. It requires both the expected manifest SHA-256 and whole-package SHA-256 obtained independently through a trusted channel. The archive alone is not a trust anchor. The download response supplies the archive hash in `X-Package-SHA256`; the authorised snapshot supplies the manifest hash.

```js
import {verifySubmissionPackage} from './src/security/submission-verifier.mjs';
const result = verifySubmissionPackage(archiveBuffer, {
  expectedPackageSha256: trustedArchiveDigest,
  expectedManifestSha256: trustedSnapshotDigest
});
```

The verifier rejects noncanonical ZIP layouts, external paths, duplicate entries, compression, unknown files, trailing bytes, inventory discrepancies, missing evidence, mismatched hashes and unsupported formats. It bounds input at 20 MiB, 66 files and the existing submission evidence limits. No files are extracted, decompressed or executed. It returns a bounded integrity summary rather than evidence contents.

This is content-integrity verification, not digital-signature verification. It does not authenticate approvers, attest current authorization, certify legal validity, scan for malware, or prove delivery or acceptance. `authenticityVerified` is always false. Distribution of independently authenticated expected hashes is not implemented here. The API/browser workflows remain unchanged. Automated tests cover generated-package round trip and negative cases; hosted CI is the verification gate.
