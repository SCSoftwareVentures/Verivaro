# G1 signed transaction context — implementation increment

Draft, pending exact-head CI and independent review. Migration 0003 supersedes the
insecure policies from 0001/0002. All migrations must be applied before runtime
access is granted. The old tenant/actor GUCs have no authorization effect.

**Trust boundary:** the API verifies RS256 identity and signs a canonical context
using a random 32-byte HMAC key. The database verification key is provisioned
out of band by a privileged administrator into the private singleton table.
Runtime SQL must not own schemas, tables or privileged functions, access the key,
or receive migration/service credentials. CI's signing function is test-only.
No default production key, secret, or runtime key provisioning endpoint exists.

Acquire an exclusive pooled connection, BEGIN, obtain
`SELECT pg_backend_pid() AS pid, pg_current_xact_id()::text AS xid`,
then use the verified token and server-resolved tenant selector with
`signDatabaseContext`. Set the result using parameterized
`SELECT set_config('verivaro.signed_context', $1, true)`. Membership is checked
by RLS. On error roll back; always release or discard the connection. The
token is bound to backend and full transaction ID, and expires in <=45 seconds.
The SQL validator rejects envelopes expiring more than 60 seconds ahead.
The signer must receive the challenge only from the actual acquired connection.
Do not log contexts or keys. A compromised trusted signer is outside this
runtime SQL threat model. Keep the signer key inaccessible to arbitrary SQL.

Deployment requires granting execute on verivaro.bound_context() and the minimum
approved table privileges to a non-owner runtime role. Key rotation presently
invalidates outstanding envelopes; coordinated rotation and recovery, read-only
transaction handling, revocation of identity tokens, project-level permissions,
production grants, parameterized pool adapter, pool/cancellation tests and
independent review are still outstanding. No claim that G1 or release is complete.
