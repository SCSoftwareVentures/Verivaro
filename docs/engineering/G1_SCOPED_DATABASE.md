# G1 scoped database adapter

Candidate driver-neutral implementation. Only three read operations are exposed:
project list, project lookup, and evidence metadata list. User-controlled SQL,
role names, connection challenges and signing keys are not accepted through
the operation interface. Queries use fixed statements and bind parameters.
Listing is capped at 200 rows; pagination remains a product requirement.

A trusted service acquires an exclusive connection from a private pool,
clears session state, rejects obviously privileged login attributes, switches
to the least-privilege runtime role, begins READ COMMITTED, sets resource
timeouts, obtains the database-generated challenge, verifies identity and signs
a transaction-bound context, and checks live tenant membership. Project RLS
remains mandatory. Success commits and clears the session. Any error fails
closed; a failed/uncertain lease is destroyed. No raw driver errors are
returned to callers.

The pool and its login are deployment trust boundaries; this adapter cannot
certify that the login lacks all indirect privileged memberships. The dedicated
login must only be permitted to SET ROLE verivaro_runtime. No real driver is
bundled. Existing unit tests use a strict mock client; they do not establish
actual pooled driver behavior or cancellation semantics. Real PostgreSQL driver
integration, live pool reuse, cancellation, token/session-specific revocation,
share revocation, observability and independent testing remain release gates.
No production infrastructure, real data, or paid dependencies are introduced.
