# @staticdeploy/pg-s3-storages

Gateway for storage resources backed by [S3](https://aws.amazon.com/s3/) (or any
API compatible alternative like [MinIO](https://min.io/)) to store static files,
and [PostgreSQL](https://www.postgresql.org/) to store metadata about the files,
as well as the other entities of StaticDeploy.

The S3 client accepts an explicit endpoint and region, with path-style
addressing enabled by default for backward-compatible MinIO behavior. Set both
`accessKeyId` and `secretAccessKey` for explicit credentials, or omit both to
use the AWS SDK default Node credential provider chain. `enableGCSCompatibility`
continues to replace bulk deletes with individual object deletes for GCS.

## V2 quarantine and immutable objects

The v2 role factories construct separate control, worker, and content clients;
production composition must inject only one role-specific S3/PostgreSQL identity
into each command. Control can only create declared quarantine objects under
`v2/quarantine/{release-id}/files/{safe-relative-path}`. The worker reads and
deletes quarantine objects and promotes verified bytes with create-only writes
under `v2/releases/{application-id}/{release-id}`. Content exposes only READY
release content reads; partial prefixes remain unreferenced. Every write
verifies the declared size and SHA-256 against a full-body read-back, and
idempotent retries accept an existing object only after the same verification.

Paths are NFC UTF-8 POSIX-relative names and reject traversal, ambiguous
separators, invalid surrogate text, case/normalization collisions,
file/directory collisions, and keys over S3's 1,024-byte UTF-8 limit. Disposable
MinIO tests provision distinct control, worker, and content users and verify raw
prefix/action denials; those local policies are evidence only. The pinned MinIO
policy engine cannot require the `If-None-Match` request header, so application
create-only behavior is tested locally but raw worker-credential overwrite
rejection is explicitly not claimed. Production credential/prefix policy,
conditional-header enforcement, retention, and provider acceptance remain
blocked on B-S3.

## V2 release jobs and cleanup

`createV2ReleaseJobQueue()` uses the migration-05 `SECURITY DEFINER` entry
points for atomic due claims, live renewal, expired-lease reclaim, final-attempt
crash terminalization, and transaction-held finalization fences. All transitions
bind the job ID, owner, and monotonic `lease_version`; retry timing is computed
from the post-lock PostgreSQL clock and is exponentially bounded. The migration
revokes `PUBLIC`; deployment grants are limited to explicit function `EXECUTE`
capabilities rather than direct job-table mutation.

`V2ReleaseJobWorker` binds the exact manifest/declaration/default-document work
identity before its first release-object write, renews at every S3 boundary, and
completes a processing job only when that identity matches the immutable READY
manifest. Cleanup requires a caller-configured bounded minimum age, checked
against the post-lock database clock, and refuses every nonterminal processing
job before sealing the release FAILED. Upload writes hold a shared release lock
through S3 read-back, so cleanup cannot race a late write. Cleanup lists,
deletes, and re-lists the complete exact `v2/quarantine/{release-id}/` prefix,
including `original.zip` and orphan objects, with bounded pagination and
restart-safe partial failure. It never targets release or routing prefixes.

Disposable MinIO JOB-03 evidence intentionally uses an unversioned quarantine
bucket: deleting an object removes its bytes there. Production quarantine
versioning/lifecycle purge behavior, credentials, and provider-policy acceptance
remain **BLOCKED-EXTERNAL on B-S3**; a versioned production bucket cannot be
accepted from the local current-version list/delete proof.

## V2 server-side OIDC sessions

Migration 06 adds short-lived, one-time login transactions and narrow
`SECURITY DEFINER` functions for session creation, database-clock lookup/touch,
revocation, and bounded cleanup. `V2OidcSessions` performs Authorization Code
with S256 PKCE, burns the state transaction atomically before token exchange,
and validates the configured issuer, audience, nonce, time claims, RS256
signature, and exact `kid` against bounded discovery/JWKS responses. Production
OIDC HTTPS resolves every endpoint, rejects any special/private answer, and pins
the selected validated address through the TLS connection while preserving the
original hostname for Host, SNI, and certificate verification; redirects and
compressed responses fail closed. Login starts are bounded before provider or
database work by direct-peer and process admission, with a cross-instance
PostgreSQL ceiling retained. PKCE verifiers and the required synchronizer-CSRF
value use row-bound, versioned AES-256-GCM envelopes with an explicit key ID and
fresh nonce; provider tokens are not persisted. Callers supply a bounded keyring
so old envelopes are re-encrypted during overlap and removed keys fail closed.

The only browser credential is the high-entropy opaque
`__Host-staticdeploy-session` cookie (`Secure; HttpOnly; Path=/; SameSite=Lax`).
Control mutations require the exact configured HTTPS Origin, a session-bound
synchronizer CSRF value, and the endpoint-specific media type before any session
touch. Login replaces an existing session atomically, logout revokes server
state and expires stale cookies, and idle renewal never exceeds absolute expiry.
The callback consumes its independent transaction binding and redirects to a
fixed clean portal URL; CSRF is bootstrapped separately and held in portal
memory. Server-session API requests use the opaque cookie plus CSRF and never a
browser OIDC bearer token.

Server-side OIDC requires a separately provisioned `OIDC_POSTGRES_URL`, complete
keyring, and grants for the exact combined migration-06 session and migration-07
authorization entry functions—never either set alone. Startup verifies that the
identity has no elevated role attributes or memberships, object ownership,
schema/database creation, direct authentication/audit table access, or unrelated
`SECURITY DEFINER` wrapper access, while every required wrapper is executable;
schema migration remains a distinct command. The focused local mock AUTH
component suites are not a real-provider or production IdP acceptance and do not
claim the later M3 foundation gate. AUTH-06 and production
issuer/client/redirect/logout/group/key-rotation acceptance remain
**BLOCKED-EXTERNAL on B-OKTA**; final production identity/grant acceptance
remains **B-PG**.

## V2 authorization and audit policy

Migration 07 adds the application `binding_version`, immutable actor-scoped
binding request identities, an immutable initialize-once authorization policy,
and narrow wrappers for authorization and whole-set binding replacement. Global
administrator authority comes only from exact configured stable group IDs in
that policy row; `v2_bindings` remains application-scoped and permits only
OWNER, PUBLISHER, or VIEWER. Unknown, differently cased, renamed, malformed, or
stale groups grant nothing.

`V2Authorization` evaluates the committed administrator/owner/publisher/viewer/
denied capability registry against the current application bindings on every
decision. It fences the exact active session ID, subject-derived audit identity,
group set, and `claims_version` under PostgreSQL locks, so binding or session
changes cannot use a process cache. Complete binding replacement validates the
entire desired set before mutation, authorizes before idempotency lookup,
linearizes on the application row, scopes immutable retry identity by actor and
application, applies either one complete set or none, and appends its audit in
the same transaction. Owners may hand off or demote their own binding while
adding or promoting only the application roles they are allowed to delegate;
global administrator cannot be represented as an application binding.

Authorization decisions and replacements emit only closed role/source/action/
result values, counts, versions, and SHA-256 request identity. Migration 07
extends the append-only trigger with a 4096-byte serialized-UTF-8, 12-key,
scalar-only metadata allowlist; raw bodies, headers, queries, cookies, CSRF/OIDC
tokens, emails, display names, idempotency keys, and free-form errors are never
copied. Audit query/pagination remains M4-03 scope. The combined control runtime
receives EXECUTE only on the exact session and authorization wrappers and cannot
read or mutate bindings, policy, requests, or audits directly. Startup
initializes the policy once, then compares its actual canonical groups, claims
version, and SHA-256 configuration digest before serving; later conflicts fail
closed.

AUTHZ-01 and TM-AUD-01 are local logical evidence only. Real Okta stable group
IDs, rename behavior, propagation, accepted stale interval, users, and group
mapping remain **BLOCKED-EXTERNAL on B-OKTA**; production role provisioning and
capability acceptance remain **B-PG**.

## V2 publication routing projection

Migration 08 turns the migration-04 publication outbox into the executable
ADR-009 protocol. Control uses one `SECURITY DEFINER` request function that
locks the application and atomically advances desired state, appends a bounded
`*_REQUESTED` audit event, and inserts one immutable outbox identity. The outbox
copies the issuer-scoped actor hash, canonical request digest, requested-audit
identity, and an explicit normalized ASCII routing-host snapshot supplied by the
authorized caller. No production suffix is invented here: B-DNS/M3-09 owns the
external host-to-routing-ID derivation. A fenced worker then binds one routing
`kid` before its first S3 side effect. Claims, renewal, retry, terminal failure,
and acknowledgement require the exact row, owner, and monotonic lease version.
Final acknowledgement atomically advances served state, records the opaque
read-back ETag/optional object version, appends the final audit event, and
completes the durable idempotency result.

Routing generations are deterministic canonical Ed25519 envelopes with a closed
protected `alg=EdDSA`/routing `typ`/single `kid` header and signed purpose,
audience, context, normalized host, application, routing, generation, immutable
request time, operation, release/prefix, and manifest digest. The worker-only
signer validates matching Ed25519 key pairs and validity windows;
content/reconciliation accept a separate public-only verifier. Active keys sign
new rows; overlap keys may finish already-bound rows; unknown, expired, retired,
revoked, or wrong-purpose keys fail closed. Generation objects are create-only.
`current.json` is never written unconditionally: initial creation uses
`If-None-Match: *`, replacement uses the opaque ETag of the last verified
pointer, and acknowledgement requires an exact body/signature/digest/ETag
read-back.

`V2ContentRoutingCache` has only S3 and public verification keys. It requires
`current.json` to equal its immutable generation and verifies the release
manifest identity/digest before advancing a monotonic in-process watermark. Any
refresh failure preserves the verified release or tombstone last-known-good; a
cold process fails closed. `V2ProjectionReconciler` uses bounded database and S3
reads to report desired/served/outbox/pointer/generation/manifest drift and
valid-old/version-history ambiguity without editing immutable release content.

Disposable PostgreSQL/MinIO PROJ-01 through PROJ-06, TM-PROJ-01, and TM-KEY-01
prove the local protocol and narrow routing prefix actions only. MinIO does not
prove production conditional-header enforcement, read-after-write/version/audit
semantics, encryption, retention, or provider identities; these remain
**BLOCKED-EXTERNAL on B-S3**. Production routing-key delivery, rotation,
revocation, and emergency replacement remain **B-DEPLOY**. Actual command
separation remains M3-09, so this focused evidence does not close full G-M3.

## PostgreSQL migrations and connections

This package uses the directly pinned and supported Knex `3.1.0` and PostgreSQL
client `pg` `8.16.3`. The existing `postgresUrl` remains the complete connection
contract, including any operator-selected TLS query parameters. The service does
not add environment knobs for pool behavior. Knex uses an explicit `pg` client
with conservative bounded defaults: pool minimum `0`, pool maximum `10`, idle
connections eligible for reaping after 30 seconds, connection attempts bounded
at 5 seconds, and pool acquisition bounded at 10 seconds.
`PgS3Storages.destroy()` closes both the PostgreSQL pool and S3 client and is
safe to call repeatedly.

Production migrations are append-only and numerically ordered. Never rename,
edit, or reformat historical source migrations `00.ts` through `02.ts`. Knex
records those names in TypeScript execution and the corresponding `00.js`
through `02.js` names in compiled production execution, so both ordered stems
are compatibility surfaces. A future production schema change must use a new
migration and the expand-backfill-contract convention:

1. **Expand** with additive nullable columns, tables, constraints, or indexes
   that old and new application versions can both tolerate.
2. **Backfill** separately, transactionally, and in bounded/restartable batches.
3. **Contract** only in a later deployment after compatibility and rollback
   windows close.

New additive migrations must include and rehearse a real inverse `down`
operation while their tables are empty. Once v2 data exists, migration 03
refuses destructive rollback; migration 04 applies the same lock-before-check
rule to sessions, idempotency records, jobs, and outbox acknowledgements.
Application rollback leaves the additive schema and retained READY/audit or
operational history installed. Job and outbox claims increment a monotonic
`lease_version`; every renewal or reclaim update must include the expected
owner/version predicate so stale workers affect zero rows. Release-job claim,
renewal, work binding, cleanup sealing, retry, completion, and failure are
available only through the migration-05 validated wrappers;
`v2_finish_release_job_attempt` remains an internal, non-granted transition
primitive. Publication attempt completion remains narrowly granted through
`v2_finish_publication_attempt`. Outbox acknowledgement is likewise available
only through the explicitly granted `v2_acknowledge_publication` function, which
locks application-first, checks the fenced lease against the post-lock database
clock, atomically confirms desired state, advances served state, assigns the
first release label, and acknowledges the matching row. Outbox rows retain an
immutable copied idempotency ID after the bounded idempotency record expires and
is cleaned up. Do not run an all-history rollback: the legacy `down` functions
in `00.ts`-`02.ts` intentionally do nothing and therefore cannot restore an
empty schema. Recovery across those historical migrations requires a verified
database backup/restore procedure.

PostgreSQL 16 is the supported runtime target. The CI schema gate runs SCH-01
through SCH-05 there and retains a PostgreSQL 13 compatibility lane for the
checksum-pinned pre/post-02 production fixtures. Coverage verifies empty and
legacy upgrades, data and foreign-key preservation, migration atomicity,
non-destructive down/reapply, publication/idempotency/lease concurrency,
immutable results and acknowledgements, session expiry/revocation, bounded query
indexes, and connection/pool recovery. Production acceptance remains
**BLOCKED-EXTERNAL on B-PG** until the production PostgreSQL roles, migration
identity, backup destination, restore owner, and RPO/RTO are provisioned and the
same acceptance is rehearsed there.
