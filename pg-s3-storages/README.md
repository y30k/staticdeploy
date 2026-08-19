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
owner/version predicate so stale workers affect zero rows. Retry, completion,
and failure are available only through narrowly granted
`v2_finish_release_job_attempt` and `v2_finish_publication_attempt` functions.
Outbox acknowledgement is likewise available only through the explicitly granted
`v2_acknowledge_publication` function, which locks application-first, checks the
fenced lease against the post-lock database clock, atomically confirms desired
state, advances served state, assigns the first release label, and acknowledges
the matching row. Outbox rows retain an immutable copied idempotency ID after
the bounded idempotency record expires and is cleaned up. Do not run an
all-history rollback: the legacy `down` functions in `00.ts`-`02.ts`
intentionally do nothing and therefore cannot restore an empty schema. Recovery
across those historical migrations requires a verified database backup/restore
procedure.

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
