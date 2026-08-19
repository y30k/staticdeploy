# StaticDeploy Modernization Technical Design

## Inputs and status

- Roadmap: `docs/2026.08.17-Project-Plan.md`
- Lifecycle gates: `docs/ai-dlc/modernization-milestones-1-7.md`
- Test strategy: `docs/test-strategies/staticdeploy-modernization.md`
- Work items: `docs/prd-work-items/staticdeploy-modernization.md`
- Baseline: legacy TypeScript/Yarn/Lerna application at commit `636e00f`, with
  two required pull-request GitHub Actions workflows and M1-R1 retirement
  cleanup merged

This design approves repository-safe contracts for local implementation. It does
not provision or authorize production registries, deployments, Okta, DNS/TLS,
PostgreSQL, object storage, pilot users, cutover, or Eyes ingestion.

## Goals and non-goals

The target is one operated platform that lets internal users create an
application, upload direct files or a ZIP, select any uploaded HTML document as
default, inspect findings, preview on an isolated origin, publish/unpublish
timestamp-labeled immutable releases, download source, restore a retained
version, and audit who did what.

The platform does not execute uploaded server code, build frameworks, create
per-application infrastructure, support public/custom-domain applications,
expose browser-readable management tokens, or become a general PaaS. The
TypeScript monorepo and useful domain boundaries evolve in place; this is not a
language or wholesale architecture rewrite.

## Current-to-target boundary

```text
Current
  one Express process
    -> management API + portal
    -> static serving
    -> legacy bearer-token authentication
    -> legacy Apps/Bundles/Entrypoints/OperationLogs
    -> mutable/cross-store bundle path

Target (one release, separately executed)
  staticdeploy control  -> portal/API/session/authz/direct upload
  staticdeploy content  -> database-free published/preview serving
  staticdeploy worker   -> leases/validation/scanning/releases/projection
  staticdeploy migrate  -> additive schema migrations under lock

  PostgreSQL v2 tables  <-> control/worker/migrate with distinct roles
  object quarantine     <-> control writes, worker reads/deletes
  immutable releases    <-> worker writes, content reads
  routing projection    <-> worker writes, content reads/cache
```

One multi-architecture OCI image contains the four commands. Compose and Helm
run them as separate workloads with different configuration and credentials. The
CLI image is retired.

## Architecture decisions

### ADR-001 — Retire unverified compatibility and distribution surfaces

**Status:** Approved repository default; M1-R1 enforces it.

Retire y30k distribution/support for API v1, the legacy CLI and CLI image,
public npm packages, Docker Hub images, and website publication. Preserve their
source temporarily only for characterization and migration analysis. V2 does not
promise behavioral compatibility with Bundle/Entrypoint/deploy contracts. No
package publication workflow exists unless a later approved consumer names the
package and supplies an acceptance test; then its only destination is GitHub
Packages.

This follows the approved default-retirement policy and the existing inventory,
which found no approved y30k consumer. If new authoritative evidence identifies
a consumer before deletion, the affected change stops for an explicit exception;
compatibility is not silently restored.

### ADR-002 — Select and pin the supported runtime through an evidence gate

**Status:** Approved — Node `24.19.0`, Yarn `4.18.0`, Lerna `10.0.0`.

The user’s full project authority approves Node `24.19.0`, verified against the
official Node release index on 2026-08-17. Isolated Yarn/Lerna and pnpm
prototypes selected the supported Yarn/Lerna upgrade as the lower-complexity
path. The evidence and rollback are recorded in
`docs/decisions/2026.08.18-m2-toolchain-and-distribution.md`.

The implementation PR:

1. pins the exact Node, Yarn, and Lerna versions in repository metadata, CI,
   developer setup, and container builders;
2. uses Yarn's `node-modules` linker and immutable installs with an exact
   reviewed package/version install-script inventory; global install-script
   enablement is forbidden by M2-GATE;
3. renames the duplicate private root package and removes obsolete/redundant
   Lerna declarations;
4. scopes the legacy Webpack OpenSSL bridge to the console build and assigns its
   removal to M4-10;
5. makes clean install/build/test and lockfile reproducibility required; and
6. opens automated patch updates subject to all required checks.

A forecasted future Node version, “latest,” or the current EOL Node 14 is not
acceptable. The selected patch must be pinned consistently; changing it requires
all required checks and an updated decision record.

### ADR-003 — Add an isolated v2 model; do not transform legacy state in place

**Status:** Approved.

Add v2 PostgreSQL tables, constraints, indexes, and object prefixes. Do not
rename or destructively mutate legacy Apps/Bundles/Entrypoints/OperationLogs or
legacy object keys. Migrations are expand-only through the cutover rollback
window. V2 APIs live only under `/api/v2`; API v1 code is not used as a facade
for new semantics.

The greenfield-versus-migration decision remains external. If migration is
required, a later read-only mapper and idempotent importer write v2 records
through documented import interfaces. If greenfield is approved, no generic
migration framework is built.

### ADR-004 — Package one artifact with four separate command modes

**Status:** Approved.

The service image exposes explicit `control`, `content`, `worker`, and `migrate`
commands. There is no mode that boots all privileges in one production process.

| Command   | Responsibilities                                                                                                                            | Allowed dependencies                                                                                                                                                                                                   |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `control` | Portal, API v2, OIDC callbacks, server sessions, authorization, metadata, direct-upload streaming, audit, idempotency, publication requests | Application/session PostgreSQL role including atomic desired-routing/audit/outbox write and acknowledgement-status read; quarantine upload write; preview signing-key reference; no release/routing object-store write |
| `content` | Resolve published/preview host, validate projection/capability, serve immutable content with sealed headers, cache last-known-good routing  | Read-only routing/release storage; preview and routing verification public-key sets; no PostgreSQL, OIDC, quarantine, object write, or private key                                                                     |
| `worker`  | Claim jobs, validate/scan/hash, build deterministic downloads/manifests, finalize releases, apply publication outbox, clean quarantine      | Worker PostgreSQL role; quarantine read/delete; release read/verify/create-only write; routing generation/current read, conditional write and read-back; routing signing-key reference; no preview/session private key |
| `migrate` | Apply additive migrations once under a PostgreSQL advisory lock                                                                             | Short-lived migration role only; no object storage                                                                                                                                                                     |

Each command has a distinct configuration schema, startup validation,
liveness/readiness behavior, and least-privilege identity. Local development
uses the same modes through Compose.

### ADR-005 — Use server-side Authorization Code with PKCE sessions

**Status:** Logical contract approved; production Okta values blocked.

The control plane is a backend-for-frontend. It performs OIDC Authorization Code
with PKCE and validates discovery/JWKS TLS, issuer, audience, signature, code
flow, state, nonce, and time claims. Tokens remain server-side. A PostgreSQL
session contains only required encrypted/token metadata and normalized
authorization claims; logs/audits never contain token values.

The browser receives a random opaque `__Host-staticdeploy-session` cookie with
`Secure`, `HttpOnly`, `Path=/`, no `Domain`, and approved `SameSite` behavior.
Idle and absolute expiration, logout, server-side revocation, signing/encryption
key rotation, and session fixation prevention are required. State-changing
same-origin requests require CSRF protection in addition to SameSite cookies.
The portal bundle does not read or store access, ID, refresh, or service tokens.

Okta group claims map to administrator, owner, publisher, and viewer roles
through configured stable group identifiers. Unknown groups grant nothing. Exact
issuer, client, redirect/logout URIs, group claim, test users, mappings, and
key/secret delivery are production provisioning gates.

### ADR-006 — Isolate portal, published applications, and previews by origin

**Status:** Logical topology approved; exact DNS/TLS values blocked.

Use:

- one trusted portal/control origin;
- one stable per-application published origin under a wildcard content domain;
  and
- one per-release preview origin under a separate wildcard preview domain.

The host contains an opaque routing identifier, not an unrestricted storage key.
A shared published origin is rejected because applications could share browser
storage. Portal cookies are host-only and never sent to either content domain.
Wrong-host requests fail closed.

Preview access uses a short-lived, release-scoped signed capability created by
control. The preview origin exchanges it for a host-only `Secure`, `HttpOnly`,
short-lived preview cookie and redirects to remove capability material from the
URL. Content verifies with a public key and receives no OIDC token, portal
session, database access, or signing key. Preview frames are restricted to the
trusted portal and omit `allow-same-origin` by default.

Published exposure remains disabled or loopback/private-only until the owner
decides and provisions the internal access boundary, DNS, certificates, and
trusted proxy chain. This design does not authorize public applications.

### ADR-007 — Quarantine first and finalize write-once immutable releases

**Status:** Approved; production storage capabilities blocked.

Object layout:

```text
v2/quarantine/{upload-id}/files/{safe-relative-path}
v2/quarantine/{upload-id}/original.zip
v2/rejected/{upload-id}/scan-report.json
v2/releases/{application-id}/{release-id}/source/{safe-relative-path}
v2/releases/{application-id}/{release-id}/original.zip
v2/releases/{application-id}/{release-id}/source-download.zip
v2/releases/{application-id}/{release-id}/content/{safe-relative-path}
v2/releases/{application-id}/{release-id}/manifest.json
v2/routing/{routing-id}/generations/{generation}.json
v2/routing/{routing-id}/current.json
```

Direct upload is initially streamed through control into quarantine; presigned
browser upload and its CORS surface are deferred until measured need. Accepted
paths are safe relative UTF-8 POSIX paths. Reject absolute paths, dot segments,
NULs, backslash/separator ambiguity, empty segments, invalid UTF-8,
Unicode-normalization collisions, and case-fold collisions. Preserve accepted
spelling and file bytes exactly.

The worker hashes and validates quarantine content, writes all release objects
with create-only/idempotent conditions, verifies their SHA-256 digests, then
inserts/finalizes immutable release metadata. READY release rows and release
objects cannot change. A failed job cannot expose a partial release.
Deletion/retention is a separately approved operation after the required
rollback/retention period, never an overwrite.

For direct uploads, `source-download.zip` uses bytewise sorted normalized paths;
fixed timestamps, ownership, permissions, compression settings, and metadata;
and a manifest entry containing path, size, MIME, and SHA-256. ZIP uploads
preserve `original.zip` byte-for-byte.

Supported production S3-compatible stores must pass capability tests for
create-only writes, conditional routing updates, read-after-write behavior,
encryption, versioning/retention policy, separate credentials, and
reconciliation. Endpoint, region, path style, explicit credentials, and
default/workload provider chains are configurable; no provider-specific identity
is mandatory.

### ADR-008 — Use PostgreSQL jobs, idempotency, and leases

**Status:** Approved.

PostgreSQL supplies the queue. A job is claimed using a transactional lease with
owner, expiry, attempt, next-attempt time, bounded retry count, timeout, and
terminal reason. Workers renew leases while making progress. Expired leases are
reclaimable. Completion, default selection, bindings, publish, unpublish,
restore, and worker finalization use scoped idempotency records so identical
retries return/observe the same result and conflicting reuse fails.

No Kafka, RabbitMQ, or generic workflow engine is introduced. Quarantine
expiration and rejected-upload cleanup are scheduled jobs using the same bounded
lease mechanism.

### ADR-009 — Publish through a transactional outbox and object-store routing projection

**Status:** Approved. This resolves the roadmap's database-free content-plane
requirement.

PostgreSQL and S3 cannot form one atomic transaction. Publication therefore
distinguishes **desired database state** from **acknowledged serving state**:

1. In one PostgreSQL transaction, control locks the application, validates a
   READY release and authorization/idempotency key, increments a per-application
   routing generation, updates `desired_current_release_id` (or null for
   unpublish), appends a `*_REQUESTED` audit event, and inserts one outbox row
   containing generation, routing ID, release ID/null, manifest digest,
   operation, and idempotency identity.
2. Worker claims the outbox row, re-verifies release immutability and manifest
   digest, writes immutable `generations/{generation}.json`, then conditionally
   replaces `current.json` only when the previous generation/ETag matches.
3. Worker reads back and verifies the pointer. In a second PostgreSQL
   transaction it confirms that generation is still desired, marks the outbox
   row applied with projection digest/time, records
   `served_current_release_id`/served generation, assigns `published_at` and a
   collision-safe label on the release's first acknowledged publish, and appends
   the final `PUBLISHED`, `RESTORED`, or `UNPUBLISHED` audit event. If that
   transaction is interrupted, reconciliation observes the already-projected
   generation and completes the same idempotent acknowledgement.
4. The API returns final success only after the matching generation is
   acknowledged. While waiting it returns a durable pending operation
   representation; an idempotent retry observes the same operation. A timeout
   does not claim publication succeeded, and requested events are not presented
   as completed publication events.
5. Content reads `current.json`, validates the generation document and manifest
   digest, then serves only immutable release objects. It caches the last valid
   projection with a bounded refresh policy. It never queries PostgreSQL.

Out-of-order workers cannot overwrite a newer generation. Duplicate application
is harmless. Unpublish projects a signed/versioned tombstone and content returns
the configured unpublished response only after acknowledgement. Restore projects
a retained immutable release without changing its version label. Until a new
generation is projected, content continues serving the last-known-good
generation, preserving availability during control-plane or PostgreSQL failure.

A reconciler compares desired/applied/served generations, outbox state, pointer
ETags, generation documents, release manifests, and digests. It may retry a
projection or report drift; it never edits immutable release content silently.
Projection lag, retry, and permanent failure are operational signals, but
production export remains gated by ADR-012.

### ADR-010 — Implement an additive API v2 and schema

**Status:** Approved.

Minimum API:

```text
POST   /api/v2/applications
GET    /api/v2/applications
GET    /api/v2/applications/{id}
POST   /api/v2/applications/{id}/archive
GET    /api/v2/applications/{id}/bindings
PUT    /api/v2/applications/{id}/bindings
GET    /api/v2/audit-events
POST   /api/v2/applications/{id}/releases
POST   /api/v2/releases/{releaseId}/complete-upload
POST   /api/v2/releases/{releaseId}/default-document
GET    /api/v2/applications/{id}/releases
GET    /api/v2/releases/{releaseId}
GET    /api/v2/releases/{releaseId}/download
POST   /api/v2/releases/{releaseId}/publish
POST   /api/v2/applications/{id}/unpublish
POST   /api/v2/applications/{id}/restore
GET    /api/v2/operations/{operationId}
```

The operation endpoint exposes durable publication/projection state without
leaking storage details. API schemas are versioned OpenAPI contracts with
bounded pagination, a stable error envelope, UTC RFC 3339 timestamps, opaque
IDs, and explicit idempotency headers on side-effecting operations. Binding
replacement is one transaction. Audit filters are bounded by application, actor,
action, and UTC range.

Additive v2 data includes:

- `v2_applications` — description, tags, owner metadata, internal visibility,
  archive state, routing ID, desired/served current release and generation;
- `v2_releases` — opaque ID, application, state, default path, manifest digest,
  immutable-finalized time, first `published_at`, collision-safe version label;
- `v2_upload_files` — declaration and observed path/size/digest state;
- `v2_release_jobs` — lease/retry/terminal fields;
- `v2_bindings` — group-to-role bindings;
- `v2_sessions` — opaque session identity, encrypted server-side token material
  as required, claims/version, idle/absolute expiry/revocation;
- `v2_idempotency` — actor/scope/key/request digest/result identity/expiry;
- `v2_audit_events` — immutable actor/action/application/release/UTC/safe
  metadata;
- `v2_publication_outbox` — desired generation/pointer payload, attempts,
  acknowledgement, projection digest/error.

Database constraints enforce allowed states, opaque foreign keys,
per-application unique version labels, monotonically increasing generation, one
idempotency result, and immutability after READY. Audit/query/job indexes are
tested with representative plans.

### ADR-011 — Deliver Docker Compose completely before Helm parity

**Status:** Approved.

Compose is the first deployment contract and default local validation path. It
runs PostgreSQL, an S3-compatible local object store, control, content, worker,
and one-shot migrate with persistent volumes, distinct credentials, health
checks, non-root users, read-only roots, dropped capabilities,
no-new-privileges, and explicit writable temporary paths. It documents start,
upgrade, verify, rollback, restart, backup/restore, and teardown on a local
machine or one Docker host.

After Compose passes, Helm expresses the same images, commands, configuration
names, migrations, storage layout, and smoke suite. Helm adds distinct service
accounts, configurable ingress, security contexts, resources, probes, disruption
controls, scheduling, topology, and NetworkPolicies. Provider annotations are
optional values. No ArgoCD or other deployment controller is introduced.

Production publication/deployment is performed only by GitHub Actions with
protected environments where provisioned, target-appropriate authentication, and
pinned digests. A conformant disposable cluster and clean Docker host are test
targets; no cloud provider is mandatory.

### ADR-012 — Instrument locally but keep telemetry disabled by default

**Status:** Approved; production Eyes enablement blocked.

Implement health endpoints, request IDs, W3C trace context, bounded in-process
operational instruments, and structured redacted logs. Cover request
rate/error/duration, dependency failures, job depth/age, validation outcomes,
publish/restore/projection, static serving, PostgreSQL pool, object-store
operations, and OIDC failures. Use route templates and bounded operation/result
categories; never label by user, application/release ID, raw URL/path, request
ID, trace ID, email, group, or query string.

Exporters are absent or disabled by default. Queues, sampling, retries,
memory/disk use, and backoff are bounded; telemetry outage never blocks serving
or publication indefinitely. Redaction occurs before output/export and excludes
tokens, cookies, authorization, credentials, bodies, form values, personal data,
and uploaded filenames/paths where they may be sensitive.

Do not configure application OTLP, Faro, Matomo, Eyes URLs/credentials/site IDs,
dashboards, alerts, or production collection until the Eyes product onboarding
handoff provides product/environment-scoped values and every applicable gate is
open. Browser analytics/business events are not required for R15 and are not
added speculatively. Once provisioned, resource attributes include stable
`service.name`, `service.namespace`, `service.version`,
`deployment.environment.name`, and `y30k.product`, and the service must still
pass Eyes-unavailable tests.

### ADR-013 — Roll out by immutable digest with explicit rollback checkpoints

**Status:** Approved; production execution blocked.

The release workflow accepts an approved tag or explicit dispatch,
verifies/reruns required checks for the exact commit, builds/smokes both
architectures, creates SBOM/provenance, signs, and publishes only to `ghcr.io`.
PRs never publish. Deployment selects Compose or Helm explicitly and records
target, actor, source commit, image/chart digest, schema compatibility, prior
verified digest, and smoke result.

Rollout order is:

1. M1 cleanup and M2 non-publishing artifacts;
2. local Compose foundation with v2 disabled externally;
3. additive migration, then control/worker/content in disposable environments;
4. direct-file and ZIP feature gates;
5. Compose upgrade/rollback/recovery proof;
6. Helm parity and chart publication;
7. production-like R1-R16 validation;
8. approved pilot and greenfield/migration rehearsal;
9. GitHub Actions cutover with route/data checkpoint;
10. legacy retirement after the rollback window.

Rollback redeploys a previously verified digest, checks schema compatibility,
runs the same API/content smoke suite, and restores the prior routing/DNS
checkpoint where required. Expand-only schema and immutable release data remain
compatible during the window. A failed migration, projection, smoke,
reconciliation, or security gate stops promotion automatically. Destructive
contract/schema cleanup is a post-retirement change, not part of the initial
cutover.

## V2 state and data flow

### Release state

```text
PENDING_UPLOAD -> UPLOADED -> PROCESSING
PROCESSING -> AWAITING_DEFAULT_DOCUMENT -> READY
PROCESSING -> READY  (default already valid)
PENDING_UPLOAD | UPLOADED | PROCESSING | AWAITING_DEFAULT_DOCUMENT -> FAILED
```

READY is final for content, manifest, source, default document, and digests.
Publication is independent state held on the application pointer/outbox. Drafts
have no version label. First acknowledged publication stores authoritative UTC
`published_at` and `YYYY.MM.DD-HH.mm.ss`; same-second collisions append the
smallest database-enforced `-2`, `-3`, and so on. Restore and republish retain
the label and append new audit events.

### Direct-file flow

```text
control: authorize + create app/release/upload declarations
  -> stream declared files to quarantine
  -> idempotently complete upload
worker: lease + verify declaration/path/MIME/limits + hash
  -> write source/content/download/manifest create-only
  -> verify objects + finalize release
control: select manifest HTML/HTM default -> READY
content: verify short-lived preview capability -> serve immutable release
control: publish desired generation + audit + outbox
worker: apply/ack routing projection
content: refresh verified generation -> serve; API operation succeeds
```

### ZIP flow

The same pipeline stores `original.zip`, then extracts within CPU, memory, disk,
file-count, path-depth, expanded-size, and elapsed-time bounds. It rejects
traversal, absolute paths, links/devices, encryption, malformed input,
duplicate/case/Unicode collisions, and bombs. MIME and malware policy run before
finalization. Candidate HTML/HTM documents are presented only after safe
extraction. Static inspection findings are advisory; origins, sessions/cookies,
storage permissions, CSP, headers, and sandboxing are enforcement.

## Authorization model

The exact matrix is versioned with the API tests. Minimum behavior:

- **administrator:** platform/application administration, binding changes,
  archive, all release operations;
- **owner:** application metadata/bindings within delegated limits, release
  creation, publish/restore/unpublish, audit/read;
- **publisher:** create/process/preview/publish/restore/unpublish releases, no
  privilege escalation;
- **viewer:** list/read/history/authorized preview/download/audit, no writes;
- **denied/unknown:** no application data or write side effect.

Every write authorizes before idempotency side effects, and binding replacement
cannot partially apply or let a user grant beyond authority. Audit events
capture actor, effective role/source, action, object, result, and UTC time using
safe bounded metadata.

## Content security defaults

Published and preview responses derive MIME from detected/manifested type and
set a sealed default policy: local assets only; no arbitrary fetch/WebSocket,
external scripts, frames, forms, object/embed, or portal framing. Apply CSP,
`X-Content-Type-Options: nosniff`, Referrer-Policy, Permissions-Policy,
Cross-Origin-Resource-Policy, frame restrictions, safe Content-Disposition, and
state-appropriate Cache-Control to documents, assets, and errors. Runtime
configuration injection is disabled and cannot carry secrets.

An approved-host exception system is not built unless pilot evidence requires
it. If later approved, entries are exact scheme/host/port, bounded, expiring,
reversible, authorized, and audited; they cannot weaken cookie, origin, frame,
form, object, or storage isolation.

## Reliability and recovery

- Control transactions are short and use database constraints for
  generation/version/idempotency races.
- Worker side effects are retry-safe and verified by digest before state
  transitions.
- Content caches only a cryptographically/digest-verified last-known-good
  projection and immutable manifest; cache expiry causes safe stale serving or
  fail-closed behavior according to the tested operation, never a database
  fallback.
- PostgreSQL backup/restore is provider-neutral. Reconciliation reports missing
  records, missing objects, pointer drift, and digest mismatch; destructive
  repair requires explicit operator action.
- Published content remains available during control/PostgreSQL outages while
  object storage and the last valid projection are available.
- Quarantine and idempotency retention are configured and bounded; release
  retention is externally approved before deletion exists.

## External provisioning gates

| Gate             | Required input/owner                                                                                                                                                                              | Blocks                                            |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| GitHub/GHCR      | Canonical `main` migration, required checks, environments, permissions, GHCR visibility, signing identity, deployment credentials/approvals                                                       | Publication and M6 production delivery            |
| Okta             | Issuer/client, redirects/logout, group claim/IDs, admin mapping, test users, secret/key rotation                                                                                                  | Production-like M3/M4 identity acceptance         |
| DNS/TLS/exposure | Portal/wildcard hosts, certificates, registrable-site/browser matrix, trusted proxy chain, query-log redaction, cache bypass, viewer policy, route-cutover access                                 | External preview/publishing and M7                |
| PostgreSQL       | Production service, roles, migration identity, backup destination, backups, restore owner, RPO/RTO                                                                                                | M3/M6/M7 production acceptance                    |
| Object storage   | Endpoint/bucket/prefix, capability pass, component policies, version/audit rollback detection, encryption/versioning/retention/backups, explicit/workload provider-chain credentials              | M3/M6/M7 production acceptance                    |
| Content security | Quotas/retention, ZIP limits, malware engine/failure posture, exception authority                                                                                                                 | M5 production acceptance                          |
| Deployment       | Kubernetes/Docker target, ingress, identities, network/PV support, purpose-separated preview/routing key delivery/storage/rotation/revocation/emergency replacement, approvals, rollback operator | M6/M7 production acceptance                       |
| Eyes             | Onboarding fields, product/environment routes/credentials, volume/sensitivity, dashboards/alerts/runbooks, open ingestion gates                                                                   | Production telemetry and M6 operations acceptance |
| Product/cutover  | Pilot users/fixtures, greenfield or inventory/mapping, route checkpoint, rollback window, waiver/support/destruction authority                                                                    | M7                                                |

## Alternatives rejected

- **Keep one privileged process:** violates content-plane isolation and
  independent permissions.
- **Let content query PostgreSQL/control:** violates database-free serving and
  control-plane-failure availability.
- **Treat a database pointer and S3 write as atomic:** impossible without a
  recovery protocol; use outbox/projection acknowledgement.
- **Mutable release keys or copy-on-restore:** breaks digest integrity and safe
  rollback; use immutable releases and pointer projection.
- **Browser bearer tokens/localStorage:** conflicts with server-session and
  hostile-content boundaries.
- **Presigned upload first:** adds CORS and browser credential complexity before
  measured need.
- **Helm before Compose:** duplicates an unproven contract; Compose is the
  required default local profile.
- **Message broker:** unnecessary before PostgreSQL lease load demonstrates a
  need.
- **Provider-specific storage/deployment identity:** violates portability.
- **Telemetry shortcuts/shared credentials:** violate Eyes product-scoped
  onboarding and current closed ingestion gates.

## Design acceptance

Implementation may begin only in the order governed by the milestone lifecycle.
A story is complete when its API/schema/security behavior, failure handling, and
rollback are covered by the mapped executable gates—not when the happy path
merely runs. Production blockers remain explicit configuration/provisioning
gates and must not be replaced by invented endpoints, credentials, hostnames,
identities, or approval assumptions.
