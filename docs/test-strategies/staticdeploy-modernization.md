# StaticDeploy Modernization Test Strategy

## Purpose and gate contract

This strategy maps R1-R16 and Milestones 2-7 from
`docs/2026.08.17-Project-Plan.md` to repeatable evidence. It is governed by
`docs/ai-dlc/modernization-milestones-1-7.md` and tests the contracts in
`docs/technical-designs/staticdeploy-modernization.md`.

The commands below are the required stable gate interface. They are
implementation targets: each owning story adds the named script/harness before
claiming its gate. A missing command, skipped required case, unretained report,
or command run against the wrong commit/artifact is a gate failure. Scripts must
support CI, fail nonzero, print the tested commit/digests/profile, retain
machine-readable reports, and never require production credentials for pull
requests.

`<pm>` means the exact package-manager binary/version selected and pinned by
ADR-002. Tests must call it through the repository pin rather than a globally
floating install.

## Required gate commands

| Gate ID | Command                                                                 | Required result/evidence                                                                                                     |
| ------- | ----------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| G-M1    | `./scripts/gates/m1-residual.sh`                                        | No residual legacy CI/publication path; corrected repository evidence; clean required Actions checks                         |
| G-M2    | `./scripts/gates/m2-toolchain.sh`                                       | Frozen install, format/lint/type/unit/characterization/contracts/integration, scan policy, image/security/architecture tests |
| G-M3    | `./scripts/gates/m3-foundation.sh`                                      | V2 schema, sessions/RBAC, storage/jobs, command separation, projection, Compose and initial Helm boundaries                  |
| G-M4    | `./scripts/gates/m4-direct-golden.sh`                                   | Complete direct-file API/worker/content/browser/accessibility/security path                                                  |
| G-M5    | `./scripts/gates/m5-zip-policy.sh`                                      | Hostile ZIP, scanner, MIME, policy/header/sandbox/quota and ZIP golden path                                                  |
| G-M6-C  | `./scripts/gates/m6-compose.sh --images-lock artifacts/images.lock`     | Compose install/upgrade/verify/rollback/restart/recovery/teardown by digest                                                  |
| G-M6-H  | `./scripts/gates/m6-helm.sh --release-lock artifacts/release.lock`      | Helm lint/render/install/upgrade/verify/rollback/disruption/uninstall by digest                                              |
| G-M6-R  | `./scripts/gates/m6-recovery.sh --profile compose` and `--profile helm` | Provider-neutral database restore and object/routing reconciliation                                                          |
| G-M6-O  | `./scripts/gates/m6-operations.sh`                                      | Redaction/cardinality/correlation/outage/resilience/runbook evidence with exporters off by default                           |
| G-M6    | Run G-M6-C, G-M6-H, G-M6-R, and G-M6-O for the same release lock        | Aggregate portable deployment, recovery, and operations evidence; every concrete subgate must pass                           |
| G-M7    | `./scripts/gates/m7-pilot-cutover.sh --evidence-index <path>`           | R1-R16 index, fixture/pilot, greenfield or migration reconciliation, cutover/rollback/retirement gates                       |

The scripts may compose focused tests instead of duplicating logic. Their
checked-in manifest must enumerate each test ID below so CI can detect
omissions.

## Harness inventory and ownership

| Suite                 | Required harness/data                                                                               | Primary level           | First owner    |
| --------------------- | --------------------------------------------------------------------------------------------------- | ----------------------- | -------------- |
| `unit-domain`         | State transitions, paths, labels, authz, idempotency, projection generation, policy rules           | Unit/property           | M3/M4          |
| `contract-v2`         | Versioned OpenAPI validation, error envelope, pagination, UTC timestamps, idempotency               | Contract                | M4             |
| `integration-pg-s3`   | Disposable supported PostgreSQL and MinIO; distinct component credentials                           | Integration/fault       | M2-M4          |
| `oidc-session`        | Mock OIDC provider plus separately provisioned Okta test client                                     | Security/contract       | M3             |
| `worker-faults`       | Concurrent workers, lease expiry, process kill, partial object failure, retry exhaustion            | Integration/reliability | M3/M4          |
| `projection`          | Conditional writes, stale ETag, out-of-order/duplicate rows, read-back failure, reconciliation      | Integration/concurrency | M3             |
| `content-security`    | Two apps/origins, hostile HTML, wrong host, cookie/storage probes, CSP network observer             | Browser/security        | M4/M5          |
| `direct-golden`       | Nested direct files with `app.html`, deterministic download oracle                                  | API/browser             | M4             |
| `zip-hostile`         | Versioned corpus for traversal, links/devices, bombs, collisions, malformed/encrypted/timeout cases | Security/resource       | M5             |
| `zip-golden`          | ZIP with non-`index.html` default and known original digest                                         | API/browser             | M5             |
| `accessibility`       | axe plus documented keyboard/screen-reader protocol                                                 | Automated/manual        | M4             |
| `image-conformance`   | amd64/arm64 boot, user/layers/SBOM, read-only root/capability restrictions                          | Artifact/security       | M2             |
| `profile-conformance` | Same API/content smoke suite against Compose and Helm                                               | Deployment/system       | M6             |
| `delivery-security`   | Untrusted PR, trusted release, signature/attestation, protected deploy, failed promotion/rollback   | CI/CD/security          | M2/M6          |
| `recovery`            | Seeded backup, controlled missing/mismatched DB/object/routing cases                                | Recovery                | M6             |
| `telemetry-safety`    | Captured local logs/signals, token/PII canaries, cardinality budget, unavailable upstream           | Operations/security     | M6             |
| `pilot-corpus`        | Approved direct/ZIP/Campaign Advisor/localization/collision/restore cases                           | User/system             | M7             |
| `migration-reconcile` | Sanitized snapshot, count/digest/URL/download oracle, interruption injection                        | Migration/recovery      | M7 conditional |

## R1-R16 traceability matrix

| Requirement                                  | Executable coverage                                                                      | Required assertions                                                                                                                                                       | Milestone gate                                        |
| -------------------------------------------- | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| **R1 Application directory**                 | `contract-v2 applications`; `direct-golden directory`; role matrix                       | Create/search/get/archive; description/tags/owner groups/internal visibility; bounded pagination; archived-write denial; audit                                            | G-M4, G-M7                                            |
| **R2 Multi-file and ZIP upload**             | `direct-golden upload`; `zip-hostile`; `zip-golden`                                      | Nested paths preserved; no index convention; missing/undeclared/duplicate/unsafe inputs rejected; bounded ZIP extraction                                                  | G-M4, G-M5, G-M7                                      |
| **R3 Immutable releases**                    | `integration-pg-s3 immutable`; `worker-faults finalization`; reconciliation digest cases | READY rows/objects reject mutation; each source/content digest verifies; partial failure cannot expose release                                                            | G-M3, G-M4, G-M6-R                                    |
| **R4 Source download**                       | `direct-golden download-oracle`; `zip-golden original-digest`                            | Direct archive repeats byte-identically and manifest proves path/size/SHA-256; ZIP download equals original bytes                                                         | G-M4, G-M5, G-M7                                      |
| **R5 Default document and isolated preview** | `contract-v2 default`; `content-security preview`; both golden paths                     | Only manifest HTML/HTM accepted; nested non-index works; no portal cookie/token; cross-app storage denied                                                                 | G-M4, G-M5, G-M7                                      |
| **R6 Publish and unpublish**                 | `projection concurrency`; `contract-v2 publication operation`; pointer browser test      | DB desired pointer/audit/outbox atomic; final success only after projection acknowledgement; retries same result; unpublish tombstone; prior generation served on failure | G-M3, G-M4, G-M6                                      |
| **R7 Timestamp versions and restore**        | `unit-domain version-label`; concurrent transaction tests; timezone browser matrix       | UTC first publish; smallest suffix under same-second race; localized display with UTC accessible; restore/republish retain label and add audit                            | G-M4, G-M7                                            |
| **R8 OIDC authentication**                   | `oidc-session mock`; production-like Okta acceptance                                     | Code+PKCE/state/nonce/issuer/audience/signature/expiry; server-only tokens; host-only cookie; logout/idle/absolute expiry/key rotation                                    | G-M3; production exit BLOCKED until Okta test passes  |
| **R9 Group authorization**                   | Generated role-by-operation matrix for every v2 write; binding rollback tests            | Admin/owner/publisher/viewer/denied; no privilege escalation; group changes; auth before side effects; no partial bindings                                                | G-M3, G-M4, G-M7                                      |
| **R10 Audit history**                        | `contract-v2 audit`; query-plan suite; event completeness matrix                         | Required auth/authz/upload/publish/unpublish/restore/archive/binding/policy events; immutable/filterable/paginated; UTC; safe metadata                                    | G-M3, G-M4, G-M5                                      |
| **R11 Static-content isolation**             | `content-security` hostile HTML/network/cookie/storage/wrong-host/header suite           | No portal state or privileged credential; per-app origins; default network denial; no cross-app storage; content role read-only                                           | G-M3, G-M4, G-M5, G-M6                                |
| **R12 Portable deployment**                  | `profile-conformance`; G-M6-C; G-M6-H                                                    | Compose and Helm install/upgrade/verify/rollback/restart or disruption/teardown; same images/config/migrations/storage/smokes                                             | G-M6-C, G-M6-H, G-M7                                  |
| **R13 Secure GitHub artifacts**              | `image-conformance`; `delivery-security release`; signature verification                 | Non-root amd64/arm64; read-only root; SBOM/provenance/signature; ghcr.io only; GitHub Packages only if approved; exact-commit check                                       | G-M2, G-M6, G-M7                                      |
| **R14 Recovery**                             | G-M6-R with discrepancy injection; routing reconciliation                                | PostgreSQL restore; missing record/object/digest/pointer detected; safe orphan report; immutable data never silently edited                                               | G-M6-R, G-M7                                          |
| **R15 Operations**                           | G-M6-O; `telemetry-safety`; runbook exercises                                            | Health/signals bounded; logs redacted; request/trace correlation; Eyes outage non-blocking; dashboards/alerts only after onboarding                                       | G-M6-O; production exit BLOCKED until Eyes acceptance |
| **R16 Actions-only delivery**                | G-M1; `delivery-security`; repository/settings search                                    | Required checks/release/deploy/promote/verify/rollback only Actions; untrusted PR cannot publish; retired integrations/credentials/webhooks absent                        | G-M1, G-M2, G-M6, G-M7                                |

## Focused test catalog

### Schema, state, and API

- `SCH-01` — apply all migrations to an empty supported PostgreSQL database.
- `SCH-02` — upgrade a captured legacy schema; legacy tables/data checksums
  remain unchanged.
- `SCH-03` — concurrent same-second first publications produce base, `-2`, `-3`
  labels with one winner each.
- `SCH-04` — READY fields and immutable audit records reject update/delete
  through application and database guard paths.
- `SCH-05` — bounded audit/application queries use expected indexes on
  representative data.
- `API-01` — generated requests/responses conform to committed OpenAPI v2.
- `API-02` — pagination/error/UTC/idempotency behavior is stable and conflict
  reuse is rejected.
- `API-03` — every write endpoint participates in the generated R9 role matrix.

### Sessions and trust boundaries

- `AUTH-01` — successful mock Code+PKCE flow sets only an opaque `__Host-`
  session cookie.
- `AUTH-02` — wrong issuer/audience/state/nonce/signature, expired code/session,
  callback replay, and rotated keys fail closed.
- `AUTH-03` — logout/revocation/idle/absolute expiry invalidate server and
  browser state; session fixation fails.
- `AUTH-04` — CSRF and wrong-origin writes fail without audit/domain side
  effects.
- `AUTH-05` — portal output, browser storage, logs, and captured telemetry
  contain no OIDC token.
- `AUTH-06` — configured Okta test tenant repeats AUTH-01/02/03 before
  production-like gate; unavailable provisioning is BLOCKED, not skipped.

### Storage, worker, and publication projection

- `STO-01` — control/worker/content credentials pass allowed operations and fail
  every forbidden prefix/action.
- `STO-02` — finalized release objects and metadata reject overwrite; digest
  verification catches controlled corruption.
- `STO-03` — direct path property tests reject traversal, ambiguity,
  normalization/case collisions and preserve accepted bytes/spelling.
- `JOB-01` — two workers cannot own one live lease; expiry permits safe reclaim.
- `JOB-02` — kill at each side-effect boundary; retry creates one release/result
  and no exposed partial prefix.
- `JOB-03` — bounded retry/timeout/terminal reason/cleanup behavior survives
  restart.
- `PROJ-01` — publish transaction atomically writes desired pointer, audit,
  generation, and outbox or none.
- `PROJ-02` — duplicate/out-of-order workers and stale ETags cannot replace a
  newer `current.json`.
- `PROJ-03` — read-back/digest failure leaves operation pending/failed and
  content on last-known-good generation.
- `PROJ-04` — acknowledged publish/restore/unpublish switches serving exactly
  once; idempotent API retry observes it.
- `PROJ-05` — reconciliation detects desired/applied/served/object drift and
  retries/reports without editing release content.
- `PROJ-06` — content serves cached verified projection during
  control/PostgreSQL outage and never opens a database connection.

### Upload, archive, and content security

- `DIR-01` — deterministic ZIP generation repeats the same digest across
  processes/architectures and matches all source bytes/manifest entries.
- `ZIP-01` — hostile corpus covers traversal, absolute, symlink, device,
  encryption, malformed, duplicate, case/Unicode collision, bomb,
  depth/count/size, CPU/disk/memory/time limits.
- `ZIP-02` — scanner clean/infected/unavailable/timeout/stale-signature outcomes
  match the approved posture.
- `POL-01` — remote scripts/assets, fetch/WebSocket, forms, frames, objects and
  malformed markup produce escaped advisory findings.
- `POL-02` — CSP/security headers apply to document, asset, error, published,
  and preview responses; browser observer records blocked egress.
- `POL-03` — sandboxed preview cannot use same-origin storage, navigate/control
  portal, steal opener state, or access another app.
- `POL-04` — quotas/rate limits enforce before full resource consumption and
  recover at defined reset/retry boundaries.
- `POL-05` — exception tests run only if an approved exception feature exists;
  otherwise an approval record marks the branch not applicable.

### UI and accessibility

- `UI-01` — direct golden path uses nested `app.html`, validates, previews,
  publishes, downloads/verifies, restores, and unpublishes.
- `UI-02` — ZIP golden path preserves original digest and uses a differently
  named default.
- `UI-03` — two browser timezone runs show localized `Published at` while
  exposing identical UTC.
- `UI-04` — denied/error/retry/worker-delay/projection-delay states remain
  idempotent and understandable.
- `A11Y-01` — automated axe checks have no serious/critical primary-flow
  violations.
- `A11Y-02` — documented keyboard and screen-reader review completes
  upload/default/publish/restore without pointer-only cues or traps.

### Artifacts, deployment, recovery, and operations

- `IMG-01` — both architectures boot from the same source revision; health/API
  smoke passes.
- `IMG-02` — image default user is non-root; read-only root, dropped
  capabilities, no-new-privileges, and only explicit tmpfs/writable mounts pass.
- `IMG-03` — runtime layers exclude build-only tooling/source; SBOM and
  vulnerability policy pass.
- `REL-01` — PR/fork/tag spoof cannot publish; approved release verifies
  exact-commit checks, signature, provenance, SBOM, architectures, and
  destination digests.
- `DEP-01` — Compose lifecycle passes twice from clean hosts with data/content
  retained across upgrade/rollback/restart.
- `DEP-02` — Helm lifecycle passes on a conformant disposable cluster, including
  disruption and optional-policy behavior.
- `DEP-03` — protected workflow rejects approval denial, mutable/unknown digest,
  incompatible migration, failed smoke, and failed promotion.
- `DEP-04` — rollback records and redeploys a previously verified digest and
  reruns identical smoke checks.
- `REC-01` — restore seeded PostgreSQL backup into clean service, then verify
  release counts/pointers/audits.
- `REC-02` — inject missing DB row/object, orphan, digest mismatch, and routing
  drift; report/reconcile per policy without silent mutation.
- `OPS-01` — controlled load/dependency/control/worker/telemetry outages remain
  within configured bounds and preserve published content where required.
- `OBS-01` — label dictionary/cardinality budget permits only bounded
  route/operation/status/release categories.
- `OBS-02` — canary cookies/tokens/query strings/email/user IDs/raw upload paths
  do not appear in logs/signals.
- `OBS-03` — W3C/request correlation works without IDs as labels; bounded queues
  drop safely when upstream is unavailable.
- `OBS-04` — exporters/browser collection are off in default/local/PR
  configuration; enablement requires provisioned product/environment
  configuration.

## Milestone executable gates

### M1 residual pre-gate

`G-M1` runs first. It searches tracked files for the residual patterns named in
the lifecycle, validates retirement evidence, runs the two required PR workflows
on a clean branch, and attaches a settings-level review. Any approved
compatibility exception must name its consumer and test; otherwise a match
fails.

### Milestone 2

`G-M2` must execute, in order:

1. exact Node/package-manager pin checks and two clean frozen installs with no
   lockfile diff;
2. format, lint, standalone typecheck, unit, characterization, contract,
   PostgreSQL, and MinIO suites;
3. dependency/license/source/secret/container scans through a severity evaluator
   and expiring allowlist;
4. IMG-01/02/03 for amd64 and arm64; and
5. REL-01 in non-publishing mode, plus an approved registry test only after
   external provisioning.

Production GHCR/signing evidence may be BLOCKED-EXTERNAL while the local M2
artifact contract passes; M6 publication cannot pass without it.

### Milestone 3

`G-M3` runs SCH-01 through SCH-05, AUTH-01 through AUTH-05, STO-01/02,
JOB-01/02/03, PROJ-01 through PROJ-06, command startup/configuration tests,
Compose security inspection, and initial Helm render/install isolation. AUTH-06
and real DNS/storage policy tests are mandatory for production-like exit but
explicitly BLOCKED-EXTERNAL until provisioned.

### Milestone 4

`G-M4` runs API-01/02/03, STO-03, DIR-01, UI-01/03/04, the complete role matrix,
audit query tests, hostile two-origin content checks, A11Y-01/02, and source
archive verification. Manual accessibility evidence records reviewer,
environment, assistive technology, result, and defects; it cannot be replaced by
axe alone.

### Milestone 5

`G-M5` runs ZIP-01, the approved ZIP-02 matrix, POL-01 through POL-04, UI-02,
and the combined hostile-content browser suite. POL-05 is either executed or
linked to an approved “not required” decision. The scanner production gate
remains blocked until its engine/failure policy is approved; a mock scanner is
necessary but not sufficient for production acceptance.

### Milestone 6

M6 requires all four commands:

- G-M6-C proves Compose first on clean hosts.
- G-M6-H then proves Helm parity on a disposable conformant cluster.
- G-M6-R runs REC-01/02 against both profiles.
- G-M6-O runs OPS-01 and OBS-01 through OBS-04 plus every runbook exercise.

REL-01 and DEP-03/04 execute through GitHub Actions with immutable digests.
Production deployment and Eyes acceptance remain BLOCKED-EXTERNAL until
provisioned. An Eyes-unavailable test is required both before and after
enablement.

### Milestone 7

`G-M7` validates the evidence index schema and all R1-R16 links, then runs the
approved pilot corpus and resource inventory. It requires an approved greenfield
record or executes the conditional migration suite:

- two clean dry runs;
- interruption/resume and idempotency;
- counts/digests/URLs/selected source downloads;
- final consistency mechanism;
- production smoke and timed routing/platform rollback.

Retirement checks probe old routes/permissions/integrations only after the
rollback window closes. Missing pilot users, Campaign Advisor rights, production
inventory, DNS/cutover access, acceptance authority, or destruction approval is
BLOCKED-EXTERNAL and prevents M7 exit.

## CI execution and retention

- Pull requests: G-M1/G-M2 affected checks, unit/contract/integration/security
  subsets, image build without push; no protected secrets.
- Merge/default branch: full affected gate plus nightly hostile/resource
  matrices where runtime is too long for PRs.
- Approved release: exact-commit G-M2, all stable product gates, REL-01,
  immutable artifacts and attestations.
- Deployment candidate: profile conformance, migration preflight, smoke, release
  annotation; failed verification stops promotion.
- Scheduled recovery/security: hostile corpus, restore/reconciliation,
  dependency updates, signature and rollback rehearsals.

Retain JUnit (or equivalent), OpenAPI report, coverage,
scan/SBOM/provenance/signature records, image/chart digests, profile logs,
screenshots/traces for browser failures, reconciliation reports, manual
accessibility/pilot records, and external approval references according to
repository policy. Never retain secrets, real cookies/tokens, malware bytes
beyond the approved scanner fixture policy, or sensitive production samples.

## Exit reporting

Each gate emits a machine-readable summary containing commit, runtime, profile,
artifact digests, tests executed/skipped, pass/fail/BLOCKED-EXTERNAL status,
report locations, and residual risks. The milestone evidence index may report a
local implementation gate as passed while naming external blocks, but R1-R16
production acceptance and M7 completion cannot pass until their required
external evidence exists.
