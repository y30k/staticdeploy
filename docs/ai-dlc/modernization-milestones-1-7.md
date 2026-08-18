# StaticDeploy Modernization: Milestones 1-7 Lifecycle and Gates

## Authority and scope

This document governs execution of Milestones 1-7 in
`docs/2026.08.17-Project-Plan.md`. It turns that roadmap into a
dependency-ordered lifecycle without changing its R1-R16 scope or non-goals. The
technical contract is in `docs/technical-designs/staticdeploy-modernization.md`;
executable evidence is defined in
`docs/test-strategies/staticdeploy-modernization.md`; PR-sized work is in
`docs/prd-work-items/staticdeploy-modernization.md`.

The approved repository-safe defaults in those documents may be implemented
locally. They do **not** authorize production publication or deployment,
external package/registry changes, Okta configuration, DNS/TLS changes,
production PostgreSQL or object-storage access, a pilot/cutover, legacy-data
destruction, or Eyes enablement. Those actions remain blocked until the named
owner provisions and approves them.

## Lifecycle rules

1. **Begin delivery with M2-01.** M1-R1 is a closed prerequisite: PR #20, its
   two successful required checks, the retired-path searches, and
   `docs/ci-retirement-evidence.md` are its immutable evidence. It is not a
   future script or open blocker.
2. **Gates are evidence, not status labels.** A milestone exits only when its
   evidence index links immutable CI artifacts, test output, review decisions,
   and any required external approval. A merged PR alone is insufficient.
3. **Do not cross an unresolved contract.** A dependent story stays blocked when
   its ADR, capability test, or external value is unresolved. Local
   mock/disposable work may proceed only where this document explicitly allows
   it.
4. **One concern per PR.** Toolchain, schema, storage, identity, serving, UI,
   deployment, and telemetry changes are independently reviewable. Additive
   schema changes land before code that depends on them.
5. **Preserve rollback.** V2 tables and object prefixes are additive; release
   objects are immutable; deployments use immutable digests; legacy data is not
   destructively transformed during the rollback window.
6. **Compose first, then Helm.** The complete local/single-host contract must
   pass in Docker Compose before Helm is accepted as equivalent.
7. **GitHub Actions only.** No other CI/CD controller may build, publish,
   deploy, promote, verify, or roll back StaticDeploy.
8. **Stop on failed verification.** Publication, promotion, cutover, and
   retirement do not continue after a failed required check, projection
   acknowledgement, smoke test, reconciliation, or security gate.
9. **Keep product boundaries.** StaticDeploy accepts static browser assets only
   and never creates per-application containers, databases, secrets, or
   orchestrator resources.
10. **Keep telemetry off until provisioned.** Local health and redacted
    structured logs are allowed. Exporters and browser collection remain
    disabled until Eyes onboarding and product/environment-scoped handoff are
    complete.

## Evidence and decision states

Every milestone evidence index uses these states:

- **PASS** — executable gate passed for the exact commit/artifact under review.
- **BLOCKED-EXTERNAL** — implementation is locally complete but a named external
  owner has not provisioned or approved the production dependency.
- **NOT-APPLICABLE** — an approved decision removes the work (for example, no
  migration after greenfield approval); the approval is linked.
- **FAIL** — required evidence failed or is missing. A milestone cannot exit
  with a FAIL.

External evidence must be referenced without credentials, sensitive production
samples, or personal data. Screenshots are supplementary; prefer API output,
signed attestations, immutable workflow artifacts, digests, and dated approvals.

## Gate sequence

```text
M1-R1 residual cleanup
  -> M1 Actions-only foundation gate
  -> M2 supported toolchain and secure local artifacts
  -> M3 trust/data/runtime foundation
  -> M4 direct multi-file vertical slice
  -> M5 ZIP and sealed content policy
  -> M6 portable delivery, recovery, and operations
  -> M7 pilot/cutover/retirement
```

Parallel work is allowed only inside a milestone where the work-item dependency
table permits it. A later milestone may be researched, but its implementation
cannot be called Ready before the prior exit gate passes.

## Milestone 1 — Completed Actions-only foundation

### Entry

The repository has two required pull-request GitHub Actions workflows and no
checked-in CircleCI configuration. PR #20 completed M1-R1 by removing residual
CircleCI website variables, public package metadata, tag-release behavior,
legacy CLI image construction, and active retired-artifact instructions.

### Completed first work: M1-R1

The repository and `docs/ci-retirement-evidence.md` now reflect the approved
compatibility default: legacy public publication is retired, and preservation
would require a separately approved consumer and characterization test.

### Exit gate

- Repository searches for `CIRCLE_`, public `publishConfig`, Docker Hub image
  references, public npm install/release instructions, and master-only release
  controls return no active path.
- Required Actions checks run from a clean pull request and branch protection
  requires the intended checks on the canonical branch.
- Dependency/source/license/secret findings are retained and release-blocking
  severity policy is identified for M2.
- Settings review finds no active non-Actions build/deploy webhook and no usable
  retired publication credential.
- The evidence document states what was checked, when, by whom, and which
  external settings could not be independently observed.

### Rollback boundary

Repository cleanup is revertible. No legacy publisher is re-enabled as rollback;
if cleanup reveals an approved consumer, M1 stops for a compatibility decision.

## Milestone 2 — Supported toolchain and secure artifacts

### Entry

M1 passes; retained behavior has characterization coverage; ADR-002 approves
Node `24.19.0` as the initial exact Node 24 LTS pin.

### Exit gate

- The selected Node LTS patch and package manager are pinned consistently; clean
  frozen installs do not change the lockfile.
- Formatting, lint, standalone typecheck, unit, characterization, API contract,
  PostgreSQL, and MinIO checks pass on a clean checkout.
- Supported dependency and migration-library slices pass; AWS SDK v2 and TSLint
  are absent from retained runtime/tooling.
- One hardened baseline service image is produced; no CLI image is produced. The
  real `control`, `content`, `worker`, and `migrate` command split belongs to M3
  after its schema and component contracts exist.
- `linux/amd64` and `linux/arm64` images run non-root with read-only roots,
  dropped capabilities, explicit writable paths, and passing smoke tests.
- No unaccepted critical vulnerability exists; exception records are owned and
  expire.
- Non-publishing image/SBOM/provenance/signature verification passes locally or
  in CI.
- **Production publication remains BLOCKED-EXTERNAL** until GHCR visibility,
  GitHub permissions/environments, signing identity, and approval policy are
  provisioned. When provisioned, only GitHub Actions may publish approved
  digests to `ghcr.io` and approved packages to GitHub Packages.

### Rollback boundary

Each dependency/tooling slice can revert independently. No v2 data is introduced
in M2. Previously verified baseline checks remain available throughout
migration.

## Milestone 3 — Security, data, and runtime foundation

### Entry

M2 local artifact gates pass. Repository ADRs for compatibility, v2 isolation,
origins, sessions, storage, publication projection, commands, deployment order,
and telemetry are accepted.

### Exit gate

- Additive v2 migrations pass empty-install and legacy-schema upgrade tests
  without changing legacy tables/objects destructively.
- Server-side OIDC sessions pass mock-IdP login/logout, validation, expiry,
  CSRF, and role tests; browser-readable bearer-token storage is absent from v2.
- Distinct `control`, `content`, `worker`, and `migrate` commands boot with
  least-privilege configuration; content has no database, quarantine, OIDC, or
  write credential.
- Quarantine, immutable release prefixes, manifests, job leases, retries,
  idempotency, and cleanup pass PostgreSQL/MinIO fault tests.
- Publication outbox and generation-numbered object-store routing projection
  pass concurrency, retry, acknowledgement, reconciliation, and last-known-good
  serving tests.
- Compose starts all components with separate credentials and security
  restrictions, then the initial Helm chart demonstrates the same boundaries on
  a disposable cluster.
- Threat-model review covers hostile content, paths/archives, OIDC, sessions,
  object storage, preview capabilities, CI identities, and projection failure.
- **Production identity, origins, storage, databases, and exposure remain
  BLOCKED-EXTERNAL** until Okta, DNS/TLS, trusted proxy, PostgreSQL roles, and
  object-store capability/policy provisioning pass their acceptance checks.

### Rollback boundary

Disable v2 routes/workloads and redeploy the prior image. Expand-only migrations
and separate v2 prefixes remain inert; legacy tables and objects remain readable
by the baseline during the cutover window.

## Milestone 4 — Direct multi-file vertical slice

### Entry

M3 trust boundaries, v2 schema, storage, worker, routing projection, and local
deployment profile pass.

### Exit gate

- API v2 contract tests cover application directory, bindings, audit, release
  creation/completion, default selection, download, publish, unpublish, and
  restore.
- The direct-upload worker preserves safe UTF-8 POSIX paths and bytes, rejects
  ambiguous/unsafe inputs, hashes each source and content asset, and finalizes
  one immutable prefix.
- A deterministic source ZIP and manifest reproduce every accepted path, size,
  and SHA-256 digest.
- First publication creates a collision-safe UTC label; republish/restore
  preserve that label; publication APIs report success only after routing
  projection acknowledgement.
- Per-application published origins and per-release preview origins prevent
  portal-cookie, credential, browser-storage, and cross-application access.
- The portal golden path completes create → upload → select non-`index.html`
  default → validate → preview → publish → download → restore → unpublish.
- Role/binding/audit tests pass, publication time is localized with UTC
  available, and the primary workflow passes WCAG 2.2 AA automated plus manual
  keyboard review.
- Production DNS/Okta are not required for disposable acceptance;
  production-like acceptance remains blocked until those dependencies are
  provisioned.

### Rollback boundary

Keep v2 unrouted externally and redeploy the previous schema-compatible digest.
Immutable releases are retained. Publication rollback changes the routing
projection to the prior verified generation; it never rebuilds release content.

## Milestone 5 — ZIP validation and sealed content policy

### Entry

The complete direct-file M4 golden path passes.

### Exit gate

- Hostile ZIP corpus rejects traversal, absolute paths, links/devices,
  encryption, malformed input, bombs, excessive count/depth/size, Unicode/case
  collisions, and bounded-resource timeouts.
- Original ZIP bytes are preserved and downloadable by identical digest; failed
  validation writes no release prefix.
- MIME detection, approved malware scanning policy, remote-dependency
  inspection, quotas, and rate limits pass clean/infected/unavailable/boundary
  tests.
- Default sealed CSP and security headers block arbitrary network, scripts,
  frames, forms, objects, and unsafe MIME behavior; preview sandbox omits
  `allow-same-origin` by default.
- A ZIP with a non-`index.html` default completes the full
  publish/download/restore/unpublish path.
- Approved-host exceptions remain absent unless pilot evidence and security
  approval explicitly require the bounded, expiring, audited mechanism.
- **Production malware scanner and limits remain BLOCKED-EXTERNAL** until
  product/security owners approve engine, pin, signature ownership, resource
  limits, and failure posture.

### Rollback boundary

ZIP admission is independently disableable. Existing valid direct-file releases
and immutable content routing remain unaffected.

## Milestone 6 — Portable deployment, operations, and recovery

### Entry

M5 supplies stable image, API, storage, routing, and security contracts.

### Exit gate

- Compose first: start, upgrade, verify, rollback, restart, backup/restore, and
  teardown pass twice on clean single-host targets using pinned image digests.
- Helm second: lint, render, install, upgrade, verify, rollback, disruption, and
  uninstall pass on a conformant disposable cluster using the same images,
  configuration schema, migrations, storage layout, and smoke suite.
- GitHub Actions release/deploy/promote/rollback workflows reject untrusted
  publication, require exact-commit checks, use protected environments where
  configured, deploy immutable digests, stop on failed verification, and retain
  evidence.
- Signed multi-architecture images and the signed OCI chart verify from
  `ghcr.io`; no public npm or Docker Hub artifact is created.
- Provider-neutral PostgreSQL restore and database/object-store reconciliation
  demonstrate counts and digests without silently mutating immutable releases.
- Published content remains available during applicable control-plane failure,
  upgrade, telemetry outage, worker restart, and dependency-failure exercises.
- Runbooks cover both deployment profiles, migration, rollback, uploads,
  recovery, credentials, incidents, and retirement.
- Bounded operational instrumentation and redacted structured logs pass
  cardinality, leakage, queue, correlation, and Eyes-outage tests with exporters
  disabled.
- **Production deployment remains BLOCKED-EXTERNAL** until target, DNS/TLS,
  credentials, GitHub Environments, approvals, backup ownership, and rollback
  operator are provisioned.
- **Eyes enablement remains BLOCKED-EXTERNAL** while application ingestion gates
  are closed or any onboarding checklist item lacks acceptance. No Eyes
  endpoint, credential, Matomo site ID, Faro route, or production exporter is
  invented.

### Rollback boundary

Actions redeploys a previously verified image/chart/Compose digest after
checking schema compatibility, runs the same smoke suite, and retains the failed
and restored evidence. Immutable releases and the prior routing generation
remain available.

## Milestone 7 — Pilot, cutover, and legacy retirement

### Entry

M1-M6 evidence is indexed against R1-R16 in a production-like environment.
Required production services and acceptance owners are provisioned.

### Exit gate

- Approved, sanitized fixtures cover direct files, ZIP, non-index defaults,
  external-dependency warning/remediation, label collision, localization,
  download, restore, and roll-forward; Campaign Advisor ownership and expected
  behavior are recorded.
- Representative users complete the primary workflow unassisted, with pass/fail
  evidence mapped to R1-R16 and no per-application infrastructure resources.
- An owner approves exactly one branch: greenfield with evidence that no
  data/consumer requires migration, or a fixed migration inventory and mapping.
- If migration is selected, two repeatable dry runs plus interruption/resume and
  count/digest/source-download reconciliation pass before final consistency and
  routing cutover.
- Production deployment and routing changes run only through GitHub Actions; a
  timed rollback restores the prior route/digest checkpoint.
- No unresolved severity-one/two defect, unaccepted critical/high security
  finding, or unexplained reconciliation discrepancy remains.
- Support, backup, restore, security, upgrade, rollback, and incident procedures
  are exercised by their owners.
- Legacy runtime, routes, storage permissions, and credentials are removed only
  after the approved rollback window closes and traffic/consumer checks are
  clean.
- **Pilot, migration choice, cutover, DNS, and retirement remain
  BLOCKED-EXTERNAL** until actual users, data inventory, production targets,
  acceptance authority, rollback window, and destruction approval are supplied.

### Rollback boundary

Before rollback-window closure, restore the prior route and verified platform
digest and retain both data snapshots. Application restore remains a pointer
operation to an immutable release. After approved retirement, rollback requires
a new incident decision; retired credentials are not kept active “just in case.”

## Cross-milestone evidence index

For every release candidate, maintain one index containing:

- commit, workflow run, source/image/chart digests, SBOM/provenance/signature
  references;
- gate command and test-report links from the test strategy;
- schema version and upgrade/rollback compatibility result;
- Compose and Helm profile results where applicable;
- R1-R16 evidence links and outstanding BLOCKED-EXTERNAL items;
- threat-model/security findings and accepted-risk records with owner/expiry;
- restore/reconciliation and publication-projection results;
- production approvals and provisioning references, with secrets omitted;
- rollout checkpoint, rollback target, actor, result, and follow-up defects.

Modernization is complete only after Milestone 7 passes and every R1-R16 item is
PASS or an expressly permitted conditional branch is NOT-APPLICABLE with
approval. External blockers may coexist with local implementation progress, but
not with a production-readiness claim.
