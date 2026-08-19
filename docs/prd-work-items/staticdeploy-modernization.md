# StaticDeploy Modernization Epics and Stories

## Use of this backlog

This is the implementation-ready decomposition of Milestones 1-7. IDs are stable
planning identifiers, not proof that tracker issues exist. Before posting,
refetch the y30k project and existing issues; extend/reopen existing work rather
than duplicating it. Native blocked-by relationships should mirror the
`Depends on` column.

Every story is intended to fit one reviewable PR or one external
approval/evidence change. If implementation requires unrelated schema, UI,
deployment, and toolchain changes in one PR, split the story without changing
its acceptance contract.

## Shared acceptance contract

The following criteria apply to every implementation story and are not repeated
in each row:

- **AC-1 Scope:** implement only the named behavior; no new language,
  controller, broker, public registry, cloud-specific requirement,
  per-application infrastructure, or speculative compatibility feature.
- **AC-2 Tests:** add/update focused tests and make the named validation pass
  from a clean checkout; retain machine-readable evidence for the exact
  commit/artifact.
- **AC-3 Security:** least privilege, fail-closed input/auth behavior, no
  committed secrets or sensitive samples, and no production access from
  untrusted pull requests.
- **AC-4 Compatibility/rollback:** preserve characterized behavior explicitly
  retained by the story; use additive schema/object changes and
  document/rehearse the story rollback.
- **AC-5 Documentation:** update API/configuration/runbook/evidence references
  affected by the change; no stale completion claim.
- **AC-6 External gate:** a disposable/mock/local pass does not satisfy a named
  production blocker. Mark it `BLOCKED-EXTERNAL` until actual provisioning and
  acceptance exist.

Decision/evidence stories satisfy AC-1, AC-3, AC-5, and AC-6; their “test” is
the concrete review or capability evidence named below.

## External blocker registry

| ID            | Provisioning/decision and owner                                                                                                                                                                                              | Blocks                                            |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| **B-GH**      | `main` default branch/protection, GitHub Environments, GHCR visibility, workflow permissions, signing identity, target credentials/approvals                                                                                 | Release publication; M6 production delivery       |
| **B-OKTA**    | Okta issuer/client, redirect/logout URIs, stable group claim/IDs, administrator mapping, test users, key/secret rotation                                                                                                     | M3/M4 production-like identity acceptance         |
| **B-DNS**     | Trusted portal and wildcard published/preview DNS/TLS, registrable-site/browser matrix, trusted proxy chain, pre-app query-log redaction, cache bypass, internal exposure decision, route cutover access                     | External content acceptance and M7                |
| **B-PG**      | Production PostgreSQL, distinct roles, migration identity, backup destination, restore owner, RPO/RTO                                                                                                                        | M3/M6/M7 production acceptance                    |
| **B-S3**      | S3-compatible service, create-only/conditional capability pass, component policies, version/audit valid-generation rollback detection, encryption/versioning/retention/backups, explicit/workload provider-chain credentials | M3/M6/M7 production acceptance                    |
| **B-CONTENT** | Retention/quotas/ZIP limits, malware scanner/pin/signature owner/failure policy, CSP exception authority                                                                                                                     | M5 production acceptance                          |
| **B-DEPLOY**  | Kubernetes and/or Docker target, ingress, identities, policies/volumes, purpose-separated preview/routing signing-key delivery/storage/rotation/revocation/emergency replacement, environment approval, rollback operator    | M6/M7 production acceptance                       |
| **B-EYES**    | Eyes product/environment onboarding, routes/credentials, open ingestion gates, volume/sensitivity review, dashboards/alerts/runbooks                                                                                         | Production telemetry and M6 operations acceptance |
| **B-PILOT**   | Approved users, Campaign Advisor ownership/license/sanitization, acceptance and defect/security waiver authorities                                                                                                           | M7 pilot/readiness                                |
| **B-DATA**    | Greenfield confirmation or complete legacy consumer/database/object/URL inventory and mapping owner                                                                                                                          | Migration choice and M7                           |
| **B-CUTOVER** | Production checkpoint, final consistency mechanism, rollback window, support owner, destruction approval                                                                                                                     | M7 cutover/retirement                             |

## Completed prerequisite remediation — M1-R1

### M1-R1 — Close residual legacy publication and website coupling

- **Status:** completed by PR #20.
- **Acceptance evidence:** active `CIRCLE_*` website inputs, public
  `publishConfig`, retired Docker Hub/public npm paths, the obsolete CLI image,
  and tag-release behavior are removed; `docs/ci-retirement-evidence.md` is
  corrected; both required Actions checks passed.
- **Validation evidence:** tracked-file searches, actionlint, clean frozen
  install/compile/lint, service-image build, and a local service/CLI
  bundle-deploy-retrieve roundtrip passed on the exact candidate.
- **Follow-on:** M2-02 owns the canonical `main` migration and restored branch
  protection. Future publication settings remain B-GH/M2-09 work. Neither
  reopens M1-R1.
- **Blocks:** cleared for M2-01.

---

## Epic M2 — Supported toolchain and secure artifacts

**Outcome:** all retained packages build/test on a pinned supported runtime; one
hardened multi-architecture image can be verified and, once provisioned,
published only through GitHub Actions.

| ID          | Story and unique acceptance                                                                                                                                                                                                                                                                                                                          | Validation                                                                                                                                      | Depends on                 | External blockers                                                   |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- | ------------------------------------------------------------------- |
| **M2-01**   | **Confirm workspace/vulnerability contracts for Node 24.19.0.** Measure upgraded Yarn/Lerna versus pnpm only where useful; select the lower-complexity path; confirm retired artifact set; define critical/high gate and owned expiring exceptions.                                                                                                  | Two clean-install/build comparisons; artifact-consumer inventory; security/GitHub review.                                                       | M1-R1                      | B-GH                                                                |
| **M2-02**   | **Pin deterministic runtime and workspace install.** Repository, CI, and builder pins agree; frozen clean installs do not change lockfile; remove Node 14 references; enforce an exact reviewed package/version install-script inventory with global execution disabled; migrate the canonical branch only when GitHub settings access is available. | G-M2 pin/install phase twice; lockfile diff; install-script policy negative test; retained workspace compile/test; refetched `main` protection. | M2-01                      | B-GH for branch rename/protection; local toolchain work may proceed |
| **M2-03**   | **Replace TSLint and centralize checks.** ESLint/shared TypeScript/test/format configuration covers retained workspaces with documented narrow exceptions; standalone typecheck exists; unsupported hook/format tooling is removed.                                                                                                                  | G-M2 format/lint/type/unit phase; search for TSLint.                                                                                            | M2-02                      | —                                                                   |
| **M2-04**   | **Upgrade S3 client to modular AWS SDK v3.** Retain characterized protocol/errors; support endpoint/region/path-style/explicit credentials/default provider chain; no AWS SDK v2 runtime dependency.                                                                                                                                                 | MinIO upload/read/list/delete/error suite under explicit and provider-chain configurations.                                                     | M2-02                      | B-S3 only for production capability acceptance                      |
| **M2-05**   | **Upgrade PostgreSQL/migration libraries.** Empty and legacy schemas migrate; pool/transaction errors are characterized; additive migration convention and rollback rehearsal are documented.                                                                                                                                                        | SCH-01/02 baseline subset and integration transaction failures.                                                                                 | M2-02                      | B-PG only for production acceptance                                 |
| **M2-06**   | **Upgrade backend dependencies in slices.** HTTP, auth, logging, utility, and test dependencies move to supported releases in separate focused changes; only approved compatibility remains; scan policy has no unaccepted critical. The pulled-forward M4-10 foundation removes retained frontend/tooling blockers from the exact graph.            | Unit/characterization/API/PG/MinIO after each slice; dependency/license/source/secret reports.                                                  | M2-03, M2-04, M2-05, M4-10 | —                                                                   |
| **M2-07**   | **Build one hardened baseline service image.** Multi-stage frozen build; runtime excludes build tooling/source; non-root/read-only-root contract; preserve characterized service startup; remove CLI image path.                                                                                                                                     | IMG-02/03; baseline service start/health smoke; SBOM/layer inspection.                                                                          | M2-06                      | —                                                                   |
| **M2-08**   | **Build and smoke amd64/arm64 without publication.** Both architectures derive from one commit, boot all applicable commands, retain digests, and PR execution cannot push.                                                                                                                                                                          | IMG-01 plus registry-negative assertion.                                                                                                        | M2-07                      | B-GH only for hosted runner capabilities if unavailable             |
| **M2-GATE** | **Close the local M2 gate.** All retained workspaces and the hardened amd64/arm64 baseline image pass the complete supported-toolchain, scan-policy, and artifact-conformance suite for one exact commit.                                                                                                                                            | `./scripts/gates/m2-toolchain.sh`; retained gate manifest and image digests.                                                                    | M2-03 through M2-08        | —                                                                   |
| **M2-09**   | **Publish approved signed release artifacts.** Approved tag/dispatch verifies exact-commit checks; images go only to GHCR by digest with SBOM/provenance/signature; packages publish only if explicitly approved and then only to GitHub Packages.                                                                                                   | REL-01 rejected/untrusted cases and one provisioned approved release; verify all digests/attestations.                                          | M2-GATE                    | B-GH                                                                |

**Epic gate:** M2-GATE. Local M3 implementation depends on M2-GATE, not M2-09;
M2-09 is the externally gated publication branch that feeds M6-05.

---

## Epic M3 — Security, data, and runtime foundation

**Outcome:** additive v2 state, server sessions, immutable storage, resilient
PostgreSQL work, database-free publication routing, and separately permissioned
commands run first in Compose and then an initial Helm profile.

| ID          | Story and unique acceptance                                                                                                                                                                                                                                                                                                                            | Validation                                                                                 | Depends on                 | External blockers                                                        |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ | -------------------------- | ------------------------------------------------------------------------ |
| **M3-01**   | **Accept trust contracts and threat model.** Review ADR-003 through ADR-012; model origins, sessions/CSRF, uploaded code/paths/archives, preview capabilities, storage, projection, CI and workload identities; unresolved concrete values remain named gates.                                                                                         | Security/operator/identity review with abuse cases and story traceability.                 | M2-GATE                    | B-OKTA, B-DNS, B-PG, B-S3 (values remain blocked, logical ADRs may pass) |
| **M3-02**   | **Add core v2 schema.** Add applications, releases, upload declarations, bindings and audit tables/indexes; opaque IDs, immutable READY fields, version-label uniqueness, bounded query support.                                                                                                                                                       | SCH-01 through SCH-05.                                                                     | M2-05, M3-01               | B-PG only for production role/capability acceptance                      |
| **M3-03**   | **Add sessions/idempotency/jobs/outbox schema.** Add expiry/revocation, request-digest/result identity, lease/retry, generation/outbox/ack constraints and indexes without altering legacy data.                                                                                                                                                       | Empty/upgrade migration, concurrency/constraint/query-plan tests.                          | M3-02                      | —                                                                        |
| **M3-04**   | **Implement quarantine and immutable releases.** Enforce prefixes, create-only finalization, digest verification, and component credentials; content cannot access quarantine/write.                                                                                                                                                                   | STO-01/02 with disposable PostgreSQL/MinIO.                                                | M2-04, M3-02               | B-S3 for production capability/policies                                  |
| **M3-05**   | **Implement job leases, retries and cleanup.** Atomic claim/renew/reclaim, bounded timeout/attempt/terminal reason, idempotent completion, expired quarantine cleanup.                                                                                                                                                                                 | JOB-01/02/03.                                                                              | M3-03, M3-04               | —                                                                        |
| **M3-06**   | **Implement server-side OIDC sessions.** Code+PKCE/state/nonce validation, exact pre-login transaction/session cookie and endpoint-specific CSRF/content-type contract, logout/revocation/expiry/rotation; no v2 browser token storage.                                                                                                                | AUTH-01 through AUTH-05 and TM-SES-01 against mock IdP.                                    | M3-03                      | B-OKTA for AUTH-06/production-like exit                                  |
| **M3-07**   | **Implement role bindings and authorization policy.** Admin/owner/publisher/viewer/denied capabilities and transactional/idempotent group binding replacement have no escalation or partial update; safe append-only audits.                                                                                                                           | AUTHZ-01, TM-AUD-01 policy/binding/audit denial and canary matrix.                         | M3-02, M3-03, M3-06        | B-OKTA for real group mapping                                            |
| **M3-08**   | **Implement publication outbox and routing projection.** `control` atomically writes PostgreSQL desired pointer/audit/outbox; `worker` purpose-signs and conditionally writes/reads back generations and `current.json`; acknowledgement, stale/duplicate/out-of-order safety, replay residual detection, reconciliation and last-known-good behavior. | PROJ-01 through PROJ-06, TM-PROJ-01 and TM-KEY-01.                                         | M3-03, M3-04, M3-05        | B-S3 for production conditional-write/read semantics                     |
| **M3-09**   | **Split the four runtime commands.** Distinct config/startup/health and dependency composition; content has no DB/OIDC/quarantine/write configuration; wrong host fails closed.                                                                                                                                                                        | CMD-01 boot/schema/credential/wrong-host/cross-command matrix.                             | M3-05, M3-06, M3-08, M2-07 | —                                                                        |
| **M3-10**   | **Create Compose security foundation.** Run migrate/control/content/worker/PostgreSQL/MinIO with persistent volumes, distinct credentials, health, non-root/read-only roots, dropped capabilities and repeatable teardown.                                                                                                                             | CMP-01 Compose lifecycle, identity, credential, mount and privilege inspection.            | M3-09                      | —                                                                        |
| **M3-11**   | **Create initial Helm security foundation.** Express the same commands/config/migration with distinct service accounts, configurable secure contexts/probes/resources/policies; provider annotations optional.                                                                                                                                         | HLM-01 chart lint/schema/render and disposable-cluster network/identity/migration/restart. | M3-10                      | B-DEPLOY only for production target acceptance                           |
| **M3-GATE** | **Close the local M3 gate.** The additive schema, mock-IdP sessions/RBAC, immutable storage/jobs/projection, four real commands, Compose, and disposable Helm boundaries pass together.                                                                                                                                                                | `./scripts/gates/m3-foundation.sh`; complete local evidence manifest.                      | M3-01 through M3-11        | —                                                                        |

**Epic gate:** M3-GATE. Production-like acceptance additionally requires AUTH-06
and provisioned DNS/database/storage policy tests.

---

## Epic M4 — Secure direct multi-file vertical slice

**Outcome:** one nontechnical-user path completes from application creation
through immutable direct-file release, isolated preview, acknowledged
publication, source download, restore, and unpublish.

| ID          | Story and unique acceptance                                                                                                                                                                                                                                                                                                        | Validation                                                                          | Depends on                 | External blockers                          |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | -------------------------- | ------------------------------------------ |
| **M4-01**   | **Publish the v2 API contract/error model.** Commit OpenAPI for minimum endpoints/operation status, bounded pagination, UTC timestamps, stable errors and idempotency headers.                                                                                                                                                     | API-01/02 schema generation and negative cases.                                     | M3-GATE                    | —                                          |
| **M4-02**   | **Implement application directory endpoints.** Create/get/search/list/archive descriptions, normalized tags, owner groups and approved internal visibility; archived apps reject releases; actions audited/authorized.                                                                                                             | R1 contract/search/pagination/archive/role tests.                                   | M4-01, M3-07               | —                                          |
| **M4-03**   | **Implement bindings and audit APIs.** Complete transactional binding replacement and bounded indexed audit filters by app/actor/action/UTC.                                                                                                                                                                                       | Binding idempotency/rollback plus SCH-05/API contract.                              | M4-01, M3-07               | —                                          |
| **M4-04**   | **Implement direct upload protocol.** Declare one or more safe paths, stream only declared files to quarantine, complete explicitly/idempotently, reject missing/undeclared/duplicate/count/size/path errors.                                                                                                                      | STO-03 and release/upload API cases.                                                | M4-01, M4-02, M3-05        | —                                          |
| **M4-05**   | **Finalize direct releases.** Detect MIME, hash source/content, preserve bytes/paths, write and verify one immutable manifest/prefix; partial failure exposes none.                                                                                                                                                                | JOB-02, STO-02, MIME confusion and manifest determinism.                            | M4-04                      | —                                          |
| **M4-06**   | **Select default and enforce release state.** Return HTML/HTM candidates; only a manifest candidate is selectable; selection is idempotent and immutable after READY.                                                                                                                                                              | State/property tests including nested non-index, missing/invalid/post-READY cases.  | M4-05                      | —                                          |
| **M4-07**   | **Generate deterministic source downloads.** Stable path order/archive metadata/compression; manifest proves path/size/SHA-256; authorized streaming exposes no storage credential.                                                                                                                                                | DIR-01 across repeated processes/architectures.                                     | M4-05, M3-07               | —                                          |
| **M4-08**   | **Implement publish/restore/unpublish operations.** Collision-safe first-publish UTC label; projection acknowledgement before final success; retries observe same operation; restore retains label.                                                                                                                                | SCH-03, PROJ-04, concurrent/rollback API tests.                                     | M4-03, M4-06, M3-08        | —                                          |
| **M4-09**   | **Serve isolated preview and published content.** Host-derived routing only; exact signed preview capability/cookie and sandbox; selected default and assets served from immutable release; minimum ISO-01 CSP/header/network/frame/service-worker isolation; cross-app/portal state denied.                                       | R5/R11, TM-PRE-01, TM-ISO-01 and PROJ-06 tests.                                     | M4-06, M4-08, M3-09        | B-DNS for production origin/TLS acceptance |
| **M4-10**   | **Modernize frontend build/test foundation.** Replace CRA with Vite and Enzyme with Testing Library; upgrade React/Ant Design compatibly; retain only required UI behavior/CSP compatibility. This bounded security foundation is pulled forward by the sequencing amendment; routing/forms and workflow behavior remain deferred. | Frontend build/component/serve smoke; dependency search.                            | M2-03                      | —                                          |
| **M4-11**   | **Modernize routing/forms.** Supported router and maintained form library replace React Router 5/Redux Form without a visual redesign; retained routes/validation/deep links work.                                                                                                                                                 | Route, deep-link, history, validation and submission-error component/browser tests. | M3-GATE, M4-10             | —                                          |
| **M4-12**   | **Build the complete direct workflow UI.** Directory/history/bindings/audit, upload/status/default, preview, publish/unpublish/download/restore, localized time and error/pending retries are keyboard operable.                                                                                                                   | UI-01/03/04, API-03, A11Y-01/02 and hostile two-app browser suite.                  | M4-02 through M4-09, M4-11 | B-OKTA/B-DNS only for production-like run  |
| **M4-GATE** | **Close the local M4 gate.** The full direct-file API/worker/content/UI path, accessibility checks, role matrix, hostile two-app isolation, deterministic download, restore, and unpublish pass together.                                                                                                                          | `./scripts/gates/m4-direct-golden.sh`; complete local evidence manifest.            | M4-01 through M4-12        | —                                          |

**Epic gate:** M4-GATE.

---

## Epic M5 — ZIP validation and sealed content policy

**Outcome:** ZIP uses the proven worker/release path with bounded hostile-input
defenses, approved scanning, sealed browser policy, and byte-exact source
preservation.

| ID          | Story and unique acceptance                                                                                                                                                                                                                           | Validation                                                            | Depends on          | External blockers                                        |
| ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ------------------- | -------------------------------------------------------- |
| **M5-01**   | **Implement bounded ZIP extraction.** Preserve original first; reject absolute/traversal/link/device/encrypted/malformed/collision/bomb/limit inputs; bound CPU/memory/disk/time; no failed release prefix.                                           | ZIP-01 and original digest checks.                                    | M4-GATE             | B-CONTENT for approved limit values                      |
| **M5-02**   | **Integrate approved malware scanning.** Pin approved engine, bound input, sanitize report, implement clean/infected/unavailable/timeout/stale-signature posture; scanner receives no product credentials.                                            | ZIP-02 including approved test signature.                             | M5-01               | B-CONTENT                                                |
| **M5-03**   | **Generate advisory content findings.** Detect remote scripts/assets, network targets, forms, frames, object/embed in HTML/CSS/JS; malformed input is bounded and portal output escaped.                                                              | POL-01 fixture matrix.                                                | M5-01               | —                                                        |
| **M5-04**   | **Enforce sealed CSP and headers.** Local-only default, no arbitrary network/scripts/frames/forms/objects; MIME-driven response plus nosniff/referrer/permissions/CORP/frame/disposition/cache headers on content/errors.                             | POL-02 network observer and header snapshots.                         | M4-09, M5-03        | —                                                        |
| **M5-05**   | **Harden preview sandbox and portal rendering.** No `allow-same-origin` by default; content cannot navigate/control portal/opener/storage; filenames/findings render as text.                                                                         | POL-03 hostile browser fixtures.                                      | M4-12, M5-04        | —                                                        |
| **M5-06**   | **Add quotas and rate limits.** Enforce approved per-file/total/count/depth/concurrency/request limits before full buffering; safe bounded responses/audits and reset behavior.                                                                       | POL-04 boundary/one-over/concurrency/resource measurements.           | M4-04, M5-01        | B-CONTENT                                                |
| **M5-07**   | **Resolve host-exception need and close ZIP golden path.** Record “not needed” unless pilot evidence approves exact bounded/expiring/audited hosts; complete non-index ZIP preview/publish/original-download/restore/unpublish and all hostile cases. | POL-05 as applicable, UI-02, full G-M5 corpus.                        | M5-02 through M5-06 | B-CONTENT; B-PILOT only if exception evidence is claimed |
| **M5-GATE** | **Close the local M5 gate.** The byte-exact ZIP golden path, hostile archive corpus, approved scanner posture, CSP/header/sandbox policy, quotas, and any approved exception behavior pass together.                                                  | `./scripts/gates/m5-zip-policy.sh`; complete local evidence manifest. | M5-01 through M5-07 | —                                                        |

**Epic gate:** M5-GATE. Do not build a general exception system without approved
evidence.

---

## Epic M6 — Portable deployment, operations, and recovery

**Outcome:** the same signed release installs, upgrades, verifies, rolls back
and recovers through Compose first and Helm second; Actions is the only delivery
controller; telemetry is safe but off until Eyes onboarding.

| ID        | Story and unique acceptance                                                                                                                                                                                                                                                                                                      | Validation                                                                                     | Depends on                 | External blockers                   |
| --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | -------------------------- | ----------------------------------- |
| **M6-01** | **Freeze profile/upgrade contract.** Document shared image/config/migration/storage/health/smoke names, ingress/secret/provider-chain behavior, purpose-separated preview/routing signing-key delivery and lifecycle, supported upgrade/schema rollback boundary and operator ownership; no cloud/CD controller requirement.     | Cross-profile design review against disposable Compose/cluster.                                | M5-GATE                    | B-DEPLOY for production values only |
| **M6-02** | **Complete Compose lifecycle.** Pinned digests, volumes/config/health, upgrade/backup/restore/rollback/restart/teardown on local and single-host targets; published content survives control restarts.                                                                                                                           | DEP-01 via G-M6-C twice from clean hosts.                                                      | M6-01, M3-10               | B-DEPLOY for production host        |
| **M6-03** | **Complete Helm lifecycle.** Configurable ingress/accounts/storage/provider chain/resources/probes/scheduling/policies/migrations/cleanup; install/upgrade/rollback/disruption/uninstall preserve content.                                                                                                                       | DEP-02 via G-M6-H on conformant disposable cluster.                                            | M6-02, M3-11               | B-DEPLOY for production cluster     |
| **M6-04** | **Create one profile conformance suite.** Same API/content/security smoke verifies digest, migrations, privileges, storage and content availability; profile differences are adapters; diagnostics retained.                                                                                                                     | Run complete suite against M6-02 and M6-03 release locks.                                      | M6-02, M6-03               | —                                   |
| **M6-05** | **Publish signed OCI chart.** Exact-commit checked chart references immutable images, publishes only to GHCR by digest, verifies approved signature/provenance, and records chart/image identifiers.                                                                                                                             | Pull/verify/install one approved digest plus rejection cases.                                  | M2-09, M6-03, M6-04        | B-GH                                |
| **M6-06** | **Add protected deploy/promotion workflows.** Explicit profile/target and verified digests; target-appropriate auth; migration/health/API/content checks; protected approvals; failure stops promotion.                                                                                                                          | DEP-03 for both profiles and failure modes.                                                    | M6-04, M6-05               | B-GH, B-DEPLOY                      |
| **M6-07** | **Add explicit rollback workflows.** Select prior verified digest, reject incompatible schema, restore approved routing/DNS checkpoint where provisioned, run identical smoke, retain actor/approver/target/from/to/result/UTC evidence.                                                                                         | DEP-04, CUT-01 and OP-AUD-01 successful/incompatible/blocked-external cases for both profiles. | M6-06                      | B-GH, B-DEPLOY, B-DNS, B-CUTOVER    |
| **M6-08** | **Implement restore/reconciliation contract.** Provider-neutral PostgreSQL backup/restore; report missing rows/objects, orphans, digest and routing drift; no silent immutable mutation; both profiles.                                                                                                                          | REC-01/02 via G-M6-R.                                                                          | M6-02, M6-03, M3-08        | B-PG, B-S3 for production exercise  |
| **M6-09** | **Implement disabled-by-default operational instrumentation.** Health, bounded request/dependency/job/validation/publication/serving/PG/S3/OIDC signals; structured redaction; request/W3C correlation; bounded sampling/queues/retries; default exporters/browser collection off.                                               | OBS-01 through OBS-04; captured-signal secret/PII search; upstream outage.                     | M6-01                      | B-EYES only for production export   |
| **M6-10** | **Complete Eyes handoff and operational exercises.** Supply onboarding fields; receive scoped routes/credentials outside Git; approve dashboards/alerts/runbooks; exercise load, dependency/worker/control/telemetry outage, backup/restore and both profile runbooks. Production collection stays off while any gate is closed. | Eyes acceptance checklist, OPS-01, G-M6-O, service-usable-with-Eyes-down test.                 | M6-04, M6-07, M6-08, M6-09 | B-EYES, B-PG, B-S3, B-DEPLOY        |

**Epic gate:** G-M6-C, then G-M6-H, G-M6-R, and G-M6-O. Production
artifact/deployment/telemetry claims require their external blockers to pass.

---

## Epic M7 — Pilot, cutover, and legacy retirement

**Outcome:** representative users and operators accept R1-R16 in a
production-like target, the approved greenfield/migration branch is reconciled,
cutover and rollback are exercised, and legacy access is retired after its
window.

| ID        | Story and unique acceptance                                                                                                                                                                                                                                    | Validation                                                                                      | Depends on                          | External blockers                                      |
| --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | ----------------------------------- | ------------------------------------------------------ |
| **M7-01** | **Acquire representative pilot corpus.** Approved/sanitized direct, ZIP, non-index, external-dependency/remediation, collision, timezone and restore fixtures; Campaign Advisor provenance/expected assertions; no credentials/personal data.                  | Fixture provenance review; upload/download/policy/scan preflight.                               | M6-10                               | B-PILOT                                                |
| **M7-02** | **Run facilitated then unassisted pilot.** Representative users complete Campaign Advisor and primary flows; results map to every R1-R16; resource inventory proves no app-specific Kubernetes/Docker resources.                                               | Pilot protocol, Playwright evidence, before/after resource inventory, defect map.               | M7-01                               | B-PILOT, B-OKTA, B-DNS, B-DEPLOY                       |
| **M7-03** | **Approve greenfield or migration branch.** Re-inventory consumers/URLs/DB/objects; approve no-migration evidence or freeze migration scope/counts/owners; approve consistency, checkpoint and rollback window; unknowns block.                                | Redacted inventory evidence and dated owner approval.                                           | M7-02                               | B-DATA, B-CUTOVER                                      |
| **M7-04** | **Map legacy model (conditional).** Read-only deterministic map of apps/bundles/entrypoints/logs/URLs/objects to v2 apps/releases/defaults/audits/routes; explicit exception report and signed-off count/digest baseline.                                      | Run mapping on snapshot; review every exception/count.                                          | M7-03 selects migration             | B-DATA                                                 |
| **M7-05** | **Implement repeatable importer (conditional).** Idempotent/resumable source identity/digest; no legacy mutation/duplicate releases; interruption safe; counts/digests/URLs/downloads match.                                                                   | Two clean dry runs plus interruption/resume/duplicate/mismatch/source-download cases.           | M7-04                               | B-PG, B-S3                                             |
| **M7-06** | **Execute consistency/cutover/rollback (conditional for migration; routing step required for greenfield).** Approved consistency prevents omissions; Actions-only deploy/routing; post-cutover reconciliation clean; checkpoint intact; timed rollback passes. | Cutover rehearsal, production smoke, reconciliation, GHA evidence and timed rollback.           | M7-03; M7-05 if migration; M6-06/07 | B-GH, B-DNS, B-DEPLOY, B-CUTOVER                       |
| **M7-07** | **Close R1-R16 and readiness gates.** Every requirement links exact evidence; no Sev1/2 or unaccepted critical/high; app restore and platform rollback pass; support/security/backup/restore/upgrade/incident docs match operator walkthrough.                 | `G-M7 --evidence-index ...`; defect/security registers and owner approvals.                     | M7-02, M7-03, M7-06                 | B-PILOT, B-CUTOVER, all unresolved production blockers |
| **M7-08** | **Retire legacy runtime after rollback window.** Remove old runtime access/storage policy/DNS/routes/credentials/secrets; only Actions can release/deploy; no consumer/data/traffic remains; record retirement/data disposition.                               | Probe old routes/access, refetch integrations/permissions, traffic check, new production smoke. | M7-07 and approved window closure   | B-CUTOVER, B-DATA, B-GH, B-DNS                         |

**Epic gate:** `./scripts/gates/m7-pilot-cutover.sh --evidence-index <path>`.

## Critical path and ready policy

```text
M1-R1
 -> M2-01 -> M2-02 -> M2-03/04/05 -> M4-10 security/toolchain foundation
 -> M2-06 -> M2-07 -> M2-08 -> M2-GATE
 -> M3-01 -> M3-02/03/04/05/06/07/08 -> M3-09 -> M3-10 -> M3-11 -> M3-GATE
 -> M4-01..09 + M4-11 -> M4-12 -> M4-GATE
 -> M5-01..07 -> M5-GATE
 -> M6-01 -> M6-02 -> M6-03 -> M6-04 -> M6-06/07/08/09/10
 -> M7-01 -> M7-02 -> M7-03 -> conditional M7-04/05 -> M7-06 -> M7-07 -> M7-08

Publication branch: M2-GATE -> M2-09 -> M6-05 -> M6-06
```

M2-09 is externally gated; the local product path does not wait on publication.

A story is Ready only when all repository dependencies pass and its required
logical decision is approved. An external blocker may leave a story Ready for
disposable/local implementation if the row says so, but it remains
`BLOCKED-EXTERNAL` for production acceptance. Conditional stories are not
implemented until their decision selects that branch.

## Tracker posting guidance

- Reopen/extend the existing CI retirement item for M1-R1.
- Create one Feature per M2-M7 epic and Story/Task children with these IDs.
- Preserve native parent and blocked-by links; do not encode dependencies only
  in prose.
- Refetch current issue/project state before mutation because earlier planning
  status is stale.
- Do not create M7 migration implementation work until M7-03 selects migration.
- Do not implement M5 host exceptions until M5-07 has approved pilot evidence.
- Do not mark M2 publication, M3 production identity/storage, M5 scanner policy,
  M6 production delivery/Eyes, or M7 cutover complete while their external
  blockers remain.
