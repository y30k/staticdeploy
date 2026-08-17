# StaticDeploy Revival Bootstrap Work-Item Mutation Report

## Posting status

- Source: `docs/prds/staticdeploy-revival-bootstrap.prd.md`
- Design: `docs/technical-designs/staticdeploy-revival-bootstrap.md`
- Test strategy: `docs/test-strategies/staticdeploy-revival-bootstrap.md`
- Target tracker: <https://github.com/orgs/y30k/projects/2/views/1>
- Target repo: `y30k/staticdeploy`
- Permission mode: authorized to mutate by user request
- Actual mode: **mutated and verified**

Project 2, repository issues, and repository PRs were empty before mutation, so no canonical or competing item existed. GitHub Issues was disabled and was enabled as the minimum tracker prerequisite. The parent Feature and eight Task sub-issues were created, added to Project 2, linked with native Parent issue and blocked-by relationships, assigned truthful Status values, and refetched for verification.

## Dependency graph

```text
RUN-01 ──> RUN-02
   ├─────> QA-01 ────────────┐
   └─────> CHAR-01 ──────────┼──> CI-01 ──> CI-02 ──> CI-03
DEC-01 ─────────> CHAR-01 ───┘                    └──────^
DEC-01 ─────────────────────────────────────────────────┘
```

## Mutation result

| Draft ID | GitHub issue | Type | Project status | Native blockers |
| --- | --- | --- | --- | --- |
| EPIC | [#1](https://github.com/y30k/staticdeploy/issues/1) | Feature | Backlog | none |
| RUN-01 | [#2](https://github.com/y30k/staticdeploy/issues/2) | Task, child of #1 | Ready | none |
| RUN-02 | [#3](https://github.com/y30k/staticdeploy/issues/3) | Task, child of #1 | Backlog | #2 |
| DEC-01 | [#4](https://github.com/y30k/staticdeploy/issues/4) | Task, child of #1 | Ready | none |
| QA-01 | [#5](https://github.com/y30k/staticdeploy/issues/5) | Task, child of #1 | Backlog | #2 |
| CHAR-01 | [#6](https://github.com/y30k/staticdeploy/issues/6) | Task, child of #1 | Backlog | #2, #4 |
| CI-01 | [#7](https://github.com/y30k/staticdeploy/issues/7) | Task, child of #1 | Backlog | #5, #6 |
| CI-02 | [#8](https://github.com/y30k/staticdeploy/issues/8) | Task, child of #1 | Backlog | #7 |
| CI-03 | [#9](https://github.com/y30k/staticdeploy/issues/9) | Task, child of #1 | Backlog | #8, #4 |

The project Priority field has no configured options and was left unset. Native dependencies and Status are the readiness source of truth.

---

## RUN-01 — Build the minimum historical service/CLI dependency closure

**Type**: Story
**Owning repo/system**: `y30k/staticdeploy`
**Priority**: Highest — first execution evidence and prerequisite for every code change
**User value**: Gives the maintainer a trustworthy baseline and isolates environmental drift before modernization.

### Scope

Run the unchanged checkout in an isolated Node 14/Yarn 1 environment. Perform a frozen install and compile only `@staticdeploy/staticdeploy`, `@staticdeploy/cli`, and their workspace dependencies. Retain exact evidence or stop at the first deterministic blocker in that required closure; unrelated workspace failures belong to QA-01 and do not block RUN-02.

### Acceptance criteria

- [ ] Commit SHA, architecture, exact Node version, exact Yarn version, commands, duration, and logs are retained.
- [ ] `yarn install --frozen-lockfile` succeeds without modifying `yarn.lock`.
- [ ] The scoped Lerna compile succeeds for the service, CLI, and their dependency closure.
- [ ] The built service and CLI entrypoints exist.
- [ ] No dependency, lockfile, source, release, or registry change is included.
- [ ] If any command fails, the first error is reproduced once and one narrowly scoped blocker is drafted instead of broad upgrades.

### Validation

```bash
node --version
yarn --version
git rev-parse HEAD
yarn install --frozen-lockfile
git diff --exit-code -- yarn.lock
yarn lerna run compile --scope=@staticdeploy/staticdeploy --scope=@staticdeploy/cli --include-dependencies --stream --concurrency 1
test -f staticdeploy/build/server.js
test -f cli/build/index.js
```

### Relationships

- parent: Revival Bootstrap epic if the project supports it
- blocked by: none
- blocks: RUN-02, QA-01, CHAR-01

### Non-scope

Dependency upgrades, supported-runtime migration, Docker builds, CI changes, persistent storage, and production claims.

---

## RUN-02 — Boot the legacy service and publish/retrieve a trusted fixture

**Type**: Story
**Owning repo/system**: `y30k/staticdeploy`
**Priority**: Highest after RUN-01 — delivers the visible running proof
**User value**: Demonstrates that the integrated console, API, and static server perform the core domain workflow.

### Scope

Start the built process with memory storage and authentication disabled **inside a verified loopback-only network namespace, container, or VM**. The server has no bind-host option and otherwise listens on all interfaces. Run smoke clients inside the same boundary, prove an outside client cannot connect, verify health and console routing, create/deploy `website/demo-static-app`, retrieve it from a content Host, then restart and confirm state is ephemeral.

### Acceptance criteria

- [ ] The selected execution boundary has no routable inbound interface; the service is reachable from inside and unreachable from outside.
- [ ] Startup logs show memory storage and contain no production credentials.
- [ ] `GET /api/health` with `Host: localhost` returns 200 from inside the boundary.
- [ ] `/` with `Host: localhost` returns the management console HTML.
- [ ] The built CLI creates and deploys the repository-owned fixture.
- [ ] `/` with `Host: smoke.local` returns the fixture's expected stable content.
- [ ] Restart preserves health but removes the deployment, proving memory mode.
- [ ] Evidence is labeled “legacy disposable baseline,” not secure or production-ready.
- [ ] Boundary method and outside connection-denial evidence are retained; the process is not exposed to untrusted networks or uploads.

### Validation

Use the RUN-02 commands and methods in `docs/test-strategies/staticdeploy-revival-bootstrap.md`.

### Relationships

- blocked by: RUN-01
- blocks: none

### Non-scope

PostgreSQL/MinIO, JWT/OIDC, repository Docker Compose implementation, image publication, and untrusted content. A temporary container/VM may be used only as the execution isolation boundary.

---

## DEC-01 — Inventory legacy consumers, data, and delivery integrations

**Type**: Task/Spike
**Owning repo/system**: `y30k/staticdeploy` plus repository/integration settings
**Priority**: Highest and parallel — retirement decisions depend on it
**User value**: Prevents modernization from silently breaking a real consumer or losing data.

### Scope

Inventory API v1, CLI, CLI image, SDK, public packages, website publication, external URLs, database/object data, CircleCI, Docker Hub, npm, Codecov, webhooks, and deployment integrations.

### Acceptance criteria

- [ ] Every surface has repository/settings evidence and one disposition: preserve, retire, none found, or external confirmation required.
- [ ] Every preserved surface has an explicit compatibility acceptance test.
- [ ] Existing production data/URLs are identified, or greenfield status is explicitly confirmed.
- [ ] Unknown external access is named and blocks only dependent retirement/migration work.
- [ ] No credential value or sensitive production sample is recorded.

### Validation

Review repository config/docs/package metadata, GitHub settings, external integration lists, and any available storage/deployment inventory. Retain links or redacted evidence.

### Relationships

- blocked by: none
- blocks: CHAR-01, CI-03, later compatibility/migration decisions

### Non-scope

Changing or revoking integrations; implementation belongs to CI-03 or later migration work.

---

## QA-01 — Reproduce complete legacy PostgreSQL/MinIO QA

**Type**: Story
**Owning repo/system**: `y30k/staticdeploy`
**Priority**: High — required before CI parity
**User value**: Establishes the complete historical test baseline, including persistent storage adapters.

### Scope

Provision dedicated disposable PostgreSQL and MinIO instances compatible with the historical tests, then run compile, lint, and coverage/test commands without dependency modernization.

### Acceptance criteria

- [ ] Test services are disposable and contain no valued data.
- [ ] Endpoints and credentials match the test contract or are changed only in a separately justified harness fix.
- [ ] `yarn compile`, `yarn lint`, and `npm run coverage` pass with retained logs/coverage, or deterministic blockers are isolated.
- [ ] Test cleanup is demonstrated not to target non-test services.
- [ ] Exact service image/software versions are recorded.

### Validation

```bash
yarn compile
yarn lint
npm run coverage
```

### Relationships

- blocked by: RUN-01
- blocks: CI-01

### Non-scope

GitHub Actions, modern PostgreSQL/S3 contract changes, performance testing, production infrastructure.

---

## CHAR-01 — Add the minimum approved characterization pack

**Type**: Story
**Owning repo/system**: `y30k/staticdeploy`
**Priority**: High — protects modernization semantics
**User value**: Makes later dependency and architecture changes observable rather than speculative.

### Scope

Retain the existing create/deploy/retrieve test and add only gaps for behavior DEC-01 approves for preservation: routing/fallback, headers, authorization denial, API errors, migrations/object layout, and trailing-dot behavior.

### Acceptance criteria

- [ ] Each test maps to a behavior approved for retention.
- [ ] Tests use trusted fixtures and deterministic data.
- [ ] Tests fail under a deliberate incompatible behavior change and pass on the untouched baseline.
- [ ] No modern API v2 or new product behavior is asserted.
- [ ] Focused and full relevant test commands pass.

### Validation

Use existing package test commands; list exact added tests and their retained behavior mapping in the change.

### Relationships

- blocked by: RUN-01, DEC-01
- blocks: CI-01

### Non-scope

Modern multi-file requirements, security redesign, broad coverage targets, UI rewrite.

---

## CI-01 — Add non-publishing GitHub Actions baseline QA

**Type**: Story
**Owning repo/system**: `y30k/staticdeploy`
**Priority**: High after baseline evidence — establishes the only future CI system
**User value**: Reproduces validated checks on every pull request without introducing release risk.

### Scope

Add pinned, minimally permissioned GitHub Actions pull-request checks for frozen install, compile, lint, tests/coverage with disposable PostgreSQL/MinIO. Preserve Node 14/Yarn 1 temporarily so this story measures CI parity, not modernization.

### Acceptance criteria

- [ ] The workflow uses pinned action revisions and minimum `contents: read` permissions.
- [ ] Untrusted PR jobs receive no publication/deployment credentials.
- [ ] Frozen install, compile, lint, and full tests/coverage match QA-01.
- [ ] Required logs/coverage are retained.
- [ ] Check names are stable and suitable for branch protection.
- [ ] No image/package/chart publication or deployment can occur.
- [ ] CircleCI remains until CI-02 and retirement gates pass.

### Validation

A clean PR run passes every check from a clean checkout and matches local QA evidence.

### Relationships

- blocked by: QA-01, CHAR-01
- blocks: CI-02

### Non-scope

Supported Node migration, GHCR/GitHub Packages publication, deployment, CircleCI deletion.

---

## CI-02 — Complete Actions parity with scans and non-publishing image build

**Type**: Story
**Owning repo/system**: `y30k/staticdeploy`
**Priority**: High before CircleCI retirement
**User value**: Ensures the replacement pipeline covers repository and artifact risks without releasing anything.

### Scope

Add approved secret, dependency, source, and license scans plus service/CLI image builds that do not push. Retain evidence and triage findings.

### Acceptance criteria

- [ ] Scanners are pinned/configured and produce retained evidence.
- [ ] Findings are triaged explicitly; no silent blanket ignore is introduced.
- [ ] Service and CLI images build without registry authentication or push.
- [ ] Untrusted PRs cannot access secrets.
- [ ] Existing CI-01 checks remain passing.

### Validation

A clean PR produces scan reports and local image IDs/digests while `ghcr.io`, GitHub Packages, npm, and Docker Hub receive no artifact.

### Relationships

- blocked by: CI-01
- blocks: CI-03

### Non-scope

Dockerfile modernization, signing, SBOM/provenance publication, multi-architecture release.

---

## CI-03 — Retire CircleCI and obsolete publication integrations

**Type**: Story
**Owning repo/system**: `y30k/staticdeploy` plus GitHub/CircleCI/integration settings
**Priority**: High after verified parity
**User value**: Establishes GitHub Actions as the sole CI system without losing validated checks.

### Scope

After CI-01/02 pass and branch protection requires their stable checks, remove CircleCI configuration/references and disable its external integration. Retire Docker Hub/public npm/legacy website publication only where DEC-01 confirms no preserved consumer.

### Acceptance criteria

- [ ] Required Actions checks pass on a clean PR and are enforced by branch protection.
- [ ] `.circleci/config.yml`, CircleCI badges/docs/env coupling, and formatting exemptions are removed.
- [ ] CircleCI project/webhooks are disabled and retired credentials are revoked.
- [ ] Docker Hub/public npm/website publication is retired only according to DEC-01 dispositions.
- [ ] Repository and integration searches find no active non-Actions CI trigger.
- [ ] No replacement release or deploy workflow is introduced in this story.

### Validation

Refetch branch protection and integrations; verify a clean PR runs only required Actions checks; search repository for legacy CI references; retain redacted revocation evidence.

### Relationships

- blocked by: CI-02, DEC-01
- blocks: later supported-runtime and release-pipeline modernization

### Non-scope

Branch rename, supported runtime, GHCR/GitHub Packages release, deployment workflows.

---

## Draft queue summary

| ID | Type | Status if posted | Blocked by | Next action |
| --- | --- | --- | --- | --- |
| RUN-01 | Story | Ready | none | First implementation target: minimum dependency closure |
| DEC-01 | Task/Spike | Ready | none | Run in parallel with RUN-01 |
| RUN-02 | Story | Blocked | RUN-01 | Move Ready when scoped build passes and isolation method is available |
| QA-01 | Story | Blocked | RUN-01 | Move Ready after minimum build; owns full workspace/tests |
| CHAR-01 | Story | Blocked | RUN-01, DEC-01 | Await baseline and dispositions |
| CI-01 | Story | Blocked | QA-01, CHAR-01 | Await full baseline |
| CI-02 | Story | Blocked | CI-01 | Await Actions QA |
| CI-03 | Story | Blocked | CI-02, DEC-01 | Await parity and inventory |

## Relationship or posting notes

- All intended parent and blocked-by relationships were returned by GraphQL/REST verification.
- Every issue is present exactly once in Project 2.
- The Priority field has no options, so no priority value could be set; queue rank and native dependencies remain explicit.
- Repository Issues was enabled to support issue types, sub-issues, and native dependencies.

## Next unblocked work

1. [#2 RUN-01](https://github.com/y30k/staticdeploy/issues/2) — builds only the service/CLI dependency closure and unblocks the visible running proof without waiting on unrelated workspaces.
2. [#4 DEC-01](https://github.com/y30k/staticdeploy/issues/4) — independently reduces compatibility and retirement risk.
