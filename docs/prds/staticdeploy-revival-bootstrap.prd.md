# StaticDeploy Revival Bootstrap

## Problem Statement

The maintainer needs a trustworthy starting point for reviving a StaticDeploy fork whose last commit and release are from 2021. The repository has no current build evidence, still depends on Node 14/Yarn/Lerna-era tooling, and uses CircleCI as its only checked-in CI/CD system, so beginning with broad upgrades would hide whether failures come from age, environment drift, or modernization changes.

## Evidence

- `package.json:31-41` defines the historical compile, lint, test, Docker, and release commands through Lerna.
- `.circleci/config.yml:4-31` shows the last known QA environment: Node 14, PostgreSQL, MinIO, frozen install, compile, lint, coverage, and Codecov.
- `staticdeploy/Dockerfile:3,37-43` uses Node 14 and intentionally performs a non-frozen image install.
- `staticdeploy/src/components/storagesModule.ts:9-34` provides a memory-storage fallback when PostgreSQL/S3 configuration is incomplete.
- `staticdeploy/src/config.ts:14-31` defaults to port 3000, requires a management hostname in production, and enforces authentication unless explicitly disabled.
- `staticdeploy/test/components/expressApp.ts:88-142` already proves create-bundle, deploy, and retrieve behavior in process.
- The `y30k/staticdeploy` issue and pull-request lists are empty as observed during this run; no tracked modernization work can be reused from the repository issue tracker.

## Proposed Solution

First install the untouched v0.15.5 dependency graph and compile only the service, CLI, and their workspace dependency closure in an isolated historical runtime. Run the service inside a loopback-only network boundary with memory storage, disabled authentication, localhost management routing, and only repository-owned fixtures. Retain commands and evidence, then reproduce the complete all-workspace build/tests/legacy QA and establish non-publishing GitHub Actions parity before changing dependencies or retiring CircleCI. This separates “does the abandoned system still work?” from “is the modernized system production-ready?” and provides the fastest path to visible software.

## Key Hypothesis

We believe reproducing the historical build and publish/retrieve path before modernization will expose a small deterministic blocker set for the maintainer.
We'll know we're right when the minimum service/CLI dependency closure compiles and a trusted fixture is published and retrieved inside an isolated local boundary with retained evidence; full-workspace QA then becomes the next gate.

## What We're NOT Building

- A production-ready service — the bootstrap uses memory storage and disabled authentication.
- The modern multi-file product workflow — it remains governed by `docs/2026.08.17-Project-Plan.md`.
- Supported-runtime, React, API v2, OIDC, storage, or container modernization — mixing these into reproduction would obscure baseline behavior.
- Helm, Docker Compose, GHCR publication, release automation, or CircleCI retirement — these follow only after their prerequisites and parity evidence.
- Untrusted-content support — current archive handling is not an approved security boundary.

## Success Metrics

| Metric | Target | How Measured |
|--------|--------|--------------|
| Minimum running-path reproduction | Frozen install and scoped service/CLI dependency compile pass on the recorded commit | Command logs with commit SHA and Node/Yarn versions |
| Running proof | Health and management console return HTTP 200 | Local HTTP smoke evidence using the required management Host header |
| Domain proof | Trusted fixture can be created, deployed, and retrieved | CLI/API transcript plus response content/digest |
| Diagnostic usefulness | First deterministic blocker captured without unrelated upgrades if reproduction fails | One narrowly scoped blocker record with exact command/error |
| CI foundation | Legacy QA responsibilities are represented by non-publishing Actions checks before CircleCI retirement | Workflow evidence and parity checklist in later stories |

## Open Questions

- [ ] Does a clean Node 14/Yarn 1 frozen install still resolve every dependency from current registries? Resolve in RUN-01.
- [ ] Do any external consumers or production data exist outside this repository? Resolve in DEC-01 before compatibility retirement.
- [ ] Which supported Node LTS will be the modernization target? Decide after baseline evidence; it does not block revival.
- [x] Project 2 provides Backlog/Ready/In progress/In review/Done statuses, native Parent issue/Sub-issues, and GitHub native blocked-by dependencies; these are applied to issues #1–#9.

---

## Users & Context

**Primary User**
- **Who**: The technical maintainer reviving and modernizing this repository.
- **Current behavior**: Reads historical docs/configuration without current execution evidence.
- **Trigger**: A need for a running build within hours and an implementation-ready queue.
- **Success state**: A locally running legacy proof, explicit limitations, and small dependency-linked follow-up work.

**Job to Be Done**
When reviving this abandoned repository, I want to reproduce its last known behavior before changing it, so I can modernize from evidence and isolate failures quickly.

**Non-Users**
Nontechnical publishers and production operators are not users of the bootstrap proof. Their modern workflow remains the larger project outcome.

---

## Solution Detail

### Core Capabilities (MoSCoW)

| Priority | Capability | Rationale |
|----------|------------|-----------|
| Must | Frozen install and scoped service/CLI dependency build | Establishes whether the minimum running path is reproducible without unrelated workspace blockers. |
| Must | Network-isolated memory/no-auth boot | Minimizes dependencies while safely proving the integrated console/API/server runs. |
| Must | Trusted fixture publish/retrieve | Proves the platform's core domain path, not just process health. |
| Must | Consumer/data inventory | Prevents accidental retirement of real compatibility surfaces. |
| Should | Full all-workspace build/tests and PostgreSQL/MinIO QA parity | Required after the visible proof and before CI migration or deeper modernization. |
| Should | Non-publishing GitHub Actions parity | Establishes the future CI foundation without releasing artifacts. |
| Could | Capture duration and environment metadata in a reusable evidence script | Useful, but manual retained evidence is sufficient initially. |
| Won't | Modern product features or production deployment | Deferred to the approved modernization plan. |

### MVP Scope

RUN-01 and RUN-02: frozen historical install, scoped service/CLI dependency compile, network-isolated boot, health/console checks, trusted fixture publication/retrieval, and explicit evidence that memory state is ephemeral. Full workspace/tests are QA-01.

### User Flow

Select historical runtime → frozen install → scoped service/CLI dependency compile → enter a loopback-only execution boundary → start the service with memory/no-auth configuration → check health and console from inside the boundary → publish repository fixture → retrieve it on the content host → stop service and retain evidence → run full-workspace QA as the next gate.

---

## Technical Approach

**Feasibility**: HIGH for a disposable proof because memory storage and auth-disabled operation already exist; MEDIUM for successful dependency resolution because the graph is four years old and untested against current registries.

**Verified Existing Primitives**

| Primitive | Location | Notes |
|-----------|----------|-------|
| Workspace compile/test scripts | `package.json:31-41` | Serial Lerna commands cover all workspaces. |
| Historical QA environment | `.circleci/config.yml:4-31` | Node 14 with PostgreSQL and MinIO. |
| Service start command | `staticdeploy/package.json:16-27` | Compiles to `build/server.js` and starts in production mode. |
| Runtime defaults | `staticdeploy/src/config.ts:8-54` | Port, hostname, auth, PostgreSQL, and S3 settings. |
| Memory fallback | `staticdeploy/src/components/storagesModule.ts:9-34` | Avoids PostgreSQL/MinIO for the first proof. |
| Management/content routing | `staticdeploy/src/components/expressApp.ts:33-49` | Management API/console uses virtual host; other hosts serve deployments. |
| Existing domain smoke | `staticdeploy/test/components/expressApp.ts:88-142` | Creates a bundle, deploys it, and retrieves content. |
| Trusted demo fixture | `website/demo-static-app/` | Repository-owned static content for smoke testing. |

**Architecture Notes**
- Use the integrated `staticdeploy` process for the proof; do not split runtime components.
- Omit all PostgreSQL/S3 settings so memory storage is selected.
- Set `MANAGEMENT_HOSTNAME=localhost`, `ENFORCE_AUTH=false`, and `PORT=3000` explicitly inside a loopback-only network namespace, container, or VM. `MANAGEMENT_HOSTNAME` controls virtual-host routing, not socket binding.
- Use a separate content Host header for deployed fixture retrieval.
- Keep the current `master` branch during reproduction; branch migration is not part of the proof.

**Technical Risks**

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Historical dependencies no longer resolve | Medium | Capture the first deterministic failure; create one blocker; do not broad-upgrade. |
| Node 14 unavailable on host | High | Use an isolated historical runtime chosen by the implementation agent; record exact version. |
| Hostname mismatch gives misleading 404 | Medium | Send the management/content Host headers explicitly. |
| Auth default blocks management actions | High | Set `ENFORCE_AUTH=false` only inside a verified loopback-only execution boundary. |
| Memory mode mistaken for production evidence | Medium | Label all evidence “legacy disposable baseline”; verify restart loses state. |
| Unsafe fixture upload | Low with controls | Use repository-owned fixture only; no untrusted access. |

---

## Implementation Phases

| # | Phase | Description | Status | Parallel | Depends |
|---|-------|-------------|--------|----------|---------|
| 1 | Minimum running-path build | Frozen install and scoped service/CLI dependency compile | pending | 3 | - |
| 2 | Running domain proof | Boot and publish/retrieve trusted fixture | pending | - | 1 |
| 3 | Compatibility inventory | Identify consumers, data, and integrations | pending | 1 | - |
| 4 | Full QA parity | Reproduce legacy lint/coverage/PostgreSQL/MinIO surface | pending | 5 | 1 |
| 5 | Characterization pack | Protect approved retained behavior | pending | 4 | 1, 3 |
| 6 | Non-publishing Actions parity | Move checks to GitHub Actions without releases | pending | - | 4, 5 |
| 7 | CircleCI retirement | Remove legacy CI/CD only after verified parity | pending | - | 6 |

### Phase Details

**Phase 1: Minimum running-path build**
- **Goal**: Determine whether the v0.15.5 service and CLI dependency closure still builds unchanged.
- **Scope**: Frozen install, scoped compile, retained evidence.
- **Success signal**: Minimum commands pass or one deterministic blocker is isolated without waiting on unrelated workspaces.

**Phase 2: Running domain proof**
- **Goal**: Show the integrated service performs its core legacy workflow.
- **Scope**: Loopback-only memory/no-auth start, health, console, trusted fixture publish/retrieve.
- **Success signal**: Expected fixture content is retrieved from the content host.

**Phase 3: Compatibility inventory**
- **Goal**: Establish what can be retired safely later.
- **Scope**: API v1, CLI/image, SDK/packages, website publishing, URLs, data, integrations.
- **Success signal**: Every surface has evidence and preserve/retire disposition or a named external confirmation need.

**Phase 4: Full QA parity**
- **Goal**: Reproduce the complete legacy QA contract.
- **Scope**: Dedicated PostgreSQL/MinIO, compile, lint, tests, coverage.
- **Success signal**: Historical gates pass with retained logs or isolated blockers.

**Phase 5: Characterization pack**
- **Goal**: Protect only behavior approved for retention.
- **Scope**: Existing publish/retrieve plus routing, headers, auth denial, API error, and storage fixtures.
- **Success signal**: Tests detect intentional semantic changes.

**Phase 6: Non-publishing Actions parity**
- **Goal**: Make Actions the verified CI foundation.
- **Scope**: PR checks and scans only; no secrets, release, deploy, or publication.
- **Success signal**: Clean checkout passes stable required check names.

**Phase 7: CircleCI retirement**
- **Goal**: Eliminate the old system without a coverage gap.
- **Scope**: Config/docs/integration/credential cleanup after parity.
- **Success signal**: Only GitHub Actions can initiate CI work.

### Parallelism Notes

Compatibility inventory can proceed alongside the minimum running-path build. After RUN-01, the visible RUN-02 smoke and full QA can proceed in parallel; characterization also needs DEC-01. Actions parity waits for QA and characterization.

---

## Decisions Log

| Decision | Choice | Alternatives | Rationale |
|----------|--------|--------------|-----------|
| Revival before upgrades | Reproduce v0.15.5 unchanged | Upgrade first | Isolates environment drift from modernization regressions. |
| Baseline runtime | Node 14/Yarn 1 only for reproduction | Current host Node 24/Yarn 11 | Matches last known CI and Dockerfile. |
| Storage | Memory | PostgreSQL/MinIO immediately | Faster proof; durability is not a bootstrap claim. |
| Authentication | Disabled only inside a loopback-only execution boundary | JWT/OIDC | Avoids unrelated setup without exposing the all-interface listener unauthenticated. |
| Branch | Keep `master` during bootstrap | Rename to `main` now | Current default and release config use `master`; migration can follow CI parity. |
| Tracker model | GitHub Feature parent, Task sub-issues, native blocked-by dependencies, and project Status | Draft items or body-only dependency notes | Provides queryable relationships and truthful Ready/Backlog state. |

---

## Research Summary

**Market Context**
External market research is not decision-relevant for this bootstrap. The task is repository revival, and the existing implementation plus approved modernization plan provide the required evidence.

**Technical Context**
The repository is a 14-workspace TypeScript monorepo. It already contains memory and PostgreSQL/S3 storage modes, optional JWT/OIDC strategies, an integrated management console/API/static server, focused service tests, and a repository fixture. Current execution status is unknown, no Actions or Compose files exist, and current host tooling is Node 24/Yarn 11 rather than the historical runtime.

---

## Validation Notes

All cited file paths and symbols were verified against the codebase. Project 2 and the repository initially contained no items, issues, or PRs. Issues #1–#9 were created, added to the project, assigned native parent/dependency relationships, and refetched successfully; #2 and #4 are Ready and all dependent work remains Backlog. No build or test was run during planning.

---

*Generated: 2026-08-17*
*Status: APPROVED FOR ACCELERATED PLANNING by explicit user directive; implementation still requires an unblocked tracker item*
