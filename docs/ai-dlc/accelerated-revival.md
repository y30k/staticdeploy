# StaticDeploy Accelerated AI-DLC Plan

## Objective

Reach delivery-board readiness for the smallest safe revival slice, with a disposable running v0.15.5 build as the immediate implementation target. This is a **legacy-baseline proof**, not completion of the modernization requirements in `docs/2026.08.17-Project-Plan.md`.

## Authorization and gate exception

The user explicitly asked the agent to answer discovery questions from existing repository evidence and proceed through delivery-board readiness quickly. On that basis:

- repository evidence substitutes for an interactive discovery interview;
- the approved project plan supplies product scope and constraints;
- the accelerated PRD, design, and test strategy may progress as one planning pass;
- implementation, source changes, commits, releases, and production operations remain outside this run;
- tracker mutation is authorized by the request, but must stop if board schema, deduplication, or relationship capabilities cannot be verified.

## Scope boundary

### Immediate revival slice

1. Install the historical dependency graph with Node 14/Yarn 1 without dependency changes.
2. Compile only the service, CLI, and their workspace dependency closure.
3. Boot the integrated service inside a loopback-only execution boundary with memory storage and authentication disabled.
4. Publish and retrieve a repository-owned static fixture.
5. Record the first deterministic blocker if the minimum path fails.
6. Inventory compatibility consumers and legacy data.
7. Reproduce the complete all-workspace legacy build, focused/full tests, and QA surface.
8. Establish non-publishing GitHub Actions parity before retiring CircleCI.

### Explicitly deferred

- Claims of production security or readiness
- PostgreSQL/S3 durability for the first running proof
- Supported-runtime migration
- API v2 and modern multi-file publishing workflow
- OIDC redesign
- Dockerfile modernization and Docker Compose implementation
- Helm/Kubernetes delivery
- Registry publication
- CircleCI removal before Actions parity
- All later modernization work in the project plan

## Proxy answers to lifecycle questions

| Question | Answer derived from repository evidence |
| --- | --- |
| Who has the problem? | The maintainer reviving a previously abandoned StaticDeploy fork and future internal publishers. |
| What is the immediate problem? | The last known build is from 2021, CI is CircleCI-only, the runtime is Node 14, and no current clean build evidence exists. |
| Why can it not be solved today? | The repository has no installed dependencies, no Actions workflows, no Compose profile, and historical infrastructure/tool versions may have drifted. |
| Why now? | A running build is wanted within hours so modernization can proceed from observed behavior rather than assumptions. |
| Immediate success | The minimum service/CLI dependency closure compiles, the isolated service returns health/console responses, and a trusted fixture can be published and retrieved locally. Full-workspace/tests remain the next baseline gate. |
| Primary user | A technical maintainer operating the repository locally. |
| Non-users | Untrusted uploaders and production users; the revival proof is not exposed or production-ready. |
| MVP | Disposable local service using memory storage and `ENFORCE_AUTH=false`, with retained build/smoke evidence. |
| Key hypothesis | Reproducing the historical workspace before upgrades will expose a small, deterministic blocker set and accelerate safe modernization. |

## Accelerating decisions

| Decision | Choice | Reason |
| --- | --- | --- |
| Baseline branch | Keep `master` for the revival proof | It is the current/default branch and the release script is restricted to it. Rename only after Actions parity and branch-protection planning. |
| Baseline runtime | Node 14 plus Yarn Classic only for historical reproduction | This matches `.circleci/config.yml` and `staticdeploy/Dockerfile`; it is explicitly not the modernization target. |
| Baseline storage | Memory storage | `staticdeploy/src/components/storagesModule.ts` selects it when PostgreSQL/S3 settings are absent, minimizing dependencies. |
| Baseline auth | `ENFORCE_AUTH=false` only inside a loopback-only network namespace, container, or VM | The server has no bind-address setting and otherwise listens on all interfaces; the isolation boundary must block inbound network access. |
| Test fixture | Repository-owned fixture only | Current archive handling is not approved for untrusted content. |
| Compatibility | Preserve behavior during revival; inventory before retirement decisions | Avoids mixing modernization with reproduction. |
| Data migration | Assume greenfield only provisionally | No repo issues, PRs, or local evidence identify production data; DEC-01 must confirm. |
| Registry | No publication in revival slice; later images/charts use `ghcr.io/y30k/staticdeploy` and packages use GitHub Packages | Matches the approved project plan. |
| Observability | Health and local logs only | Eyes application ingestion remains gated; no endpoints or credentials are invented. |

## AI-DLC phase status

| Phase | Artifact/evidence | Status |
| --- | --- | --- |
| Workspace readiness | Clean working-tree inventory, auth check, repo/tool inspection | Complete with known pre-existing `.gitignore` and `docs/` changes |
| PRD | `docs/prds/staticdeploy-revival-bootstrap.prd.md` | Complete under expedited authorization |
| Technical design | `docs/technical-designs/staticdeploy-revival-bootstrap.md` | Complete under expedited authorization |
| Test strategy | `docs/test-strategies/staticdeploy-revival-bootstrap.md` | Complete under expedited authorization |
| Work-item decomposition | `docs/prd-work-items/staticdeploy-revival-bootstrap.md` | Complete; issues #1–#9 created and verified |
| Delivery-board readiness | `docs/delivery-board/staticdeploy-revival-readiness.md` | Complete; native parent/dependency relationships and statuses verified |

## Delivery-board handoff

GitHub Issues was disabled in the repository, so it was enabled as the minimum tracker prerequisite. Project 2 was empty and repository issues/PRs were empty, so no duplicate work existed.

- Parent feature: <https://github.com/y30k/staticdeploy/issues/1>
- Ready: <https://github.com/y30k/staticdeploy/issues/2> (RUN-01)
- Ready: <https://github.com/y30k/staticdeploy/issues/4> (DEC-01)
- Blocked backlog: issues #3 and #5–#9

All child issues use the native Parent issue relationship to #1. Blocked work uses GitHub's native issue dependency API, and a final refetch verified relationship direction and project status.
