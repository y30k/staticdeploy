# StaticDeploy Revival Delivery-Board Readiness

**Board**: <https://github.com/orgs/y30k/projects/2/views/1>
**Repository**: `y30k/staticdeploy`
**Mode**: updated and verified
**Source**: `docs/prd-work-items/staticdeploy-revival-bootstrap.md`

## Readiness decision

Project 2 is ready for the accelerated revival slice. The board was initially empty, repository issues and PRs were empty, and no duplicate work existed. GitHub Issues was disabled in the repository and was enabled to support issue types, sub-issues, and native dependencies.

The board now contains one parent Feature and eight Task sub-issues. Native Parent issue and blocked-by relationships were applied and refetched. Only the two issues with no blockers are Ready; every dependent issue remains Backlog.

## Next unblocked work

| Rank | Item | Repo/System | Why ready | Validation | Downstream unblocked |
| --- | --- | --- | --- | --- | --- |
| 1 | [#2 RUN-01 — Build minimum historical service/CLI dependency closure](https://github.com/y30k/staticdeploy/issues/2) | `y30k/staticdeploy` | No blocker; scoped build avoids unrelated workspace failures | Frozen install, lockfile check, scoped dependency compile, built entrypoints | #3, #5, contributes to #6 |
| 2 | [#4 DEC-01 — Inventory consumers/data/integrations](https://github.com/y30k/staticdeploy/issues/4) | `y30k/staticdeploy` plus settings | No blocker; read-only discovery can proceed independently | Every surface has evidence and a disposition | #6, #9, later migration/compatibility decisions |

#2 is the implementation priority because it has the highest probability of producing the requested running build within hours. #4 can proceed in parallel without touching source.

## Blocked work

| Item | Native blocked by | Needed action |
| --- | --- | --- |
| [#3 RUN-02 — Boot and publish/retrieve fixture](https://github.com/y30k/staticdeploy/issues/3) | #2 | Complete scoped build and provide a loopback-only namespace/container/VM with outside-denial verification |
| [#5 QA-01 — Full legacy PostgreSQL/MinIO QA](https://github.com/y30k/staticdeploy/issues/5) | #2 | Confirm minimum closure builds; provision disposable services and run complete workspace/tests |
| [#6 CHAR-01 — Minimal characterization](https://github.com/y30k/staticdeploy/issues/6) | #2, #4 | Confirm executable baseline and retained compatibility scope |
| [#7 CI-01 — Non-publishing Actions QA](https://github.com/y30k/staticdeploy/issues/7) | #5, #6 | Complete full baseline and characterization |
| [#8 CI-02 — Scans/non-publishing image build](https://github.com/y30k/staticdeploy/issues/8) | #7 | Establish Actions QA |
| [#9 CI-03 — CircleCI retirement](https://github.com/y30k/staticdeploy/issues/9) | #8, #4 | Verify parity, branch protection, consumers, and integrations |

## Relationship verification

- [#1](https://github.com/y30k/staticdeploy/issues/1) is the parent Feature.
- #2–#9 are Task sub-issues of #1.
- GitHub native issue dependencies match the intended graph.
- #2 and #4 have no blockers and are Status `Ready`.
- #1, #3, and #5–#9 are Status `Backlog`.
- Every issue appears exactly once in Project 2.
- Final REST and GraphQL refetches confirmed relationship direction, issue type, parent, and status.

## Hygiene findings

- The Project Priority field exists but has no configured options; it was left unset. Native dependencies and Status are the readiness source of truth.
- The repository is public. Enabling Issues exposes planning content and may attract issue spam or unwanted reports; current issue bodies contain no secrets or sensitive production data. Disabling Issues later would undermine the board's native relationships.
- The repository default/current branch is `master`, not `main`; keep it for baseline reproduction and treat branch migration as separate work.
- No GitHub Actions workflows or Docker Compose files currently exist.
- CircleCI remains the only checked-in CI/CD definition.
- Current host Node/Yarn versions do not match the historical baseline, so #2 needs an isolated Node 14/Yarn 1 environment.
- The service listens on all interfaces and has no bind-host setting; #3 requires a loopback-only network namespace, container, or VM and outside connection denial before disabling authentication.
- Existing working-tree changes (`.gitignore` and `docs/`) must not be reset or mixed into implementation accidentally.

## Handoff to implementation

Use `implement-prd-stories` on [#2 RUN-01](https://github.com/y30k/staticdeploy/issues/2). Run #4 in parallel only through a separate read-only tracker/discovery lane. Move #3 and #5 to Ready only after #2 genuinely satisfies its acceptance criteria; propagate every later Ready transition from the verified native dependency graph.
