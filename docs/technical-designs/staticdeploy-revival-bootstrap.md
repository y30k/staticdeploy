# StaticDeploy Revival Bootstrap Technical Design

## Inputs

- PRD/spec: `docs/prds/staticdeploy-revival-bootstrap.prd.md`
- Roadmap: `docs/2026.08.17-Project-Plan.md`
- Target repo/system: `y30k/staticdeploy`
- Approval state: expedited planning authorized by the user; implementation not started

## Summary

Install v0.15.5 unchanged in its historical Node 14/Yarn 1 environment, compile the service/CLI dependency closure, then boot the integrated service inside a loopback-only execution boundary with memory storage and authentication disabled. Prove health, console delivery, and trusted fixture publication/retrieval before reproducing the complete all-workspace PostgreSQL/MinIO QA and creating non-publishing GitHub Actions parity. Do not upgrade dependencies, alter domain contracts, publish artifacts, or remove CircleCI until baseline evidence exists.

## Codebase Findings

- `package.json:6-20,31-41` — 14 Yarn workspaces; Lerna serializes compile, lint, test, Docker, and release commands.
- `.circleci/config.yml:4-31` — historical QA used Node 14, PostgreSQL, MinIO, frozen install, compile, lint, coverage, and Codecov.
- `staticdeploy/package.json:16-27` — service compiles TypeScript to `build/` and starts `build/server.js` in production mode.
- `staticdeploy/src/config.ts:8-54` — production requires `MANAGEMENT_HOSTNAME`; port defaults to 3000; auth defaults on; PostgreSQL/S3 settings are optional.
- `staticdeploy/src/components/storagesModule.ts:9-34` — any incomplete PostgreSQL/S3 configuration selects `MemoryStorages`.
- `staticdeploy/src/components/authenticationStrategies.ts:8-30` — JWT and OIDC strategies are optional and created only when configured.
- `staticdeploy/src/components/expressApp.ts:33-49` — the management router is mounted by virtual host; all other hosts use the static server.
- `staticdeploy/src/components/managementRouter.ts:17-54` — the integrated process serves the compiled management console and `/api`.
- `staticdeploy/test/components/expressApp.ts:88-142` — existing test creates a bundle, deploys it, and retrieves it from another hostname.
- `pg-s3-storages/test/index.ts:13-58` — full storage tests require dedicated localhost PostgreSQL/MinIO and perform destructive cleanup.
- `staticdeploy/Dockerfile:3,37-59` — the current image uses Node 14, non-frozen installs, one build/runtime stage, and root execution; it is not the first reproduction target.
- `website/demo-static-app/` — repository-owned smoke fixture.

## Decisions

| Decision | Choice | Alternatives | Rationale | Reversible? |
| --- | --- | --- | --- | --- |
| First execution target | Workspace process, not existing Dockerfile | Build image first | Frozen root install is a better reproducibility signal than the Dockerfile's intentional non-frozen install. | Yes |
| Runtime | Exact Node 14.x/Yarn 1.x recorded at execution | Current Node 24/Yarn 11 | Matches historical CI; avoids accidental migration. | Yes; bootstrap-only |
| Storage | Memory mode | PostgreSQL/MinIO | Removes two infrastructure dependencies from the first running proof. | Yes |
| Authentication | Disabled only inside a loopback-only network namespace, container, or VM | JWT/OIDC | The server listens on all interfaces and has no bind-host setting; an external isolation boundary is mandatory. | Yes |
| Routing | `localhost` management host plus explicit content Host inside the boundary | Historical public DNS | Avoids DNS assumptions and follows current vhost implementation. | Yes |
| Fixture | Repository-owned static fixture | User-supplied upload | Current archive path is not approved for untrusted content. | Yes |
| Failure handling | Stop at first deterministic blocker | Opportunistic broad upgrades | Keeps diagnosis bounded and creates an implementation-ready blocker. | Yes |
| CI migration | Baseline parity before modernization or CircleCI removal | Upgrade runtime in CI first | Preserves a reference behavior and avoids a test-coverage gap. | Yes |
| Branch | Keep `master` during baseline | Rename immediately | Current default/release script use `master`; branch migration does not help reproduction. | Yes |

## Proposed Architecture

### Bootstrap runtime

```text
Browser/curl/CLI
  | management Host: localhost
  | content Host: smoke.local
  v
single staticdeploy Node process
  |- management console
  |- management API
  |- static content server
  |- memory metadata/artifact stores
  `- no authentication strategy; enforcement disabled
```

This architecture is intentionally disposable. It proves current composition and domain behavior only.

### Evidence flow

```text
record commit + Node/Yarn versions
  -> frozen install
  -> compile service + CLI dependency closure
  -> enter verified loopback-only boundary
  -> start service with no auth
  -> health + console smoke from inside boundary
  -> bundle trusted fixture
  -> deploy fixture to content host
  -> retrieve expected content
  -> stop/restart and confirm ephemeral state
  -> retain logs or first deterministic blocker
  -> continue separately to complete all-workspace build/tests in QA-01
```

### Follow-on CI parity

```text
Pull request
  -> GitHub Actions, contents:read
  -> frozen install on historical baseline
  -> compile + lint + tests/coverage with disposable PostgreSQL/MinIO
  -> scans + non-publishing image build
  -> retained evidence
```

No workflow receives publication or deployment credentials during the bootstrap scope.

## API, Data, and Contract Changes

- Bootstrap API changes: none.
- Bootstrap schema changes: none.
- Bootstrap storage changes: none; use existing memory implementation.
- Compatibility: preserve current API v1, CLI, management console, and static-serving behavior for reproduction.
- Migration/backfill: none.
- Test fixture contract:
  - management health returns 200 with `Host: localhost`;
  - management console returns 200 with `Host: localhost`;
  - trusted fixture is created/deployed through existing CLI/API;
  - content retrieval uses a separate explicit Host and matches fixture content;
  - process restart loses deployment state in memory mode.

If the minimum dependency install or scoped compile fails, the only permitted change in RUN-01 is diagnostic evidence. A separate blocker story owns any source or dependency fix. Unrelated workspace failures are deferred to QA-01 and do not block attempting RUN-02.

## Security, Privacy, and Permissions

- Run inside a loopback-only network namespace, container, or VM with no routable inbound interface. `MANAGEMENT_HOSTNAME=localhost` does not bind the listening socket.
- Execute the service and every smoke client inside that same boundary, and verify a client outside the boundary cannot connect.
- Set `ENFORCE_AUTH=false` only inside this disposable boundary.
- Do not supply production credentials, cookies, OIDC configuration, PostgreSQL URLs, or S3 keys.
- Use only repository-owned fixture content.
- Do not expose the service to untrusted networks or uploaders.
- Treat current tar extraction as untrusted-content unsafe until the modernization security work is implemented.
- GitHub Actions bootstrap checks use `contents: read`, no publishing permissions, no production environments, and no secrets for untrusted pull requests.
- Full storage tests must target disposable PostgreSQL/MinIO because cleanup is destructive.

## Performance and Reliability

Performance is not a bootstrap gate. Record command durations to identify pathological install/build behavior, but do not optimize until reproduction is known.

Failure modes and handling:

| Failure | Handling |
| --- | --- |
| Frozen dependency resolution fails | Retain first deterministic package/error and create one blocker; do not regenerate lockfile. |
| Scoped compile fails | Retain first required package/error and environment versions; isolate fix in blocker. |
| Unrelated workspace compile/test fails | Record under QA-01; do not block the already-built service smoke. |
| Isolation boundary is unavailable | Do not run the no-auth process; choose another loopback-only namespace/container/VM method. |
| Management requests return 404 | Verify required Host header before treating as code failure. |
| Management actions return unauthorized | Verify localhost-only `ENFORCE_AUTH=false`. |
| Fixture retrieval returns 404 | Verify deploy succeeded and content Host matches entrypoint. |
| State survives restart unexpectedly | Verify PostgreSQL/S3 variables were omitted and logs selected `MemoryStorages`. |
| Full tests corrupt data | Prevent by requiring disposable service endpoints and explicit preflight. |

## Rollout, Rollback, and Observability

### Rollout

1. Run RUN-01 in an isolated historical runtime without changing tracked files.
2. If successful, run RUN-02 locally and retain evidence.
3. Reproduce full QA with disposable PostgreSQL/MinIO.
4. Add non-publishing Actions checks.
5. Remove CircleCI only after parity, branch protection, and external integration review.

### Rollback

- Bootstrap runtime: stop the process; memory state is discarded.
- CI changes: revert the workflow change while CircleCI remains available.
- CircleCI retirement: only occurs in a separate story after Actions parity; rollback restores the last verified config and integration if retirement validation fails.

### Observability

- Use existing local structured logs and health endpoint only.
- Retain command output, process logs, HTTP status, and fixture-response evidence as artifacts.
- Do not add OTLP, Faro, Matomo, dashboards, or alerts during bootstrap. Eyes application ingestion remains gated and no endpoint or credential may be invented.

## Validation Strategy

- Environment evidence: commit SHA, architecture, Node version, Yarn version.
- Reproducibility: frozen install with no lockfile change.
- Minimum build: `yarn lerna run compile --scope=@staticdeploy/staticdeploy --scope=@staticdeploy/cli --include-dependencies --stream --concurrency 1`.
- Network safety: prove the no-auth listener is reachable from inside but unreachable from outside the loopback-only boundary.
- Runtime smoke: management health and console with explicit Host from inside the boundary.
- Full baseline after smoke: `yarn compile`, `yarn lint`, and `npm run coverage` in QA-01.
- Domain smoke: trusted fixture bundle/deploy/retrieve.
- Ephemeral-mode proof: restart and verify deployment absence plus memory-storage log.
- Full QA follow-on: compile, lint, coverage/tests against disposable PostgreSQL/MinIO.
- CI parity: same commands on a clean checkout, retained evidence, no publication.

Detailed mapping is in `docs/test-strategies/staticdeploy-revival-bootstrap.md`.

## Dependencies and Story Seeds

| Seed | Repo/System | Depends On | Notes |
| --- | --- | --- | --- |
| RUN-01 Build minimum service/CLI dependency closure | `y30k/staticdeploy` | None | First implementation target; unrelated workspaces do not block RUN-02. |
| RUN-02 Boot and publish/retrieve fixture | `y30k/staticdeploy` | RUN-01 | First visible running proof. |
| DEC-01 Inventory consumers and data | `y30k/staticdeploy` plus external evidence | None | Can run parallel to RUN-01. |
| QA-01 Reproduce full legacy QA | `y30k/staticdeploy` | RUN-01 | Requires disposable PostgreSQL/MinIO. |
| CHAR-01 Add minimal approved characterization | `y30k/staticdeploy` | RUN-01, DEC-01 | Protect only retained behavior. |
| CI-01 Add non-publishing Actions QA | `y30k/staticdeploy` | QA-01, CHAR-01 | Keep historical toolchain initially. |
| CI-02 Add scans/non-publishing image check | `y30k/staticdeploy` | CI-01 | No registry credentials. |
| CI-03 Retire CircleCI | `y30k/staticdeploy` plus GitHub integration | CI-01, CI-02, compatibility decisions | External webhook/credential cleanup required. |

## Verification Notes

- Verified: all cited repository paths and runtime selection behavior.
- Verified: `master` is the current and remote default branch; `package.json:40` restricts release to `master`.
- Verified: repository issue list contains zero items and PR list contains zero items at review time.
- Unverified/TBD: clean Node 14/Yarn 1 install/build/test result; implementation must produce evidence.
- Unverified/TBD: external consumers, data, webhooks, and CircleCI project state; DEC-01/CI-03 must verify.
- Verified: Project 2 statuses, Feature/Task issue types, parent/sub-issue support, and native blocked-by dependencies; issues #1–#9 were refetched with the intended relationships.

## Risks and Open Questions

- Historical dependency availability or required dependency compile may block RUN-01 — capture first deterministic blocker.
- No application bind-host option exists — RUN-02 must prove an external loopback-only isolation boundary before disabling auth.
- Exact Node 14/Yarn 1 patch versions are not pinned in the repo — record selected versions and avoid claiming byte-for-byte build reproducibility.
- The demo fixture's exact CLI flags must be confirmed from the built CLI before execution — use existing tests as fallback API proof.
- Project Priority exists but has no configured options — use native dependency readiness plus Status as the source of truth until board owners configure priority options.
