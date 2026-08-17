# StaticDeploy Revival Bootstrap Test Strategy

## Scope

- Sources:
  - `docs/prds/staticdeploy-revival-bootstrap.prd.md`
  - `docs/technical-designs/staticdeploy-revival-bootstrap.md`
  - `docs/2026.08.17-Project-Plan.md`
- Target repo/system: `y30k/staticdeploy`
- Target release: disposable legacy baseline plus non-publishing CI parity
- Gate status: approved for accelerated planning; execution evidence not yet available

## Existing Validation Inventory

- `package.json:31-41` — `yarn compile`, `yarn lint`, `yarn test`, and `npm run coverage` aggregate workspace checks through Lerna.
- `staticdeploy/package.json:16-27` — service compile, lint, focused Mocha test, and start commands.
- `staticdeploy/test/components/expressApp.ts:88-142` — in-process create/deploy/retrieve test, including trailing-dot host behavior and missing-entrypoint 404.
- `pg-s3-storages/test/index.ts:13-58` — storage integration against dedicated localhost PostgreSQL and MinIO; cleanup is destructive.
- `.circleci/config.yml:4-31` — historical gate sequence and service dependencies.
- `website/demo-static-app/` — trusted smoke fixture with `/index.html` fallback.
- `staticdeploy/src/config.ts:14-31` — management Host, port, and auth configuration needed for runtime smoke.
- `staticdeploy/src/components/storagesModule.ts:9-34` — memory-storage selection to verify in logs and restart behavior.

## Validation Matrix

| Requirement/Story | Risk | Acceptance Criteria | Test Level | Command/Method | Preconditions/Data/Env | Expected Evidence | Gate? |
| --- | --- | --- | --- | --- | --- | --- | --- |
| RUN-01 frozen install | Registry/tool drift | Install succeeds and `yarn.lock` is unchanged | Reproducibility | `yarn install --frozen-lockfile`; `git diff --exit-code -- yarn.lock` | Isolated Node 14.x, Yarn 1.x, network; record exact versions | Install log, versions, unchanged lockfile | Yes — RUN-01 |
| RUN-01 scoped compile | Required service/CLI dependency breakage | The service, CLI, and their workspace dependency closure compile | Build | `yarn lerna run compile --scope=@staticdeploy/staticdeploy --scope=@staticdeploy/cli --include-dependencies --stream --concurrency 1` | Frozen install complete | Exit 0 and required package output | Yes — RUN-01 |
| RUN-01 failure handling | Broad upgrades obscure cause | First deterministic failure is captured without source/lockfile mutation | Manual evidence | Stop after first reproducible error; rerun once to confirm determinism | Any failed RUN-01 command | Command, error, versions, affected package, rerun result | Yes on failure |
| RUN-02 isolation | No-auth server listens on all interfaces | Inside-boundary client can connect; outside-boundary client cannot | Security/runtime | Run service and smoke clients in a loopback-only network namespace, container, or VM; probe from outside before any management action | Verified boundary with no routable inbound interface | Boundary method, inside success, outside connection failure | Yes — RUN-02 |
| RUN-02 boot | Runtime config/vhost mismatch | Process starts and logs `MemoryStorages` | Runtime smoke | Inside the boundary: `MANAGEMENT_HOSTNAME=localhost ENFORCE_AUTH=false PORT=3000 yarn --cwd staticdeploy start` | RUN-01 passed; omit all PG/S3 variables | Startup log and storage-selection line | Yes — RUN-02 |
| RUN-02 health | Wrong Host returns misleading 404 | Management health returns 200 | HTTP smoke | Inside the boundary: `curl -fsS -H 'Host: localhost' http://127.0.0.1:3000/api/health` | Service running | Status/body evidence | Yes — RUN-02 |
| RUN-02 console | Console build or routing broken | `/` on management Host returns 200 and HTML | HTTP smoke | `curl -fsS -D - -H 'Host: localhost' http://127.0.0.1:3000/` | Service running | Headers and recognizable HTML | Yes — RUN-02 |
| RUN-02 fixture bundle | CLI/API path broken | Repository fixture is accepted as bundle | System smoke | `STATICDEPLOY_API_URL=http://localhost:3000/api node cli/bin/staticdeploy.js bundle --from website/demo-static-app --name smoke --tag baseline --description 'legacy baseline'` | Built CLI; service running; repository fixture only | CLI exit 0/output | Yes — RUN-02 |
| RUN-02 fixture deploy | Entrypoint update broken | Bundle deploys to `smoke.local/` | System smoke | `STATICDEPLOY_API_URL=http://localhost:3000/api node cli/bin/staticdeploy.js deploy --app smoke --entrypoint smoke.local/ --bundle smoke:baseline` | Bundle created | CLI exit 0/output | Yes — RUN-02 |
| RUN-02 fixture retrieve | Static serving broken | Content Host returns expected fixture HTML | System smoke | `curl -fsS -H 'Host: smoke.local' http://127.0.0.1:3000/` and compare a stable fixture marker | Deployment complete | Response/digest or stable marker | Yes — RUN-02 |
| RUN-02 ephemeral proof | Memory mode misrepresented as durable | After restart, fixture retrieval returns entrypoint-not-found while health still passes | Reliability smoke | Stop/start same command; repeat health and content requests | No PG/S3 env variables | Health 200; content 404; memory log | Yes — RUN-02 |
| DEC-01 inventory | Unknown consumers cause accidental breakage | Every legacy surface has evidence and preserve/retire/unknown disposition | Manual/repository/external | Search code, package metadata, repo settings, docs, integrations; record unavailable external checks | Read access to repo/settings; external confirmation as needed | Completed inventory table | Yes before retirement |
| QA-01 full legacy QA | Focused test misses storage failures | Compile, lint, and coverage/tests pass against disposable services | Integration | `yarn compile`; `yarn lint`; `npm run coverage` | Dedicated disposable PostgreSQL and MinIO matching test endpoints; never valued data | Logs and coverage | Yes — QA-01 |
| CHAR-01 retained behavior | Modernization changes semantics silently | Approved behaviors have deterministic tests | Characterization | Existing package commands plus added focused fixtures in later implementation | DEC-01 disposition | Test names and pass output | Yes before toolchain changes |
| CI-01 Actions parity | CI differs from local baseline | Clean checkout performs approved baseline commands with no publication | CI | GitHub Actions check run | Pinned actions; service containers; `contents: read`; no publish secrets | Run URL/artifacts/check names | Yes before CircleCI retirement |
| CI-02 scans/build check | Security or image failures are invisible | Scans and non-publishing image build retain triaged evidence | CI/security | Repository-approved scanners plus image build without push | CI-01 | Reports/digests; triage record | Yes before CircleCI retirement |
| CI-03 retirement | Delivery gap or duplicate publishers | Actions remains green; CircleCI cannot trigger; credentials/webhooks removed | Integration/manual | Repository/integration review and clean PR check | CI-01/02 passing; project settings access | Screenshots/API evidence and repo search | Yes — CI-03 |

## Nonfunctional Checks

| Area | Needed? | Check | Baseline/Budget | Notes |
| --- | --- | --- | --- | --- |
| Security | Yes | Loopback-only execution boundary with outside connection denial, no production credentials, trusted fixture only, no publish permissions in CI | Zero routable exposure | `MANAGEMENT_HOSTNAME` is not a bind address; bootstrap makes no production-security claim. |
| Reliability | Yes | Process restart, memory-state loss, deterministic blocker rerun | Health recovers after restart | Durability intentionally deferred. |
| Performance | Record only | Install/compile/test/start durations | No pass/fail budget | Use data to prioritize later; do not optimize bootstrap. |
| Compatibility | Yes | Node/Yarn/architecture/commit recorded; approved API/static behavior characterized | Exact environment retained with evidence | Baseline runtime is EOL and temporary. |
| Accessibility | No bootstrap gate | Console only needs to render for running proof | Deferred | Modern portal has separate WCAG requirement. |
| Migration/rollback | Limited | No schema changes; stop process to roll back | No persistent state | CI changes remain reversible until CircleCI retirement. |
| Observability | Limited | Health, local structured logs, command output | No Eyes ingestion | Product ingestion remains gated. |
| Privacy | Yes | No production or personal data | Zero sensitive data | Use repository fixture only. |

## Missing Harnesses or Blockers

- Node 14/Yarn 1 is not the current host runtime (`node v24`, `yarn 11` observed) — RUN-01 implementation must choose an isolated historical runtime and record exact versions.
- No current dependency/build result — RUN-01 is the first executable evidence.
- The application has no bind-host configuration and listens on all interfaces — RUN-02 requires a loopback-only network namespace, container, or VM and an outside-denial probe.
- No Docker Compose file — irrelevant to RUN-01/RUN-02; create only in the later deployment story.
- Full storage tests require dedicated PostgreSQL/MinIO and are destructive — QA-01 must provision disposable instances and preflight endpoints.
- No execution evidence exists yet — tracker setup is complete, with RUN-01 (#2) and DEC-01 (#4) Ready.
- External CircleCI/webhook/credential state is not visible from repository files — CI-03 needs settings-level evidence.

## Recommended Story/Test Work

- RUN-01 — execute and retain historical build evidence.
- RUN-02 — execute local runtime and domain smoke.
- QA-01 — provision disposable PG/MinIO and reproduce historical QA.
- CHAR-01 — add only approved missing characterization tests.
- CI-01 — encode baseline checks in non-publishing Actions.
- CI-02 — add scans and image build-without-push.
- CI-03 — verify and retire CircleCI after parity.

## Test Strategy Summary

**Recommended immediate gate set**:

```bash
node --version
yarn --version
git rev-parse HEAD
yarn install --frozen-lockfile
git diff --exit-code -- yarn.lock
yarn lerna run compile --scope=@staticdeploy/staticdeploy --scope=@staticdeploy/cli --include-dependencies --stream --concurrency 1
```

Then create and verify the loopback-only execution boundary and run the health/console plus trusted fixture bundle/deploy/retrieve/restart sequence inside it. QA-01 separately runs the complete all-workspace compile, lint, and coverage/tests.

**Blockers**: no execution evidence yet; RUN-02 and later items are blocked by verified native issue dependencies.

**New work items needed**: RUN-01, RUN-02, DEC-01, QA-01, CHAR-01, CI-01, CI-02, CI-03.

**Next**: implement RUN-01 (#2) first and run DEC-01 (#4) in parallel; move dependents to Ready only after their native blockers close or are explicitly waived.
