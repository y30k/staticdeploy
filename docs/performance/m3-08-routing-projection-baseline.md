# M3-08 routing projection performance baseline

Status: **accepted local initial baseline**

Measured: 2026-08-19

Scope: M3-08 publication queue, routing projection reconciliation, key
retirement, and content refresh. This is a repeatable local regression check,
not a production SLO. Production capacity remains **B-PG**; provider
object-store latency, conditional semantics, and version/audit behavior remain
**B-S3**; production key delivery remains **B-DEPLOY**.

## Reproduce

Use the repository-pinned Node binary and dedicated disposable loopback
resources. The database name must begin with `m308bench`; the benchmark resets
its `public` schema and removes its unique MinIO bucket.

```sh
export PATH="$HOME/.nvm/versions/node/v24.19.0/bin:$PATH"
M308_BENCHMARK_ALLOW_RESET=1 \
POSTGRES_BENCHMARK_URL='postgres://<test-user>:<test-password>@127.0.0.1:<port>/m308benchbaseline' \
MINIO_BENCHMARK_URL='http://127.0.0.1:<port>' \
MINIO_BENCHMARK_ACCESS_KEY='<disposable-admin-access-key>' \
MINIO_BENCHMARK_SECRET_KEY='<disposable-admin-secret-key>' \
M308_BENCHMARK_OUTPUT='/tmp/m308-benchmark.json' \
corepack yarn benchmark:m3-08
```

The script first compiles the current `@staticdeploy/pg-s3-storages` workspace
and only then dynamically loads its ignored `lib/` output; compilation failure
stops the run before any fixture reset. It fails closed on the wrong
Node/PostgreSQL major, non-loopback URLs, a non-dedicated database name, absent
reset acknowledgement, invalid result identity, missing required plan indexes,
budget regression, or any cleanup failure. It attempts all cleanup actions
before failing and never writes a `PASSED` report when cleanup fails. No
credentials are retained. `corepack yarn test:m3-08-benchmark` exercises the
result, disjointness, object-source, and plan contracts without services.

## Candidate and retained evidence

The accepted raw report, including samples and full
`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` plans, is retained at
[`evidence/m3-08-routing-projection-baseline.json`](evidence/m3-08-routing-projection-baseline.json).
It binds source HEAD `2506916153689b1b5acdacbb72a6cebd50cc37b2`, tested staged
tree `ef13182ba43a973f7a0f15d17c0b2573698566b0`, and SHA-256 digests for the
migration, projection runtime/test, benchmark/contract test, MinIO policy
fixture, and the executed compiled index/projection/migration artifacts. Adding
this evidence file changes the final Git tree but not any tested executable
artifact; artifact digests provide the non-recursive exact-candidate binding.

## Environment and inputs

- Node `24.19.0`; PostgreSQL `16.14` (`shared_buffers=128MB`, `work_mem=4MB`,
  `effective_cache_size=4GB`, `random_page_cost=4`, JIT enabled).
- Linux x64; 6 × Intel Xeon Gold 6140 logical CPUs; 16,771,915,776 bytes memory.
- Disposable loopback MinIO returned healthy with `Server: MinIO`; its version
  was unavailable from the safe unauthenticated health response and is recorded
  as such rather than invented.
- 10,000 outbox rows: 50% due pending, 15% future pending, 15% expired leased,
  10% live leased, 5% acknowledged current, and 5% acknowledged historical.
- Terminal-state rows are seeded with USER triggers disabled only inside the
  benchmark transaction; foreign keys and CHECK constraints remain active, and
  triggers are restored before `ANALYZE` and every measurement.
- Key-retirement fixture has 600 active/current references and 500 acknowledged
  historical references that must not block retirement.
- Reconciliation deterministically selects application ordinal 1 with desired
  generation 2, served generation 0, no desired-generation outbox row, and one
  stale `PENDING` generation 1 row. Every sample asserts `superseded_count = 1`
  from the exact production correlated scan.
- Claims: 5 warmups/20 samples for pending batch 1/100, expired batch 100, and
  mixed pending/expired batch 100. Concurrent claims use 8 independent clients,
  3 warmups/15 samples, 100 rows each, with exact 800-row disjointness checks.
- Content: 5 warmups/25 samples with a maximum 1,024-file valid manifest
  (1,073,293 bytes) and 1,035-byte signed routing document.

## Accepted baseline results

| Path                                 | Iterations |  min ms |  p50 ms |  p95 ms |  max ms | mean ms | p95 budget |
| ------------------------------------ | ---------: | ------: | ------: | ------: | ------: | ------: | ---------: |
| Pending claim batch 1                |         20 |  55.285 |  55.973 |  58.066 |  64.483 |  56.771 |     100 ms |
| Pending claim batch 100              |         20 |  88.315 |  90.469 |  93.366 |  95.409 |  90.831 |     200 ms |
| Expired-lease claim batch 100        |         20 |  64.954 |  67.021 |  69.885 |  70.668 |  67.200 |     200 ms |
| Mixed pending/expired batch 100      |         20 |  67.492 |  68.616 |  71.217 |  78.895 |  69.345 |     200 ms |
| 8 concurrent batch-100 claimers      |         15 | 154.903 | 163.093 | 181.436 | 181.436 | 164.503 |     400 ms |
| `assertKeyRetirable` query           |         20 |   8.681 |   8.741 |  10.025 |  10.079 |   8.904 |      20 ms |
| Reconciliation database query        |         20 |   1.122 |   1.266 |   1.387 |   1.387 |   1.263 |      10 ms |
| Content refresh, 1,024-file manifest |         25 |  70.590 |  73.152 |  92.799 |  92.839 |  76.415 |     200 ms |

Content refresh process RSS rose by **56,266,752 bytes**, below the initial
**201,326,592-byte (192 MiB)** delta budget. This process-level sentinel
includes Node/V8 retained allocation and is not a live-heap claim.

## Query plans

| Query                               | Root/access                         | Planning ms | Execution ms | Shared hits | Required evidence                                  |
| ----------------------------------- | ----------------------------------- | ----------: | -----------: | ----------: | -------------------------------------------------- |
| Dense due claim, limit 100          | `Limit`; sequential scans/hash join |       0.663 |       24.537 |       2,728 | Dense 50%-due scan is expected                     |
| Key retirement                      | aggregate; bitmap index             |       0.910 |        9.467 |         614 | `v2_outbox_routing_kid_active_idx`                 |
| Reconciliation with superseded scan | nested loop plus indexed subplan    |       0.385 |        0.174 |          56 | `v2_publication_outbox_application_generation_idx` |

The initial per-row claim implementation measured roughly 6.5 seconds p95 for
batch 100 and 16.1 seconds for concurrent claimers. Set-based pending and
expired claims reduce accepted p95 to 93.366 ms and 181.436 ms while preserving
selected priority, fencing, exact limits, and `SKIP LOCKED` disjointness. The
retirement plan justified `v2_outbox_routing_kid_active_idx`.

## Future comparison

Run on the exact staged candidate after compiling with Node 24.19.0. Use the
same dataset, warmups, and iterations, compare p95/RSS to checked-in budgets,
and inspect retained plans when access strategy changes. Raising a budget
requires a reviewed new baseline and operational justification. Production
acceptance still requires B-PG/B-S3/B-DEPLOY evidence.
