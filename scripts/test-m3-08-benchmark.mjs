import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";

import {
    assertClaimRows,
    assertConcurrentClaims,
    assertObjectRefresh,
    assertReconciliationRow,
    assertRequiredPlans,
    metric,
    runCleanupSteps,
} from "./m3-08-benchmark-contract.mjs";

const require = createRequire(import.meta.url);
execFileSync(
    "corepack",
    ["yarn", "workspace", "@staticdeploy/pg-s3-storages", "compile"],
    { cwd: process.cwd(), env: process.env, stdio: "inherit" }
);
const {
    v2ProjectionReconciliationSql,
} = require("../pg-s3-storages/lib/V2RoutingProjection.js");
const normalizeSql = (value) =>
    value
        .replace(/\?|\$1/g, "$PARAM")
        .replace(/\s+/g, " ")
        .trim();
assert.equal(
    normalizeSql(v2ProjectionReconciliationSql("?")),
    normalizeSql(v2ProjectionReconciliationSql("$1")),
    "Knex and pg must execute one normalized reconciliation query"
);
assert.match(
    v2ProjectionReconciliationSql("?"),
    /superseded_count/,
    "shared reconciliation query must retain superseded-operation detection"
);
assert.throws(
    () => v2ProjectionReconciliationSql(":applicationId"),
    /unsupported reconciliation SQL placeholder/
);

const id = (value) =>
    `00000000-0000-4000-8000-${String(value).padStart(12, "0")}`;
const row = (value, owner, attempt = 1, version = 1) => ({
    id: id(value),
    state: "LEASED",
    lease_owner: owner,
    attempt_count: attempt,
    lease_version: version,
    next_attempt_at: null,
});

assert.deepEqual(metric([4, 1, 3, 2]), {
    iterations: 4,
    minMs: 1,
    p50Ms: 2,
    p95Ms: 4,
    maxMs: 4,
    meanMs: 2.5,
});
const pendingIds = assertClaimRows([row(1, "pending"), row(2, "pending")], {
    count: 2,
    owner: "pending",
    identityFor: () => ({ attemptCount: 1, leaseVersion: 1 }),
});
assert.equal(pendingIds.size, 2);
for (const invalid of [
    [row(1, "wrong")],
    [row(1, "pending"), row(1, "pending")],
    [row(1, "pending", 2, 1)],
    [],
]) {
    assert.throws(() =>
        assertClaimRows(invalid, {
            count: 1,
            owner: "pending",
            identityFor: () => ({ attemptCount: 1, leaseVersion: 1 }),
        })
    );
}
const claims = Array.from({ length: 8 }, (_, client) => ({
    owner: `concurrent-${client}`,
    rows: Array.from({ length: 100 }, (_, offset) =>
        row(client * 100 + offset + 1, `concurrent-${client}`)
    ),
}));
assert.equal(assertConcurrentClaims(claims, 100).size, 800);
claims[1].rows[0] = claims[0].rows[0];
assert.throws(
    () => assertConcurrentClaims(claims, 100),
    /wrong lease owner|overlapping/
);
assert.equal(assertObjectRefresh({ source: "OBJECT" }).source, "OBJECT");
assert.throws(
    () => assertObjectRefresh({ source: "LAST_KNOWN_GOOD" }),
    /verified object storage/
);
const reconciliationApplicationId = id(9999);
assert.equal(
    assertReconciliationRow(
        {
            id: reconciliationApplicationId,
            desired_generation: "2",
            served_generation: "0",
            outbox_id: null,
            superseded_count: "1",
        },
        reconciliationApplicationId
    ).superseded_count,
    "1"
);
for (const invalid of [
    { desired_generation: "1" },
    { served_generation: "1" },
    { outbox_id: id(1) },
    { superseded_count: "0" },
])
    assert.throws(
        () =>
            assertReconciliationRow(
                {
                    id: reconciliationApplicationId,
                    desired_generation: "2",
                    served_generation: "0",
                    outbox_id: null,
                    superseded_count: "1",
                    ...invalid,
                },
                reconciliationApplicationId
            ),
        /superseded-count contract/
    );
assert.doesNotThrow(() =>
    assertRequiredPlans({
        keyRetirable: { indexes: ["v2_outbox_routing_kid_active_idx"] },
        reconciliation: {
            indexes: ["v2_publication_outbox_application_generation_idx"],
        },
    })
);
assert.throws(
    () =>
        assertRequiredPlans({
            keyRetirable: { indexes: [] },
            reconciliation: { indexes: [] },
        }),
    /required index/
);
const cleanupOrder = [];
const cleanupErrors = await runCleanupSteps([
    {
        label: "first",
        operation: async () => {
            cleanupOrder.push("first");
            throw new Error("controlled");
        },
    },
    {
        label: "second",
        operation: async () => cleanupOrder.push("second"),
    },
]);
assert.deepEqual(cleanupOrder, ["first", "second"]);
assert.equal(cleanupErrors.length, 1);
assert.match(cleanupErrors[0].message, /first: controlled/);

const source = await readFile(
    new URL("./benchmark-m3-08-routing-projection.mjs", import.meta.url),
    "utf8"
);
for (const required of [
    'const EXPECTED_NODE = "v24.19.0"',
    "const ROWS = 10_000",
    "M308_BENCHMARK_ALLOW_RESET",
    "POSTGRES_BENCHMARK_URL",
    "MINIO_BENCHMARK_URL",
    "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)",
    'residualGates: ["B-PG", "B-S3", "B-DEPLOY"]',
    "sourceHead",
    "stagedTree",
    "artifactDigests",
    '"scripts/test-m3-08-benchmark.mjs"',
    "assertConcurrentClaims",
    "assertReconciliationRow",
    'v2ProjectionReconciliationSql("$1")',
    "assertRequiredPlans",
    "cleanupErrors",
    '"corepack"',
    '"@staticdeploy/pg-s3-storages", "compile"',
    '"pg-s3-storages/lib/index.js"',
    '"pg-s3-storages/lib/V2RoutingProjection.js"',
    '"pg-s3-storages/lib/migrations/08.js"',
])
    assert.ok(
        source.includes(required),
        `benchmark contract missing ${required}`
    );
const compileAt = source.indexOf(
    '["yarn", "workspace", "@staticdeploy/pg-s3-storages", "compile"]'
);
const runtimeLoadAt = source.indexOf(
    'require("../pg-s3-storages/lib/V2RoutingProjection.js")'
);
assert.ok(compileAt >= 0, "benchmark must compile the current workspace");
assert.ok(
    runtimeLoadAt > compileAt,
    "benchmark must load compiled runtime only after compilation succeeds"
);
assert.doesNotMatch(
    source.slice(0, source.indexOf("async function main()")),
    /require\(["']\.\.\/pg-s3-storages\/lib\//,
    "benchmark must not load ignored lib output at module initialization"
);
assert.doesNotMatch(source, /process\.env\.(?:AWS|PG|POSTGRES)PASSWORD/);
assert.match(source, /database must start with m308bench/);
assert.match(source, /must be loopback-only/);
assert.match(source, /DROP SCHEMA IF EXISTS public CASCADE/);

const retained = JSON.parse(
    await readFile(
        new URL(
            "../docs/performance/evidence/m3-08-routing-projection-baseline.json",
            import.meta.url
        ),
        "utf8"
    )
);
assert.equal(retained.status, "PASSED");
assert.deepEqual(retained.dataset.reconciliationFixture, {
    applicationOrdinal: 1,
    desiredGeneration: 2,
    servedGeneration: 0,
    stalePendingGeneration: 1,
    expectedSupersededCount: 1,
});
assert.equal(retained.metrics.reconciliationQuery.summary.iterations, 20);
assert.ok(
    retained.metrics.reconciliationQuery.summary.p95Ms <=
        retained.budgetsMs.reconciliationQueryP95
);
assert.ok(
    retained.plans.reconciliation.plan,
    "full reconciliation plan missing"
);
assert.match(
    JSON.stringify(retained.plans.reconciliation.plan),
    /SubPlan 1|application_generation_idx/,
    "retained plan does not include the superseded-count indexed subplan"
);
assert.equal(retained.cleanup.status, "PASSED");

process.stdout.write(
    "M3-08 performance benchmark behavior and fail-closed contract passed.\n"
);
