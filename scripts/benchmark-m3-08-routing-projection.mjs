#!/usr/bin/env node

import {
    DeleteBucketCommand,
    DeleteObjectsCommand,
    ListObjectsV2Command,
    PutObjectCommand,
    S3Client,
} from "@aws-sdk/client-s3";
import { createHash, generateKeyPairSync, randomUUID } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { cpus, totalmem } from "node:os";
import { execFileSync } from "node:child_process";
import pg from "pg";

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
let V2ContentRoutingCache;
let V2RoutingSigner;
let v2ProjectionReconciliationSql;

const EXPECTED_NODE = "v24.19.0";
const ROWS = 10_000;
const ITERATIONS = 20;
const CONCURRENT_ITERATIONS = 15;
const CONTENT_ITERATIONS = 25;
const budgetsMs = Object.freeze({
    claimBatch1P95: 100,
    claimBatch100P95: 200,
    expiredBatch100P95: 200,
    mixedBatch100P95: 200,
    concurrentClaimersP95: 400,
    keyRetirableP95: 20,
    reconciliationQueryP95: 10,
    contentRefreshP95: 200,
});
const budgetsResources = Object.freeze({
    contentRssDeltaBytes: 192 * 1024 * 1024,
});

function required(name) {
    const value = process.env[name];
    if (!value) throw new Error(`${name} is required`);
    return value;
}

function assertLoopback(url, name) {
    const parsed = new URL(url);
    if (!new Set(["127.0.0.1", "localhost", "::1"]).has(parsed.hostname))
        throw new Error(`${name} must be loopback-only`);
    return parsed;
}

async function timed(operation) {
    const started = process.hrtime.bigint();
    await operation();
    return Number(process.hrtime.bigint() - started) / 1e6;
}

async function resetDatabase(client) {
    await client.query("DROP SCHEMA IF EXISTS public CASCADE");
    await client.query("CREATE SCHEMA public");
    await client.query("GRANT ALL ON SCHEMA public TO PUBLIC");
}

async function seedOutbox(client) {
    // Direct terminal-state fixture insertion is benchmark-only. USER triggers
    // are disabled for this bounded seed transaction and restored before every
    // measurement; foreign-key and CHECK constraints remain enforced.
    await client.query("BEGIN");
    try {
        await client.query(`
        CREATE TEMP TABLE m308_benchmark_ids ON COMMIT PRESERVE ROWS AS
        SELECT i, gen_random_uuid() AS application_id, gen_random_uuid() AS routing_id,
               gen_random_uuid() AS idempotency_id, gen_random_uuid() AS outbox_id,
               gen_random_uuid() AS request_audit_id
          FROM generate_series(1, ${ROWS}) generated(i);

        INSERT INTO public.v2_idempotency
          (id, actor_id, scope, idempotency_key, request_digest, state,
           result_kind, result_id, result_status, created_at, completed_at, expires_at)
        SELECT idempotency_id, 'oidc:' || repeat('a', 64), 'application.unpublish',
               'm308-benchmark-' || lpad(i::text, 10, '0'), repeat('b', 64),
               CASE WHEN i > 9000 THEN 'COMPLETED' ELSE 'IN_PROGRESS' END,
               CASE WHEN i > 9000 THEN 'PUBLICATION' ELSE NULL END,
               CASE WHEN i > 9000 THEN outbox_id ELSE NULL END,
               CASE WHEN i > 9000 THEN 'SUCCEEDED' ELSE NULL END,
               transaction_timestamp() - interval '1 hour',
               CASE WHEN i > 9000 THEN transaction_timestamp() - interval '10 minutes' ELSE NULL END,
               transaction_timestamp() + interval '1 day'
          FROM m308_benchmark_ids;

        INSERT INTO public.v2_applications
          (id, name, routing_id, desired_generation, served_generation, created_at, updated_at)
        SELECT application_id, 'm308-benchmark-' || lpad(i::text, 10, '0'), routing_id,
               CASE WHEN i = 1 OR i > 9500 THEN 2 ELSE 1 END,
               CASE WHEN i > 9500 THEN 2 WHEN i > 9000 THEN 1 ELSE 0 END,
               transaction_timestamp() - interval '1 hour', transaction_timestamp()
          FROM m308_benchmark_ids;

        ALTER TABLE public.v2_publication_outbox DISABLE TRIGGER USER;
        INSERT INTO public.v2_publication_outbox
          (id, application_id, routing_id, release_id, generation, operation,
           idempotency_id, payload_kind, manifest_digest, object_prefix,
           state, lease_owner, lease_expires_at, attempt_count, lease_version,
           next_attempt_at, acknowledged_at, projection_digest,
           routing_kid, routing_host, request_digest, request_actor_id,
           request_audit_id, acknowledged_etag, created_at, updated_at)
        SELECT outbox_id, application_id, routing_id, NULL, 1, 'UNPUBLISH',
               idempotency_id, 'TOMBSTONE', NULL, NULL,
               CASE WHEN i <= 6500 THEN 'PENDING'
                    WHEN i <= 8000 THEN 'LEASED'
                    WHEN i <= 9000 THEN 'LEASED'
                    ELSE 'ACKNOWLEDGED' END,
               CASE WHEN i BETWEEN 6501 AND 9000 THEN
                    CASE WHEN i <= 8000 THEN 'benchmark-expired' ELSE 'benchmark-live' END
                    ELSE NULL END,
               CASE WHEN i BETWEEN 6501 AND 8000 THEN transaction_timestamp() - interval '1 minute'
                    WHEN i BETWEEN 8001 AND 9000 THEN transaction_timestamp() + interval '1 hour'
                    ELSE NULL END,
               CASE WHEN i BETWEEN 6501 AND 9000 THEN 1 ELSE 0 END,
               CASE WHEN i BETWEEN 6501 AND 9000 THEN 1 ELSE 0 END,
               CASE WHEN i <= 5000 THEN transaction_timestamp() - interval '1 minute'
                    WHEN i <= 6500 THEN transaction_timestamp() + interval '1 day'
                    ELSE NULL END,
               CASE WHEN i > 9000 THEN transaction_timestamp() - interval '10 minutes' ELSE NULL END,
               CASE WHEN i > 9000 THEN repeat('c', 64) ELSE NULL END,
               CASE WHEN i > 9000 OR i <= 100 THEN 'routing-retained' ELSE 'routing-benchmark' END,
               'route-' || i::text || '.benchmark.invalid', repeat('b', 64),
               'oidc:' || repeat('a', 64), request_audit_id,
               CASE WHEN i > 9000 THEN '"benchmark-etag-' || i::text || '"' ELSE NULL END,
               transaction_timestamp() - interval '1 hour',
               CASE WHEN i BETWEEN 6501 AND 8000 THEN transaction_timestamp() - interval '2 minutes'
                    ELSE transaction_timestamp() END
          FROM m308_benchmark_ids;
        ALTER TABLE public.v2_publication_outbox ENABLE TRIGGER USER;
        COMMIT;
        ANALYZE public.v2_applications;
        ANALYZE public.v2_publication_outbox;
      `);
    } catch (error) {
        await client.query("ROLLBACK");
        throw error;
    }
}

async function rollbackMeasurement(client, operation) {
    await client.query("BEGIN");
    try {
        return await operation();
    } finally {
        await client.query("ROLLBACK");
    }
}

async function measureRepeated(warmups, iterations, operation) {
    for (let index = 0; index < warmups; index += 1) await operation(index);
    const samples = [];
    for (let index = 0; index < iterations; index += 1)
        samples.push(await timed(() => operation(index)));
    return {
        samples: samples.map((value) => Number(value.toFixed(3))),
        summary: metric(samples),
    };
}

async function explain(client, sql, parameters = []) {
    const result = await client.query(
        `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${sql}`,
        parameters
    );
    const plan = result.rows[0]["QUERY PLAN"][0];
    const serialized = JSON.stringify(plan);
    return {
        planningTimeMs: plan["Planning Time"],
        executionTimeMs: plan["Execution Time"],
        indexes: [
            ...new Set(
                serialized.match(/v2_[A-Za-z0-9_]+_(?:idx|unique)/g) ?? []
            ),
        ].sort(),
        plan,
    };
}

async function cleanBucket(s3, bucket) {
    let token;
    do {
        const listed = await s3.send(
            new ListObjectsV2Command({
                Bucket: bucket,
                ContinuationToken: token,
            })
        );
        if ((listed.Contents ?? []).length > 0)
            await s3.send(
                new DeleteObjectsCommand({
                    Bucket: bucket,
                    Delete: {
                        Objects: listed.Contents.map(({ Key }) => ({ Key })),
                    },
                })
            );
        token = listed.IsTruncated ? listed.NextContinuationToken : undefined;
    } while (token);
    await s3.send(new DeleteBucketCommand({ Bucket: bucket }));
}

async function prepareContent(s3, bucket) {
    const applicationId = randomUUID();
    const routingId = randomUUID();
    const releaseId = randomUUID();
    const host = `${routingId}.benchmark.invalid`;
    const zeroDigest = createHash("sha256")
        .update(Buffer.alloc(0))
        .digest("hex");
    const files = Array.from({ length: 1024 }, (_, index) => ({
        path: `files/${String(index).padStart(4, "0")}-${"a".repeat(900)}.txt`,
        mime: "text/plain; charset=utf-8",
        size: 0,
        sha256: zeroDigest,
    }));
    const manifest = Buffer.from(
        JSON.stringify({
            version: 1,
            applicationId,
            releaseId,
            defaultPath: files[0].path,
            files,
            sourceDownload: { size: 0, sha256: zeroDigest },
        })
    );
    const manifestDigest = createHash("sha256").update(manifest).digest("hex");
    const keyPair = generateKeyPairSync("ed25519");
    const issuedAt = new Date().toISOString();
    const signer = new V2RoutingSigner([
        {
            kid: "routing-benchmark",
            purpose: "staticdeploy-routing-v1",
            status: "ACTIVE",
            publicKey: keyPair.publicKey,
            privateKey: keyPair.privateKey,
            notBefore: "2020-01-01T00:00:00.000Z",
            notAfter: "2099-01-01T00:00:00.000Z",
        },
    ]);
    const body = signer.sign({
        version: 1,
        purpose: "staticdeploy-routing-v1",
        context: "v2/routing",
        applicationId,
        routingId,
        host,
        audience: "staticdeploy-published-content",
        generation: 1,
        issuedAt,
        operation: "PUBLISH",
        release: {
            id: releaseId,
            manifestDigest,
            objectPrefix: `v2/releases/${applicationId}/${releaseId}`,
        },
    });
    await Promise.all([
        s3.send(
            new PutObjectCommand({
                Bucket: bucket,
                Key: `v2/releases/${applicationId}/${releaseId}/manifest.json`,
                Body: manifest,
            })
        ),
        s3.send(
            new PutObjectCommand({
                Bucket: bucket,
                Key: `v2/routing/${routingId}/generations/1.json`,
                Body: body,
            })
        ),
        s3.send(
            new PutObjectCommand({
                Bucket: bucket,
                Key: `v2/routing/${routingId}/current.json`,
                Body: body,
            })
        ),
    ]);
    return {
        cache: new V2ContentRoutingCache(
            s3,
            bucket,
            routingId,
            applicationId,
            host,
            signer.verifier,
            1
        ),
        manifestBytes: manifest.byteLength,
        routingDocumentBytes: body.byteLength,
    };
}

async function candidateIdentity() {
    const paths = [
        "pg-s3-storages/src/migrations/08.ts",
        "pg-s3-storages/src/V2RoutingProjection.ts",
        "pg-s3-storages/test/v2RoutingProjection.ts",
        "scripts/benchmark-m3-08-routing-projection.mjs",
        "scripts/m3-08-benchmark-contract.mjs",
        "scripts/test-m3-08-benchmark.mjs",
        "scripts/setup-m304-minio-roles.sh",
        "pg-s3-storages/lib/index.js",
        "pg-s3-storages/lib/V2RoutingProjection.js",
        "pg-s3-storages/lib/migrations/08.js",
    ];
    const artifactDigests = [];
    for (const path of paths) {
        const bytes = await readFile(path);
        artifactDigests.push({
            path,
            sha256: createHash("sha256").update(bytes).digest("hex"),
        });
    }
    return {
        sourceHead: execFileSync("git", ["rev-parse", "HEAD"], {
            encoding: "utf8",
        }).trim(),
        stagedTree: execFileSync("git", ["write-tree"], {
            encoding: "utf8",
        }).trim(),
        artifactDigests,
    };
}

async function minioIdentity(url) {
    try {
        const response = await fetch(new URL("/minio/health/live", url), {
            method: "HEAD",
            signal: AbortSignal.timeout(5_000),
        });
        return {
            healthStatus: response.status,
            serverHeader: response.headers.get("server"),
            version: response.headers.get("x-minio-version"),
            versionStatus:
                response.headers.get("x-minio-version") === null
                    ? "UNAVAILABLE_FROM_SAFE_HEALTH_RESPONSE"
                    : "ATTESTED",
        };
    } catch (error) {
        return {
            healthStatus: null,
            serverHeader: null,
            version: null,
            versionStatus: "UNAVAILABLE_FROM_SAFE_HEALTH_RESPONSE",
            probeErrorClass: error instanceof Error ? error.name : "Error",
        };
    }
}

async function main() {
    if (process.version !== EXPECTED_NODE)
        throw new Error(
            `Node ${EXPECTED_NODE} is required; observed ${process.version}`
        );
    execFileSync(
        "corepack",
        ["yarn", "workspace", "@staticdeploy/pg-s3-storages", "compile"],
        { cwd: process.cwd(), env: process.env, stdio: "inherit" }
    );
    ({
        V2ContentRoutingCache,
        V2RoutingSigner,
        v2ProjectionReconciliationSql,
    } = require("../pg-s3-storages/lib/V2RoutingProjection.js"));
    if (process.env.M308_BENCHMARK_ALLOW_RESET !== "1")
        throw new Error(
            "M308_BENCHMARK_ALLOW_RESET=1 is required for destructive fixture reset"
        );
    const postgresUrl = required("POSTGRES_BENCHMARK_URL");
    const minioUrl = required("MINIO_BENCHMARK_URL");
    const postgresParsed = assertLoopback(
        postgresUrl,
        "POSTGRES_BENCHMARK_URL"
    );
    assertLoopback(minioUrl, "MINIO_BENCHMARK_URL");
    if (!postgresParsed.pathname.slice(1).startsWith("m308bench"))
        throw new Error(
            "POSTGRES_BENCHMARK_URL database must start with m308bench"
        );
    const accessKeyId = required("MINIO_BENCHMARK_ACCESS_KEY");
    const secretAccessKey = required("MINIO_BENCHMARK_SECRET_KEY");
    const outputPath = required("M308_BENCHMARK_OUTPUT");
    const bucket = `m308-benchmark-${randomUUID()}`;
    const admin = new pg.Client({ connectionString: postgresUrl });
    const s3 = new S3Client({
        endpoint: minioUrl,
        region: "us-east-1",
        forcePathStyle: true,
        credentials: { accessKeyId, secretAccessKey },
    });
    const clients = [];
    let storage;
    let report;
    let exceeded = [];
    let operationError;
    let adminConnected = false;
    let bucketCreated = false;
    const cleanupErrors = [];
    try {
        await admin.connect();
        adminConnected = true;
        const version = await admin.query("SHOW server_version_num");
        const postgresMajor = Math.floor(
            Number(version.rows[0].server_version_num) / 10000
        );
        if (postgresMajor !== 16)
            throw new Error(
                `PostgreSQL 16 is required; observed ${postgresMajor}`
            );
        await resetDatabase(admin);
        const PgS3Storages = require("../pg-s3-storages/lib/index.js").default;
        storage = new PgS3Storages({
            postgresUrl,
            s3Config: {
                bucket,
                endpoint: minioUrl,
                region: "us-east-1",
                forcePathStyle: true,
                accessKeyId,
                secretAccessKey,
            },
        });
        await storage.setup();
        bucketCreated = true;
        await seedOutbox(admin);
        const categories = await admin.query(
            "SELECT outbox_id, i FROM m308_benchmark_ids ORDER BY i"
        );
        const expiredIds = new Set(
            categories.rows
                .filter((row) => Number(row.i) >= 6501 && Number(row.i) <= 8000)
                .map((row) => row.outbox_id)
        );

        const claimSql =
            "SELECT * FROM public.v2_claim_publications($1, $2, $3)";
        const measuredClaim = (owner, limit) =>
            rollbackMeasurement(admin, async () => {
                const result = await admin.query(claimSql, [
                    owner,
                    30_000,
                    limit,
                ]);
                assertClaimRows(result.rows, {
                    count: limit,
                    owner,
                    identityFor: (row) =>
                        expiredIds.has(row.id)
                            ? { attemptCount: 2, leaseVersion: 2 }
                            : { attemptCount: 1, leaseVersion: 1 },
                });
                return result;
            });
        const configureDuePending = (maximumDueId) =>
            admin.query(
                `UPDATE public.v2_publication_outbox outbox
                    SET next_attempt_at = CASE WHEN ids.i <= $1
                        THEN transaction_timestamp() - interval '1 minute'
                        ELSE transaction_timestamp() + interval '1 day' END
                   FROM m308_benchmark_ids ids
                  WHERE ids.outbox_id = outbox.id AND outbox.state = 'PENDING'`,
                [maximumDueId]
            );
        const claimBatch1 = await measureRepeated(5, ITERATIONS, (index) =>
            measuredClaim(`bench-one-${index}`, 1)
        );
        const claimBatch100 = await measureRepeated(5, ITERATIONS, (index) =>
            measuredClaim(`bench-hundred-${index}`, 100)
        );
        await configureDuePending(0);
        const expiredBatch100 = await measureRepeated(5, ITERATIONS, (index) =>
            measuredClaim(`bench-expired-${index}`, 100)
        );
        await configureDuePending(50);
        const mixedBatch100 = await measureRepeated(5, ITERATIONS, (index) =>
            measuredClaim(`bench-mixed-${index}`, 100)
        );
        await configureDuePending(5000);

        for (let index = 0; index < 8; index += 1) {
            const client = new pg.Client({ connectionString: postgresUrl });
            await client.connect();
            clients.push(client);
        }
        const concurrentClaimers = await measureRepeated(
            3,
            CONCURRENT_ITERATIONS,
            async (iteration) => {
                await Promise.all(
                    clients.map((client) => client.query("BEGIN"))
                );
                try {
                    const results = await Promise.all(
                        clients.map(async (client, index) => {
                            const owner = `bench-concurrent-${iteration}-${index}`;
                            const result = await client.query(claimSql, [
                                owner,
                                30_000,
                                100,
                            ]);
                            return { owner, rows: result.rows };
                        })
                    );
                    assertConcurrentClaims(results, 100);
                    await Promise.all(
                        clients.map((client) =>
                            client.query("SELECT pg_sleep(0.02)")
                        )
                    );
                } finally {
                    await Promise.all(
                        clients.map((client) => client.query("ROLLBACK"))
                    );
                }
            }
        );

        const keySql = `SELECT count(*)::text AS count
      FROM public.v2_publication_outbox outbox
      JOIN public.v2_applications application ON application.id = outbox.application_id
     WHERE outbox.routing_kid = $1
       AND (outbox.state IN ('PENDING', 'LEASED')
         OR (outbox.state = 'ACKNOWLEDGED'
           AND application.served_generation = outbox.generation))`;
        const keyRetirable = await measureRepeated(5, ITERATIONS, async () => {
            const result = await admin.query(keySql, ["routing-retained"]);
            if (result.rows[0]?.count !== "600")
                throw new Error(
                    "key retirement fixture did not distinguish active and historical references"
                );
            return result;
        });

        const sample = await admin.query(
            "SELECT application_id FROM m308_benchmark_ids WHERE i = 1"
        );
        const reconciliationSql = v2ProjectionReconciliationSql("$1");
        const reconciliationApplicationId = sample.rows[0].application_id;
        const reconciliationQuery = await measureRepeated(
            5,
            ITERATIONS,
            async () => {
                const result = await admin.query(reconciliationSql, [
                    reconciliationApplicationId,
                ]);
                if (result.rows.length !== 1)
                    throw new Error(
                        "reconciliation fixture returned the wrong row count"
                    );
                assertReconciliationRow(
                    result.rows[0],
                    reconciliationApplicationId
                );
                return result;
            }
        );

        const contentFixture = await prepareContent(s3, bucket);
        for (let index = 0; index < 5; index += 1)
            assertObjectRefresh(await contentFixture.cache.refresh());
        const rssBefore = process.memoryUsage().rss;
        const contentRefresh = await measureRepeated(
            0,
            CONTENT_ITERATIONS,
            async () =>
                assertObjectRefresh(await contentFixture.cache.refresh())
        );
        const rssAfter = process.memoryUsage().rss;

        const plans = {
            claimCandidate: await explain(
                admin,
                `SELECT outbox.id FROM public.v2_publication_outbox outbox
          JOIN public.v2_applications application
            ON application.id = outbox.application_id
         WHERE outbox.state = 'PENDING'
           AND outbox.next_attempt_at <= clock_timestamp()
           AND outbox.attempt_count < outbox.max_attempts
           AND application.desired_generation = outbox.generation
           AND application.desired_current_release_id IS NOT DISTINCT FROM outbox.release_id
         ORDER BY outbox.next_attempt_at, outbox.created_at, outbox.id LIMIT 100`
            ),
            keyRetirable: await explain(admin, keySql, ["routing-retained"]),
            reconciliation: await explain(admin, reconciliationSql, [
                reconciliationApplicationId,
            ]),
        };

        assertRequiredPlans(plans);

        const metrics = {
            claimBatch1,
            claimBatch100,
            expiredBatch100,
            mixedBatch100,
            concurrentClaimers,
            keyRetirable,
            reconciliationQuery,
            contentRefresh,
        };
        const checks = {
            claimBatch1P95: claimBatch1.summary.p95Ms,
            claimBatch100P95: claimBatch100.summary.p95Ms,
            expiredBatch100P95: expiredBatch100.summary.p95Ms,
            mixedBatch100P95: mixedBatch100.summary.p95Ms,
            concurrentClaimersP95: concurrentClaimers.summary.p95Ms,
            keyRetirableP95: keyRetirable.summary.p95Ms,
            reconciliationQueryP95: reconciliationQuery.summary.p95Ms,
            contentRefreshP95: contentRefresh.summary.p95Ms,
        };
        const resourceChecks = {
            contentRssDeltaBytes: rssAfter - rssBefore,
        };
        exceeded = [
            ...Object.entries(checks)
                .filter(([name, value]) => value > budgetsMs[name])
                .map(
                    ([name, value]) => `${name}=${value}ms>${budgetsMs[name]}ms`
                ),
            ...Object.entries(resourceChecks)
                .filter(([name, value]) => value > budgetsResources[name])
                .map(
                    ([name, value]) =>
                        `${name}=${value}>${budgetsResources[name]} bytes`
                ),
        ];
        const postgresConfiguration = (
            await admin.query(`SELECT version() AS full_version,
                current_setting('server_version') AS server_version,
                current_setting('shared_buffers') AS shared_buffers,
                current_setting('work_mem') AS work_mem,
                current_setting('effective_cache_size') AS effective_cache_size,
                current_setting('max_connections') AS max_connections,
                current_setting('random_page_cost') AS random_page_cost,
                current_setting('jit') AS jit`)
        ).rows[0];
        const cpu = cpus();
        report = {
            schemaVersion: 1,
            subject: "M3-08-routing-projection-performance",
            candidate: await candidateIdentity(),
            environment: {
                nodeVersion: process.version,
                postgresMajor,
                postgresConfiguration,
                postgresTopology: "disposable loopback dedicated database",
                objectStore: "disposable loopback MinIO",
                minio: await minioIdentity(minioUrl),
                platform: `${process.platform}/${process.arch}`,
                cpuModel: cpu[0]?.model ?? "unknown",
                cpuCount: cpu.length,
                totalMemoryBytes: totalmem(),
            },
            dataset: {
                outboxRows: ROWS,
                distribution: {
                    duePendingPercent: 50,
                    futurePendingPercent: 15,
                    expiredLeasedPercent: 15,
                    liveLeasedPercent: 10,
                    acknowledgedCurrentPercent: 5,
                    acknowledgedHistoricalPercent: 5,
                },
                fixtureMethod:
                    "benchmark-only USER triggers disabled inside the seed transaction, foreign keys and CHECK constraints retained, triggers restored before ANALYZE and measurement",
                keyRetirementExpectedReferences: 600,
                reconciliationFixture: {
                    applicationOrdinal: 1,
                    desiredGeneration: 2,
                    servedGeneration: 0,
                    stalePendingGeneration: 1,
                    expectedSupersededCount: 1,
                },
                concurrentClaimers: clients.length,
                concurrentClaimRows: clients.length * 100,
                manifestFiles: 1024,
                manifestBytes: contentFixture.manifestBytes,
                routingDocumentBytes: contentFixture.routingDocumentBytes,
                routingReadLimitBytes: 16 * 1024,
            },
            warmups: { database: 5, concurrent: 3, content: 5 },
            metrics,
            resources: {
                rssBeforeBytes: rssBefore,
                rssAfterBytes: rssAfter,
                rssDeltaBytes: rssAfter - rssBefore,
            },
            plans,
            requiredPlanIndexes: {
                keyRetirable: ["v2_outbox_routing_kid_active_idx"],
                reconciliation: [
                    "v2_publication_outbox_application_generation_unique",
                    "v2_publication_outbox_application_generation_idx",
                ],
            },
            budgetsMs,
            budgetsResources,
            budgetChecks: { ...checks, ...resourceChecks },
            status: exceeded.length === 0 ? "PASSED" : "FAILED",
            exceeded,
            residualGates: ["B-PG", "B-S3", "B-DEPLOY"],
            generatedAt: new Date().toISOString(),
        };
    } catch (error) {
        operationError = error;
    } finally {
        cleanupErrors.push(
            ...(await runCleanupSteps([
                ...(storage === undefined
                    ? []
                    : [
                          {
                              label: "storage destroy failed",
                              operation: () => storage.destroy(),
                          },
                      ]),
                ...clients.map((client, index) => ({
                    label: `claim client ${index} cleanup failed`,
                    operation: () => client.end(),
                })),
                ...(bucketCreated
                    ? [
                          {
                              label: "benchmark bucket cleanup failed",
                              operation: () => cleanBucket(s3, bucket),
                          },
                      ]
                    : []),
                ...(adminConnected
                    ? [
                          {
                              label: "benchmark database fixture cleanup failed",
                              operation: () => resetDatabase(admin),
                          },
                          {
                              label: "benchmark admin connection cleanup failed",
                              operation: () => admin.end(),
                          },
                      ]
                    : []),
                {
                    label: "S3 client cleanup failed",
                    operation: async () => s3.destroy(),
                },
            ]))
        );
    }
    if (operationError !== undefined || cleanupErrors.length > 0) {
        throw new AggregateError(
            [operationError, ...cleanupErrors].filter(
                (error) => error !== undefined
            ),
            "benchmark operation or cleanup failed"
        );
    }
    if (report === undefined)
        throw new Error("benchmark report was not produced");
    report.cleanup = {
        status: "PASSED",
        attempted: [
            "storage.destroy",
            "claim clients",
            "object-store bucket",
            "database public schema",
            "admin connection",
            "S3 client",
        ],
    };
    await writeFile(outputPath, `${JSON.stringify(report, null, 2)}\n`, {
        flag: "wx",
    });
    process.stdout.write(`${JSON.stringify(report)}\n`);
    if (exceeded.length > 0)
        throw new Error(`performance budgets exceeded: ${exceeded.join(", ")}`);
}

main().catch((error) => {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    if (error instanceof AggregateError)
        for (const nested of error.errors)
            process.stderr.write(`caused by: ${nested?.stack ?? nested}\n`);
    process.exitCode = 1;
});
