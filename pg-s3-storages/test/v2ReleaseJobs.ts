import {
    DeleteBucketCommand,
    DeleteObjectsCommand,
    GetBucketVersioningCommand,
    GetObjectCommand,
    paginateListObjectsV2,
    PutObjectCommand,
    S3Client,
} from "@aws-sdk/client-s3";
import { expect } from "chai";
import { knex, Knex } from "knex";
import { createHash, randomUUID } from "node:crypto";

import PgS3Storages, {
    createV2ControlObjectStorage,
    createV2ReleaseJobQueue,
    createV2WorkerObjectStorage,
    V2JobLeaseLostError,
    V2ReleaseJobLease,
    V2ReleaseJobWorker,
    V2WorkerObjectStorage,
} from "../src";
import tables from "../src/common/tables";

const postgresAdminUrl =
    process.env.POSTGRES_TEST_URL ??
    "postgres://postgres:password@127.0.0.1:5432/postgres";
const s3Endpoint = process.env.MINIO_TEST_URL ?? "http://127.0.0.1:9000";
const rootCredentials = {
    accessKeyId: "accessKeyId",
    secretAccessKey: "secretAccessKey",
};
const controlCredentials = {
    accessKeyId: "m304-control",
    secretAccessKey: "m304-control-secret",
};
const workerCredentials = {
    accessKeyId: "m304-worker",
    secretAccessKey: "m304-worker-secret",
};

function client(credentials = rootCredentials): S3Client {
    return new S3Client({
        endpoint: s3Endpoint,
        region: "us-east-1",
        forcePathStyle: true,
        credentials,
    });
}

function digest(content: Uint8Array) {
    return {
        size: content.byteLength,
        sha256: createHash("sha256").update(content).digest("hex"),
    };
}

async function expectFailure(
    operation: PromiseLike<unknown>,
    expected: string | (new (...args: never[]) => Error)
) {
    let failure: unknown;
    try {
        await operation;
    } catch (error) {
        failure = error;
    }
    if (typeof expected === "string") {
        expect(failure).to.be.instanceOf(Error);
        expect((failure as Error).message).to.include(expected);
    } else expect(failure).to.be.instanceOf(expected);
}

const pause = (milliseconds: number) =>
    new Promise<void>((resolve) => setTimeout(resolve, milliseconds));

describe("M3-05 release job leases, retries, and quarantine cleanup", () => {
    const databaseName = `m305_${randomUUID().replace(/-/g, "")}`;
    const bucket = `m304-${randomUUID()}`;
    let admin: Knex;
    let module: PgS3Storages;
    let database: Knex;
    let secondDatabase: Knex;
    let root: S3Client;
    let controlClient: S3Client;
    let workerClient: S3Client;
    let control: ReturnType<typeof createV2ControlObjectStorage>;
    let objects: ReturnType<typeof createV2WorkerObjectStorage>;
    let queue: ReturnType<typeof createV2ReleaseJobQueue>;
    let secondQueue: ReturnType<typeof createV2ReleaseJobQueue>;
    let suffix = 1;

    before(async () => {
        admin = knex({ client: "pg", connection: postgresAdminUrl });
        await admin.raw("create database ??", [databaseName]);
        const databaseUrl = new URL(postgresAdminUrl);
        databaseUrl.pathname = `/${databaseName}`;
        module = new PgS3Storages({
            postgresUrl: databaseUrl.toString(),
            s3Config: {
                bucket,
                endpoint: s3Endpoint,
                forcePathStyle: true,
                ...rootCredentials,
            },
        });
        await module.setup();
        database = (module as unknown as { knex: Knex }).knex;
        root = (module as unknown as { s3Client: S3Client }).s3Client;
        secondDatabase = knex({
            client: "pg",
            connection: databaseUrl.toString(),
        });
        controlClient = client(controlCredentials);
        workerClient = client(workerCredentials);
        control = createV2ControlObjectStorage(database, controlClient, bucket);
        objects = createV2WorkerObjectStorage(database, workerClient, bucket);
        queue = createV2ReleaseJobQueue(database);
        secondQueue = createV2ReleaseJobQueue(secondDatabase);
    });

    after(async () => {
        try {
            const keys: string[] = [];
            for await (const page of paginateListObjectsV2(
                { client: root },
                { Bucket: bucket }
            ))
                for (const object of page.Contents ?? [])
                    if (object.Key) keys.push(object.Key);
            for (let index = 0; index < keys.length; index += 1000)
                await root.send(
                    new DeleteObjectsCommand({
                        Bucket: bucket,
                        Delete: {
                            Objects: keys
                                .slice(index, index + 1000)
                                .map((Key) => ({ Key })),
                        },
                    })
                );
            await root.send(new DeleteBucketCommand({ Bucket: bucket }));
        } finally {
            controlClient.destroy();
            workerClient.destroy();
            await secondDatabase.destroy();
            await module.destroy();
            await admin.raw("drop database ??", [databaseName]);
            await admin.destroy();
        }
    });

    it("JOB-03 attests disposable quarantine is unversioned", async () => {
        const versioning = await root.send(
            new GetBucketVersioningCommand({ Bucket: bucket })
        );
        expect(versioning.Status).to.equal(undefined);
    });

    it("rejects NULL SECURITY DEFINER bounds before mutation", async () => {
        await expectFailure(
            database.raw(
                "select * from public.v2_claim_release_jobs(?, ?, ?)",
                ["null-probe", null, 1]
            ),
            "claim arguments are invalid"
        );
        await expectFailure(
            database.raw(
                "select * from public.v2_claim_release_jobs(?, ?, ?)",
                ["null-probe", 1000, null]
            ),
            "claim arguments are invalid"
        );

        const cleanup = await insertJob("CLEANUP_QUARANTINE", 2, "UPLOADED");
        const cleanupLease = (
            await queue.claimDue({ owner: "null-cleanup", leaseMs: 2000 })
        )[0];
        await expectFailure(
            database.raw(
                "select public.v2_prepare_quarantine_cleanup(?, ?, ?, ?)",
                [
                    cleanupLease.id,
                    cleanupLease.owner,
                    cleanupLease.leaseVersion,
                    null,
                ]
            ),
            "minimum age is outside bounds"
        );
        await queue.fail(cleanupLease, "TEST_COMPLETE", "TEST_COMPLETE");
        expect(
            (
                await database(tables.v2Releases)
                    .where({ id: cleanup.releaseId })
                    .first("state")
            ).state
        ).to.equal("UPLOADED");

        const processing = await insertJob("PROCESS_RELEASE", 2);
        const processingLease = (
            await queue.claimDue({ owner: "null-retry", leaseMs: 2000 })
        )[0];
        expect(processingLease.releaseId).to.equal(processing.releaseId);
        await expectFailure(
            database.raw(
                `select public.v2_finish_release_job(
                    ?, ?, ?, ?, ?, 'RETRY', 'TRANSIENT_STORAGE', null, null, null
                )`,
                [
                    processingLease.id,
                    processingLease.releaseId,
                    processingLease.kind,
                    processingLease.owner,
                    processingLease.leaseVersion,
                ]
            ),
            "retry arguments are invalid"
        );
        await queue.fail(processingLease, "TEST_COMPLETE", "TEST_COMPLETE");
    });

    it("JOB-01 atomically claims one live owner and fences renew/reclaim", async () => {
        await expectFailure(
            queue.claimDue({ owner: "worker", leaseMs: 99 }),
            "duration is outside bounds"
        );
        await expectFailure(
            queue.claimDue({ owner: "worker", leaseMs: 900_001 }),
            "duration is outside bounds"
        );
        await expectFailure(
            queue.claimDue({ owner: "worker", leaseMs: 1000, limit: 101 }),
            "batch is outside bounds"
        );
        const fixture = await insertJob("PROCESS_RELEASE", 3);
        const [left, right] = await Promise.all([
            queue.claimDue({ owner: "worker-a", leaseMs: 1000 }),
            secondQueue.claimDue({ owner: "worker-b", leaseMs: 1000 }),
        ]);
        expect(left.length + right.length).to.equal(1);
        const original = (left[0] ?? right[0]) as V2ReleaseJobLease;
        const originalQueue = left.length === 1 ? queue : secondQueue;
        const reclaimQueue = left.length === 1 ? secondQueue : queue;
        await expectFailure(
            originalQueue.renew({ ...original, leaseVersion: 99 }, 1000),
            V2JobLeaseLostError
        );
        const renewed = await originalQueue.renew(original, 1000);
        expect(renewed.leaseVersion).to.equal(original.leaseVersion);
        expect(
            (await reclaimQueue.claimDue({ owner: "worker-c", leaseMs: 1000 }))
                .length
        ).to.equal(0);
        await pause(1100);
        const reclaimed = await reclaimQueue.claimDue({
            owner: "worker-c",
            leaseMs: 500,
        });
        expect(reclaimed).to.have.length(1);
        expect(reclaimed[0].attemptCount).to.equal(2);
        expect(reclaimed[0].leaseVersion).to.equal(original.leaseVersion + 1);
        await expectFailure(
            originalQueue.fail(original, "STALE_WORKER", "STALE_WORKER"),
            V2JobLeaseLostError
        );
        await reclaimQueue.fail(
            reclaimed[0],
            "CONTROLLED_FAILURE",
            "CONTROLLED_FAILURE"
        );
        await reclaimQueue.fail(
            reclaimed[0],
            "CONTROLLED_FAILURE",
            "CONTROLLED_FAILURE"
        );
        expect(
            (
                await database(tables.v2ReleaseJobs)
                    .where({ id: fixture.jobId })
                    .first()
            ).state
        ).to.equal("FAILED");
    });

    it("JOB-01 evaluates liveness after row-lock wait and skips locked work in order", async () => {
        const expiring = await insertJob("PROCESS_RELEASE", 2);
        const lease = (
            await queue.claimDue({ owner: "lock-waiter", leaseMs: 100 })
        )[0];
        let blockedRenew!: Promise<V2ReleaseJobLease>;
        await secondDatabase.transaction(async (transaction) => {
            await transaction(tables.v2ReleaseJobs)
                .where({ id: expiring.jobId })
                .forUpdate()
                .first();
            blockedRenew = queue.renew(lease, 1000);
            await pause(175);
        });
        await expectFailure(blockedRenew, V2JobLeaseLostError);
        const reclaimed = (
            await queue.claimDue({ owner: "lock-reclaimer", leaseMs: 1000 })
        )[0];
        await queue.fail(reclaimed, "TEST_COMPLETE", "TEST_COMPLETE");

        const ordered = await Promise.all([
            insertJob("PROCESS_RELEASE", 2),
            insertJob("PROCESS_RELEASE", 2),
            insertJob("PROCESS_RELEASE", 2),
        ]);
        await database(tables.v2ReleaseJobs)
            .whereIn(
                "id",
                ordered.map((item) => item.jobId)
            )
            .update({ next_attempt_at: new Date("2000-01-01T00:00:00.000Z") });
        const expectedOrder = (
            await database(tables.v2ReleaseJobs)
                .whereIn(
                    "id",
                    ordered.map((item) => item.jobId)
                )
                .orderBy([
                    { column: "next_attempt_at", order: "asc" },
                    { column: "created_at", order: "asc" },
                    { column: "id", order: "asc" },
                ])
                .select("id")
        ).map((item) => item.id);
        let claimedWhileLocked: V2ReleaseJobLease[] = [];
        await secondDatabase.transaction(async (transaction) => {
            await transaction(tables.v2ReleaseJobs)
                .where({ id: expectedOrder[0] })
                .forUpdate()
                .first();
            claimedWhileLocked = await queue.claimDue({
                owner: "skip-locked",
                leaseMs: 1000,
                limit: 2,
            });
        });
        expect(claimedWhileLocked.map((item) => item.id)).to.deep.equal(
            expectedOrder.slice(1)
        );
        const last = await queue.claimDue({
            owner: "ordered-last",
            leaseMs: 1000,
        });
        expect(last.map((item) => item.id)).to.deep.equal([expectedOrder[0]]);
        for (const item of [...claimedWhileLocked, ...last])
            await queue.fail(item, "TEST_COMPLETE", "TEST_COMPLETE");
    });

    it("JOB-01 bounds a blocked lease operation with the database lock timeout", async () => {
        const fixture = await insertJob("PROCESS_RELEASE", 2);
        const lease = (
            await queue.claimDue({ owner: "timeout-worker", leaseMs: 30_000 })
        )[0];
        await secondDatabase.transaction(async (transaction) => {
            await transaction(tables.v2ReleaseJobs)
                .where({ id: fixture.jobId })
                .forUpdate()
                .first();
            const startedAt = Date.now();
            await expectFailure(queue.renew(lease, 30_000), "lock timeout");
            expect(Date.now() - startedAt).to.be.within(4_500, 7_000);
        });
        await queue.fail(lease, "TEST_COMPLETE", "TEST_COMPLETE");
    });

    it("JOB-03 bounds exponential retry and records one terminal result", async () => {
        const fixture = await insertJob("PROCESS_RELEASE", 2);
        const first = (
            await queue.claimDue({ owner: "retry-worker", leaseMs: 2000 })
        )[0];
        const realDateNow = Date.now;
        try {
            Date.now = () => realDateNow() + 86_400_000;
            await queue.retry(first, "TRANSIENT_STORAGE", 100);
        } finally {
            Date.now = realDateNow;
        }
        await queue.retry(first, "TRANSIENT_STORAGE", 100);
        const retryIdentity = (await database(tables.v2ReleaseJobs)
            .where({ id: fixture.jobId })
            .first("next_attempt_at", "completion_identity")) as {
            next_attempt_at: Date;
            completion_identity: string;
        };
        await expectFailure(
            queue.retry(first, "TRANSIENT_STORAGE", 101),
            "completion conflicts with immutable result"
        );
        await expectFailure(
            queue.retry(
                { ...first, owner: "different-owner" },
                "TRANSIENT_STORAGE",
                100
            ),
            "completion conflicts with immutable result"
        );
        expect(
            await database(tables.v2ReleaseJobs)
                .where({ id: fixture.jobId })
                .first("next_attempt_at", "completion_identity")
        ).to.deep.equal(retryIdentity);
        let row = await database(tables.v2ReleaseJobs)
            .where({ id: fixture.jobId })
            .first();
        expect(row.state).to.equal("RETRY_WAIT");
        expect(
            new Date(row.next_attempt_at).getTime()
        ).to.be.greaterThanOrEqual(new Date(row.updated_at).getTime() + 90);
        expect(
            (await queue.claimDue({ owner: "too-early", leaseMs: 500 })).length
        ).to.equal(0);
        await pause(150);
        const finalLease = (
            await queue.claimDue({ owner: "final-worker", leaseMs: 2000 })
        )[0];
        expect(finalLease.attemptCount).to.equal(2);
        await expectFailure(
            queue.retry(finalLease, "STILL_BROKEN", 100),
            "final release job attempt cannot be retried"
        );
        await queue.fail(finalLease, "STILL_BROKEN", "RETRY_EXHAUSTED");
        await queue.fail(finalLease, "STILL_BROKEN", "RETRY_EXHAUSTED");
        row = await database(tables.v2ReleaseJobs)
            .where({ id: fixture.jobId })
            .first();
        expect(row).to.include({
            state: "FAILED",
            last_error_code: "STILL_BROKEN",
            terminal_reason: "RETRY_EXHAUSTED",
        });
    });

    it("JOB-03 applies deterministic seeded jitter, exponential growth, and the cap", async () => {
        const jitteredQueue = createV2ReleaseJobQueue(
            database,
            "deterministic-test-seed"
        );
        const fixture = await insertJob("PROCESS_RELEASE", 5);
        const observed: number[] = [];
        for (let attempt = 1; attempt <= 3; attempt += 1) {
            const lease = (
                await jitteredQueue.claimDue({
                    owner: `jitter-${attempt}`,
                    leaseMs: 2000,
                })
            )[0];
            await jitteredQueue.retry(lease, "TRANSIENT_STORAGE", 100);
            await jitteredQueue.retry(lease, "TRANSIENT_STORAGE", 100);
            const row = await database(tables.v2ReleaseJobs)
                .where({ id: fixture.jobId })
                .first("next_attempt_at", "updated_at");
            observed.push(
                new Date(row.next_attempt_at).getTime() -
                    new Date(row.updated_at).getTime()
            );
            await database(tables.v2ReleaseJobs)
                .where({ id: fixture.jobId })
                .update({
                    next_attempt_at: database.raw(
                        "clock_timestamp() - interval '1 second'"
                    ),
                });
        }
        expect(observed[0]).to.be.within(100, 125);
        expect(observed[1]).to.be.within(200, 250);
        expect(observed[2]).to.be.within(400, 500);

        const capped = (
            await jitteredQueue.claimDue({
                owner: "jitter-cap",
                leaseMs: 2000,
            })
        )[0];
        await jitteredQueue.retry(capped, "TRANSIENT_STORAGE", 900_000);
        const cappedRow = await database(tables.v2ReleaseJobs)
            .where({ id: fixture.jobId })
            .first("next_attempt_at", "updated_at");
        expect(
            new Date(cappedRow.next_attempt_at).getTime() -
                new Date(cappedRow.updated_at).getTime()
        ).to.be.closeTo(900_000, 2);
        expect(() => createV2ReleaseJobQueue(database, "")).to.throw(
            "jitter seed is outside bounds"
        );
    });

    it("JOB-03 terminalizes a crashed final attempt without exceeding max attempts", async () => {
        const fixture = await insertJob("PROCESS_RELEASE", 1);
        const lease = (
            await queue.claimDue({ owner: "crashed-worker", leaseMs: 100 })
        )[0];
        expect(lease.attemptCount).to.equal(1);
        await pause(175);
        const restartedQueue = createV2ReleaseJobQueue(secondDatabase);
        expect(
            (await restartedQueue.claimDue({ owner: "recovery", leaseMs: 500 }))
                .length
        ).to.equal(0);
        const row = await database(tables.v2ReleaseJobs)
            .where({ id: fixture.jobId })
            .first();
        expect(row).to.include({
            state: "FAILED",
            attempt_count: 1,
            last_error_code: "LEASE_EXPIRED",
            terminal_reason: "FINAL_ATTEMPT_LEASE_EXPIRED",
        });
        await queue.fail(lease, "LEASE_EXPIRED", "FINAL_ATTEMPT_LEASE_EXPIRED");
        await expectFailure(
            queue.fail(lease, "DIFFERENT_FAILURE", "DIFFERENT_FAILURE"),
            "completion conflicts with immutable result"
        );
        expect(
            (
                await database(tables.v2Releases)
                    .where({ id: fixture.releaseId })
                    .first("state")
            ).state
        ).to.equal("FAILED");

        const ready = await insertJob("PROCESS_RELEASE", 1);
        await declareAndUpload(
            ready.releaseId,
            "index.html",
            Buffer.from("final READY crash")
        );
        let readyLease = (
            await queue.claimDue({ owner: "final-ready-crash", leaseMs: 1000 })
        )[0];
        await objects.finalizeRelease({
            applicationId: ready.applicationId,
            releaseId: ready.releaseId,
            uploadId: ready.releaseId,
            defaultPath: "index.html",
            finalizationFence: {
                assertActive: (transaction: Knex.Transaction) =>
                    queue.assertActiveInTransaction(readyLease, transaction),
                bindWorkIdentity: (identity: string) =>
                    queue.bindWorkIdentity(readyLease, identity),
                checkpoint: async () => {
                    readyLease = await queue.renew(readyLease, 1000);
                },
            },
        });
        await pause(1100);
        const finalRecoveryQueue = createV2ReleaseJobQueue(secondDatabase);
        expect(
            await finalRecoveryQueue.claimDue({
                owner: "final-ready-recovery",
                leaseMs: 1000,
            })
        ).to.deep.equal([]);
        expect(
            await database(tables.v2ReleaseJobs)
                .where({ id: ready.jobId })
                .first("state", "attempt_count")
        ).to.include({ state: "SUCCEEDED", attempt_count: 1 });
        expect(
            (
                await database(tables.v2Releases)
                    .where({ id: ready.releaseId })
                    .first("state")
            ).state
        ).to.equal("READY");
    });

    it("JOB-03 makes terminal processing failures eligible for cleanup", async () => {
        const fixture = await insertJob("PROCESS_RELEASE", 2);
        const lease = (
            await queue.claimDue({
                owner: "terminal-processing",
                leaseMs: 2000,
            })
        )[0];
        await queue.fail(lease, "VALIDATION_FAILED", "VALIDATION_FAILED");
        expect(
            (
                await database(tables.v2Releases)
                    .where({ id: fixture.releaseId })
                    .first("state")
            ).state
        ).to.equal("FAILED");
        await pause(110);
        const cleanupJobId = `72000000-0000-4000-8000-${String(
            suffix++
        ).padStart(12, "0")}`;
        await database(tables.v2ReleaseJobs).insert({
            id: cleanupJobId,
            release_id: fixture.releaseId,
            kind: "CLEANUP_QUARANTINE",
            max_attempts: 2,
        });
        const cleanupLease = (
            await queue.claimDue({ owner: "terminal-cleanup", leaseMs: 2000 })
        )[0];
        await new V2ReleaseJobWorker(
            queue,
            objects,
            2000,
            100
        ).cleanupQuarantine(cleanupLease);
        expect(
            (
                await database(tables.v2ReleaseJobs)
                    .where({ id: cleanupJobId })
                    .first("state")
            ).state
        ).to.equal("SUCCEEDED");
    });

    it("JOB-02 rejects exact work success before READY", async () => {
        const fixture = await insertJob("PROCESS_RELEASE", 2);
        const lease = (
            await queue.claimDue({ owner: "false-success", leaseMs: 2000 })
        )[0];
        const identity = "f".repeat(64);
        await queue.bindWorkIdentity(lease, identity);
        await expectFailure(
            queue.succeed(lease, identity),
            "does not match immutable READY work"
        );
        expect(
            (
                await database(tables.v2Releases)
                    .where({ id: fixture.releaseId })
                    .first("state")
            ).state
        ).to.equal("PROCESSING");
        await queue.fail(lease, "TEST_COMPLETE", "TEST_COMPLETE");
        expect(
            (
                await database(tables.v2Releases)
                    .where({ id: fixture.releaseId })
                    .first("state")
            ).state
        ).to.equal("FAILED");
    });

    it("JOB-02 canonicalizes release identity before object side effects", async () => {
        const canonical = await insertJob("PROCESS_RELEASE", 2);
        const unrelated = await insertJob("PROCESS_RELEASE", 2);
        await database(tables.v2ReleaseJobs)
            .where({ id: unrelated.jobId })
            .update({
                next_attempt_at: database.raw(
                    "clock_timestamp() + interval '1 hour'"
                ),
            });
        const lease = (
            await queue.claimDue({ owner: "identity-probe", leaseMs: 2000 })
        )[0];
        await expectFailure(
            new V2ReleaseJobWorker(queue, objects, 2000, 100).finalizeRelease(
                { ...lease, releaseId: unrelated.releaseId },
                {
                    applicationId: unrelated.applicationId,
                    releaseId: unrelated.releaseId,
                    uploadId: unrelated.releaseId,
                    defaultPath: "index.html",
                }
            ),
            "does not match release identity"
        );
        expect(
            (
                await database(tables.v2Releases)
                    .where({ id: unrelated.releaseId })
                    .first("state")
            ).state
        ).to.equal("PROCESSING");
        await queue.fail(lease, "TEST_COMPLETE", "TEST_COMPLETE");
        await database(tables.v2ReleaseJobs)
            .where({ id: unrelated.jobId })
            .update({ next_attempt_at: database.raw("clock_timestamp()") });
        const unrelatedLease = (
            await queue.claimDue({ owner: "identity-cleanup", leaseMs: 2000 })
        )[0];
        expect(unrelatedLease.releaseId).to.equal(unrelated.releaseId);
        await queue.fail(unrelatedLease, "TEST_COMPLETE", "TEST_COMPLETE");
        expect(canonical.releaseId).to.equal(lease.releaseId);
    });

    it("JOB-02 finalizes through an active transaction fence and denies stale workers", async () => {
        const fixture = await insertJob("PROCESS_RELEASE", 3);
        const body = Buffer.from("fenced release");
        await declareAndUpload(fixture.releaseId, "index.html", body);
        const stale = (
            await queue.claimDue({ owner: "stale-finalizer", leaseMs: 100 })
        )[0];
        await pause(175);
        const current = (
            await secondQueue.claimDue({
                owner: "current-finalizer",
                leaseMs: 1000,
            })
        )[0];
        const worker = new V2ReleaseJobWorker(secondQueue, objects, 1000, 100);
        await expectFailure(
            secondQueue.succeed(current),
            "requires an exact manifest digest"
        );
        await expectFailure(
            new V2ReleaseJobWorker(queue, objects, 1000, 100).finalizeRelease(
                stale,
                {
                    applicationId: fixture.applicationId,
                    releaseId: fixture.releaseId,
                    uploadId: fixture.releaseId,
                    defaultPath: "index.html",
                }
            ),
            V2JobLeaseLostError
        );
        const result = await worker.finalizeRelease(current, {
            applicationId: fixture.applicationId,
            releaseId: fixture.releaseId,
            uploadId: fixture.releaseId,
            defaultPath: "index.html",
        });
        const manifestDigest = digest(
            Buffer.from(JSON.stringify(result))
        ).sha256;
        await secondQueue.succeed(current, manifestDigest);
        await expectFailure(
            secondQueue.succeed(current, "f".repeat(64)),
            "completion conflicts with immutable result"
        );
        expect(result.defaultPath).to.equal("index.html");
        expect(
            (
                await database(tables.v2Releases)
                    .where({ id: fixture.releaseId })
                    .first()
            ).state
        ).to.equal("READY");
        expect(
            (
                await database(tables.v2ReleaseJobs)
                    .where({ id: fixture.jobId })
                    .first()
            ).state
        ).to.equal("SUCCEEDED");
    });

    it("JOB-02 persists work identity, rejects stale progress, and recovers after READY-before-finish crash", async () => {
        const staleFixture = await insertJob("PROCESS_RELEASE", 3);
        const staleLease = (
            await queue.claimDue({ owner: "mid-flight-stale", leaseMs: 100 })
        )[0];
        const workA = "a".repeat(64);
        const fakeObjects = {
            finalizeRelease: async (input: {
                finalizationFence?: {
                    bindWorkIdentity(identity: string): Promise<void>;
                    checkpoint(): Promise<void>;
                };
            }) => {
                await input.finalizationFence?.bindWorkIdentity(workA);
                await pause(175);
                await input.finalizationFence?.checkpoint();
                throw new Error("unreachable");
            },
        } as unknown as V2WorkerObjectStorage;
        await expectFailure(
            new V2ReleaseJobWorker(
                queue,
                fakeObjects,
                100,
                100
            ).finalizeRelease(staleLease, {
                applicationId: staleFixture.applicationId,
                releaseId: staleFixture.releaseId,
                uploadId: staleFixture.releaseId,
                defaultPath: "index.html",
            }),
            V2JobLeaseLostError
        );
        const reclaimed = (
            await secondQueue.claimDue({
                owner: "mid-flight-current",
                leaseMs: 1000,
            })
        )[0];
        await expectFailure(
            secondQueue.bindWorkIdentity(reclaimed, "b".repeat(64)),
            "work identity conflicts"
        );
        await secondQueue.bindWorkIdentity(reclaimed, workA);
        await secondQueue.fail(reclaimed, "CONTROLLED_STOP", "CONTROLLED_STOP");

        const crash = await insertJob("PROCESS_RELEASE", 3);
        await declareAndUpload(
            crash.releaseId,
            "index.html",
            Buffer.from("crash boundary")
        );
        let crashLease = (
            await queue.claimDue({ owner: "ready-crash", leaseMs: 1000 })
        )[0];
        const crashFence = {
            assertActive: (transaction: Knex.Transaction) =>
                queue.assertActiveInTransaction(crashLease, transaction),
            bindWorkIdentity: (identity: string) =>
                queue.bindWorkIdentity(crashLease, identity),
            checkpoint: async () => {
                crashLease = await queue.renew(crashLease, 1000);
            },
        };
        const manifest = await objects.finalizeRelease({
            applicationId: crash.applicationId,
            releaseId: crash.releaseId,
            uploadId: crash.releaseId,
            defaultPath: "index.html",
            finalizationFence: crashFence,
        });
        expect(
            (
                await database(tables.v2ReleaseJobs)
                    .where({ id: crash.jobId })
                    .first("state")
            ).state
        ).to.equal("LEASED");
        await database.raw("select pg_sleep(1.1)");
        const recovered = (
            await secondQueue.claimDue({
                owner: "ready-recovery",
                leaseMs: 1000,
            })
        )[0];
        const recoveredManifest = await new V2ReleaseJobWorker(
            secondQueue,
            objects,
            1000,
            100
        ).finalizeRelease(recovered, {
            applicationId: crash.applicationId,
            releaseId: crash.releaseId,
            uploadId: crash.releaseId,
            defaultPath: "index.html",
        });
        expect(recoveredManifest).to.deep.equal(manifest);
        expect(
            await database(tables.v2ReleaseJobs)
                .where({ id: crash.jobId })
                .first("state", "attempt_count")
        ).to.include({ state: "SUCCEEDED", attempt_count: 2 });
    });

    it("JOB-02 recovers at every immutable object-write boundary", async () => {
        for (let failurePoint = 0; failurePoint < 4; failurePoint += 1) {
            const fixture = await insertJob("PROCESS_RELEASE", 6);
            await declareAndUpload(
                fixture.releaseId,
                "index.html",
                Buffer.from(`boundary-${failurePoint}`)
            );
            const lease = (
                await queue.claimDue({
                    owner: `boundary-${failurePoint}`,
                    leaseMs: 5000,
                })
            )[0];
            let putIndex = 0;
            let injected = false;
            const failingClient = {
                send: async (command: unknown, options?: unknown) => {
                    if (
                        command instanceof PutObjectCommand &&
                        !injected &&
                        putIndex++ === failurePoint
                    ) {
                        injected = true;
                        throw new Error(
                            `injected object boundary ${failurePoint}`
                        );
                    }
                    return workerClient.send(
                        command as never,
                        options as never
                    );
                },
            } as unknown as S3Client;
            const failingObjects = createV2WorkerObjectStorage(
                database,
                failingClient,
                bucket
            );
            await expectFailure(
                new V2ReleaseJobWorker(
                    queue,
                    failingObjects,
                    5000,
                    100
                ).finalizeRelease(lease, {
                    applicationId: fixture.applicationId,
                    releaseId: fixture.releaseId,
                    uploadId: fixture.releaseId,
                    defaultPath: "index.html",
                }),
                `injected object boundary ${failurePoint}`
            );
            expect(injected).to.equal(true);
            await queue.retry(lease, "INJECTED_BOUNDARY", 1);
            await database(tables.v2ReleaseJobs)
                .where({ id: fixture.jobId })
                .update({ next_attempt_at: database.raw("clock_timestamp()") });
            const restartedQueue = createV2ReleaseJobQueue(secondDatabase);
            const recovered = (
                await restartedQueue.claimDue({
                    owner: `boundary-restart-${failurePoint}`,
                    leaseMs: 5000,
                })
            )[0];
            await new V2ReleaseJobWorker(
                restartedQueue,
                objects,
                5000,
                100
            ).finalizeRelease(recovered, {
                applicationId: fixture.applicationId,
                releaseId: fixture.releaseId,
                uploadId: fixture.releaseId,
                defaultPath: "index.html",
            });
            expect(
                await database(tables.v2ReleaseJobs)
                    .where({ id: fixture.jobId })
                    .first("state", "attempt_count")
            ).to.include({ state: "SUCCEEDED", attempt_count: 2 });
        }
    });

    it("JOB-03 seals a racing upload before cleanup and prevents resurrection", async () => {
        const fixture = await insertJob("CLEANUP_QUARANTINE", 2, "UPLOADED");
        const content = Buffer.from("racing upload");
        const expected = digest(content);
        const declarationId = String(suffix++).padStart(12, "0");
        await database(tables.v2UploadFiles).insert({
            id: `50000000-0000-4000-8000-${declarationId}`,
            release_id: fixture.releaseId,
            declared_path: "race.txt",
            declared_size: expected.size,
            declared_digest: expected.sha256,
        });
        let releasePut!: () => void;
        let enteredPut!: () => void;
        const putGate = new Promise<void>((resolve) => {
            releasePut = resolve;
        });
        const entered = new Promise<void>((resolve) => {
            enteredPut = resolve;
        });
        const blockedClient = {
            send: async (command: unknown) => {
                if (command instanceof PutObjectCommand) {
                    enteredPut();
                    await putGate;
                }
                return controlClient.send(command as never);
            },
        } as unknown as S3Client;
        const racingControl = createV2ControlObjectStorage(
            database,
            blockedClient,
            bucket
        );
        const put = racingControl.putQuarantineFile(
            fixture.releaseId,
            "race.txt",
            content,
            expected
        );
        await entered;
        const lease = (
            await queue.claimDue({ owner: "sealing-cleaner", leaseMs: 1000 })
        )[0];
        await expectFailure(
            queue.succeed(lease),
            "requires a sealed FAILED release"
        );
        let cleanupSettled = false;
        const cleanup = new V2ReleaseJobWorker(queue, objects, 1000, 100)
            .cleanupQuarantine(lease)
            .finally(() => {
                cleanupSettled = true;
            });
        await pause(100);
        expect(cleanupSettled).to.equal(false);
        releasePut();
        await put;
        await cleanup;
        expect(
            await objectExists(quarantineKey(fixture.releaseId, "race.txt"))
        ).to.equal(false);
        await expectFailure(
            control.putQuarantineFile(
                fixture.releaseId,
                "race.txt",
                content,
                expected
            ),
            "active database declaration"
        );
    });

    it("JOB-03 permits one cleaner and fences it after expiry and reclaim", async () => {
        const fixture = await insertJob("CLEANUP_QUARANTINE", 3, "UPLOADED");
        const [left, right] = await Promise.all([
            queue.claimDue({ owner: "cleaner-a", leaseMs: 100 }),
            secondQueue.claimDue({ owner: "cleaner-b", leaseMs: 100 }),
        ]);
        expect(left.length + right.length).to.equal(1);
        const stale = (left[0] ?? right[0]) as V2ReleaseJobLease;
        const staleQueue = left.length === 1 ? queue : secondQueue;
        const reclaimQueue = left.length === 1 ? secondQueue : queue;
        await pause(175);
        const current = (
            await reclaimQueue.claimDue({
                owner: "cleaner-current",
                leaseMs: 1000,
            })
        )[0];
        await expectFailure(
            new V2ReleaseJobWorker(
                staleQueue,
                objects,
                1000,
                100
            ).cleanupQuarantine(stale),
            V2JobLeaseLostError
        );
        await new V2ReleaseJobWorker(
            reclaimQueue,
            objects,
            1000,
            100
        ).cleanupQuarantine(current);
        expect(
            await database(tables.v2ReleaseJobs)
                .where({ id: fixture.jobId })
                .first("state", "attempt_count")
        ).to.include({ state: "SUCCEEDED", attempt_count: 2 });
    });

    it("JOB-03 restarts after a failed quarantine listing page", async () => {
        const fixture = await insertJob("CLEANUP_QUARANTINE", 3, "UPLOADED");
        await declareAndUpload(
            fixture.releaseId,
            "listed.txt",
            Buffer.from("listed")
        );
        const lease = (
            await queue.claimDue({ owner: "list-failure", leaseMs: 1000 })
        )[0];
        let failed = false;
        const listingFailure = {
            ...objects,
            readQuarantineFile: objects.readQuarantineFile.bind(objects),
            deleteQuarantineFile: objects.deleteQuarantineFile.bind(objects),
            deleteQuarantineObject:
                objects.deleteQuarantineObject.bind(objects),
            finalizeRelease: objects.finalizeRelease.bind(objects),
            listQuarantineObjects: async (uploadId: string) => {
                if (!failed) {
                    failed = true;
                    throw new Error("injected listing page failure");
                }
                return objects.listQuarantineObjects(uploadId);
            },
        } as V2WorkerObjectStorage;
        await expectFailure(
            new V2ReleaseJobWorker(
                queue,
                listingFailure,
                1000,
                100
            ).cleanupQuarantine(lease),
            "injected listing page failure"
        );
        await queue.retry(lease, "LIST_FAILED", 100);
        await pause(150);
        const retry = (
            await secondQueue.claimDue({
                owner: "list-restart",
                leaseMs: 1000,
            })
        )[0];
        await new V2ReleaseJobWorker(
            secondQueue,
            objects,
            1000,
            100
        ).cleanupQuarantine(retry);
        expect(
            await objectExists(quarantineKey(fixture.releaseId, "listed.txt"))
        ).to.equal(false);
    });

    it("JOB-03 enforces DB-clock retention and blocks every active processing job", async () => {
        const future = await insertJob("CLEANUP_QUARANTINE", 2, "UPLOADED");
        await database(tables.v2Releases)
            .where({ id: future.releaseId })
            .update({ updated_at: database.fn.now() });
        const futureLease = (
            await queue.claimDue({ owner: "future-cleaner", leaseMs: 1000 })
        )[0];
        await expectFailure(
            queue.prepareQuarantineCleanup(futureLease, 60_000),
            "not eligible"
        );
        await queue.fail(futureLease, "NOT_EXPIRED", "NOT_EXPIRED");

        const active = await insertJob("CLEANUP_QUARANTINE", 2, "UPLOADED");
        const processJobId = `71000000-0000-4000-8000-${String(
            suffix++
        ).padStart(12, "0")}`;
        await database(tables.v2ReleaseJobs).insert({
            id: processJobId,
            release_id: active.releaseId,
            kind: "PROCESS_RELEASE",
            max_attempts: 2,
            next_attempt_at: database.raw(
                "clock_timestamp() + interval '1 hour'"
            ),
        });
        const cleanupLease = (
            await queue.claimDue({
                owner: "active-process-cleaner",
                leaseMs: 1000,
            })
        )[0];
        await expectFailure(
            queue.prepareQuarantineCleanup(cleanupLease, 100),
            "active processing job blocks"
        );
        await queue.fail(cleanupLease, "ACTIVE_PROCESS", "ACTIVE_PROCESS");
        expect(
            (
                await database(tables.v2Releases)
                    .where({ id: active.releaseId })
                    .first("state")
            ).state
        ).to.equal("UPLOADED");
    });

    it("JOB-03 confines cleanup, survives partial deletion, and leaves active/immutable prefixes", async () => {
        const fixture = await insertJob("CLEANUP_QUARANTINE", 3, "UPLOADED");
        await declareAndUpload(
            fixture.releaseId,
            "a.txt",
            Buffer.from("first")
        );
        await addDeclarationAndUpload(
            fixture.releaseId,
            "b.txt",
            Buffer.from("second")
        );
        const immutableKey = `v2/releases/${fixture.applicationId}/${fixture.releaseId}/content/keep.txt`;
        await root.send(
            new PutObjectCommand({
                Bucket: bucket,
                Key: immutableKey,
                Body: Buffer.from("immutable"),
            })
        );
        const lease = (
            await queue.claimDue({ owner: "cleanup-worker", leaseMs: 1000 })
        )[0];
        let failedOnce = false;
        const partialObjects = {
            readQuarantineFile: objects.readQuarantineFile.bind(objects),
            listQuarantineObjects: objects.listQuarantineObjects.bind(objects),
            deleteQuarantineFile: objects.deleteQuarantineFile.bind(objects),
            finalizeRelease: objects.finalizeRelease.bind(objects),
            deleteQuarantineObject: async (uploadId: string, path: string) => {
                if (!failedOnce && path === "files/b.txt") {
                    failedOnce = true;
                    throw new Error("injected delete failure");
                }
                return objects.deleteQuarantineObject(uploadId, path);
            },
        } as V2WorkerObjectStorage;
        await expectFailure(
            new V2ReleaseJobWorker(
                queue,
                partialObjects,
                1000,
                100
            ).cleanupQuarantine(lease),
            "injected delete failure"
        );
        await queue.retry(lease, "DELETE_FAILED", 100);
        await pause(150);
        const retry = (
            await secondQueue.claimDue({
                owner: "cleanup-restart",
                leaseMs: 1000,
            })
        )[0];
        await new V2ReleaseJobWorker(
            secondQueue,
            objects,
            1000,
            100
        ).cleanupQuarantine(retry);
        expect(await objectExists(immutableKey)).to.equal(true);
        expect(
            await objectExists(quarantineKey(fixture.releaseId, "a.txt"))
        ).to.equal(false);
        expect(
            await objectExists(quarantineKey(fixture.releaseId, "b.txt"))
        ).to.equal(false);
        expect(
            (
                await database(tables.v2Releases)
                    .where({ id: fixture.releaseId })
                    .first()
            ).state
        ).to.equal("FAILED");

        const active = await insertJob("CLEANUP_QUARANTINE", 2, "PROCESSING");
        await addDeclarationAndUpload(
            active.releaseId,
            "index.html",
            Buffer.from("active")
        );
        const activeLease = (
            await queue.claimDue({ owner: "active-cleaner", leaseMs: 1000 })
        )[0];
        await expectFailure(
            queue.prepareQuarantineCleanup(activeLease, 100),
            "not eligible"
        );
        expect(
            await objectExists(quarantineKey(active.releaseId, "index.html"))
        ).to.equal(true);

        const rogue = await insertJob("CLEANUP_QUARANTINE", 2, "UPLOADED");
        const rogueKey = quarantineKey(rogue.releaseId, "undeclared.txt");
        const quarantineRoot = `v2/quarantine/${rogue.releaseId}/`;
        const originalZipKey = `${quarantineRoot}original.zip`;
        const unusualKeys = [
            quarantineRoot,
            `${quarantineRoot}files/back\\slash.txt`,
            `${quarantineRoot}files/e\u0301.txt`,
        ];
        for (const Key of [rogueKey, originalZipKey, ...unusualKeys])
            await root.send(
                new PutObjectCommand({
                    Bucket: bucket,
                    Key,
                    Body: Buffer.from("undeclared"),
                })
            );
        const rogueLease = (
            await queue.claimDue({ owner: "rogue-cleaner", leaseMs: 3000 })
        )[0];
        const rogueWorker = new V2ReleaseJobWorker(queue, objects, 3000, 100);
        await rogueWorker.cleanupQuarantine(rogueLease);
        expect(await objectExists(rogueKey)).to.equal(false);
        expect(await objectExists(originalZipKey)).to.equal(false);
        for (const key of unusualKeys)
            expect(await objectExists(key)).to.equal(false);
    });

    it("JOB-03 wires bounded aborts and rejects escaped or non-progressing pages", async () => {
        const uploadId = "30000000-0000-4000-8000-000000009999";
        const abortingClient = {
            send: async (
                _command: unknown,
                options?: { abortSignal?: AbortSignal }
            ) => {
                expect(options?.abortSignal).to.be.instanceOf(AbortSignal);
                throw new Error("observed bounded S3 abort signal");
            },
        } as unknown as S3Client;
        await expectFailure(
            createV2WorkerObjectStorage(
                database,
                abortingClient,
                bucket
            ).listQuarantineObjects(uploadId),
            "observed bounded S3 abort signal"
        );
        const prefix = `v2/quarantine/${uploadId}/`;
        let page = 0;
        const loopingClient = {
            send: async () => {
                page += 1;
                return {
                    IsTruncated: true,
                    NextContinuationToken: "repeated",
                    Contents: [{ Key: `${prefix}files/${page}.txt` }],
                };
            },
        } as unknown as S3Client;
        const looping = createV2WorkerObjectStorage(
            database,
            loopingClient,
            bucket
        );
        await expectFailure(
            looping.listQuarantineObjects(uploadId),
            "pagination made no progress"
        );

        for (const Key of [
            `v2/quarantine/${uploadId}0/files/escape.txt`,
            `${prefix}${"a".repeat(1025)}`,
        ]) {
            const hostileClient = {
                send: async () => ({
                    IsTruncated: false,
                    Contents: [{ Key }],
                }),
            } as unknown as S3Client;
            const hostile = createV2WorkerObjectStorage(
                database,
                hostileClient,
                bucket
            );
            await expectFailure(
                hostile.listQuarantineObjects(uploadId),
                Key.includes("escape")
                    ? "escaped its exact prefix"
                    : "exceeds S3 UTF-8 byte limit"
            );
        }
    });

    async function insertJob(
        kind: "PROCESS_RELEASE" | "CLEANUP_QUARANTINE",
        maxAttempts: number,
        releaseState = kind === "PROCESS_RELEASE" ? "PROCESSING" : "UPLOADED"
    ) {
        const id = String(suffix++).padStart(12, "0");
        const applicationId = `10000000-0000-4000-8000-${id}`;
        const releaseId = `30000000-0000-4000-8000-${id}`;
        const jobId = `70000000-0000-4000-8000-${id}`;
        await database(tables.v2Applications).insert({
            id: applicationId,
            name: `m305-${id}`,
            description: "M3-05 fixture",
            tags: JSON.stringify([]),
            owner_metadata: JSON.stringify({}),
            routing_id: `40000000-0000-4000-8000-${id}`,
        });
        const releaseTime =
            kind === "CLEANUP_QUARANTINE"
                ? database.raw("clock_timestamp() - interval '1 second'")
                : database.fn.now();
        await database(tables.v2Releases).insert({
            id: releaseId,
            application_id: applicationId,
            state: releaseState,
            created_at: releaseTime,
            updated_at: releaseTime,
        });
        await database(tables.v2ReleaseJobs).insert({
            id: jobId,
            release_id: releaseId,
            kind,
            max_attempts: maxAttempts,
        });
        return { applicationId, releaseId, jobId };
    }

    async function declareAndUpload(
        releaseId: string,
        path: string,
        content: Buffer
    ) {
        const id = String(suffix++).padStart(12, "0");
        const expected = digest(content);
        await database(tables.v2UploadFiles).insert({
            id: `50000000-0000-4000-8000-${id}`,
            release_id: releaseId,
            declared_path: path,
            declared_size: expected.size,
            declared_digest: expected.sha256,
        });
        await control.putQuarantineFile(releaseId, path, content, expected);
    }

    async function addDeclarationAndUpload(
        releaseId: string,
        path: string,
        content: Buffer
    ) {
        return declareAndUpload(releaseId, path, content);
    }

    function quarantineKey(releaseId: string, path: string) {
        return `v2/quarantine/${releaseId}/files/${path}`;
    }

    async function objectExists(key: string): Promise<boolean> {
        try {
            const response = await root.send(
                new GetObjectCommand({ Bucket: bucket, Key: key })
            );
            await response.Body?.transformToByteArray();
            return true;
        } catch (error) {
            const status = (
                error as { $metadata?: { httpStatusCode?: number } }
            ).$metadata?.httpStatusCode;
            if (status === 404) return false;
            throw error;
        }
    }
});
