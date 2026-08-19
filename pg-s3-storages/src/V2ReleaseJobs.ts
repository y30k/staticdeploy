import { Knex } from "knex";
import { createHash } from "node:crypto";

import {
    V2ReleaseFinalizationFence,
    V2ReleaseManifest,
    V2WorkerObjectStorage,
} from "./V2ObjectStorage";

const OWNER = /^[A-Za-z0-9._:-]{1,200}$/;
const REASON = /^[A-Z][A-Z0-9_]{0,127}$/;
const MIN_LEASE_MS = 100;
const MAX_LEASE_MS = 15 * 60 * 1000;
const MAX_CLAIM_BATCH = 100;
const MAX_RETRY_DELAY_MS = 15 * 60 * 1000;
const MAX_CLEANUP_AGE_MS = 365 * 24 * 60 * 60 * 1000;
const CLEANUP_CONCURRENCY = 4;
const MAX_CLEANUP_LIST_ROUNDS = 4;

export type V2ReleaseJobKind = "PROCESS_RELEASE" | "CLEANUP_QUARANTINE";

export interface V2ReleaseJobLease {
    id: string;
    releaseId: string;
    kind: V2ReleaseJobKind;
    owner: string;
    leaseVersion: number;
    leaseExpiresAt: Date;
    attemptCount: number;
    maxAttempts: number;
}

interface JobRow {
    id: string;
    release_id: string;
    kind: V2ReleaseJobKind;
    state: string;
    lease_owner: string | null;
    lease_expires_at: Date | string | null;
    attempt_count: number;
    lease_version: string | number;
    max_attempts: number;
    next_attempt_at: Date | string | null;
    last_error_code: string | null;
    terminal_reason: string | null;
}

export class V2JobLeaseLostError extends Error {
    constructor() {
        super("release job lease fencing does not match an active lease");
        this.name = "V2JobLeaseLostError";
    }
}

function assertOwner(owner: string): void {
    if (!OWNER.test(owner)) throw new Error("invalid release job lease owner");
}

function assertLeaseDuration(leaseMs: number): void {
    if (
        !Number.isSafeInteger(leaseMs) ||
        leaseMs < MIN_LEASE_MS ||
        leaseMs > MAX_LEASE_MS
    )
        throw new Error("release job lease duration is outside bounds");
}

function assertReason(value: string, label: string): void {
    if (!REASON.test(value)) throw new Error(`invalid release job ${label}`);
}

function asLease(row: JobRow): V2ReleaseJobLease {
    if (row.lease_owner === null || row.lease_expires_at === null)
        throw new Error("claimed release job has no lease identity");
    const leaseVersion = Number(row.lease_version);
    if (!Number.isSafeInteger(leaseVersion))
        throw new Error(
            "release job lease version is outside JavaScript bounds"
        );
    return {
        id: row.id,
        releaseId: row.release_id,
        kind: row.kind,
        owner: row.lease_owner,
        leaseVersion,
        leaseExpiresAt: new Date(row.lease_expires_at),
        attemptCount: Number(row.attempt_count),
        maxAttempts: Number(row.max_attempts),
    };
}

function rows<T>(result: unknown): T[] {
    return (result as { rows: T[] }).rows;
}

export class V2ReleaseJobQueue {
    constructor(
        private readonly knex: Knex,
        private readonly retryJitterSeed = "staticdeploy-v2-release-jobs-v1"
    ) {
        if (
            retryJitterSeed.length < 1 ||
            Buffer.byteLength(retryJitterSeed, "utf8") > 256
        )
            throw new Error("release job retry jitter seed is outside bounds");
    }

    async claimDue(input: {
        owner: string;
        leaseMs: number;
        limit?: number;
    }): Promise<V2ReleaseJobLease[]> {
        assertOwner(input.owner);
        assertLeaseDuration(input.leaseMs);
        const limit = input.limit ?? 1;
        if (
            !Number.isSafeInteger(limit) ||
            limit < 1 ||
            limit > MAX_CLAIM_BATCH
        )
            throw new Error("release job claim batch is outside bounds");
        const claimed = rows<JobRow>(
            await this.knex.raw(
                "SELECT * FROM public.v2_claim_release_jobs(?, ?, ?)",
                [input.owner, input.leaseMs, limit]
            )
        );
        return claimed.map(asLease);
    }

    async renew(
        lease: V2ReleaseJobLease,
        leaseMs: number
    ): Promise<V2ReleaseJobLease> {
        this.assertLeaseShape(lease);
        assertLeaseDuration(leaseMs);
        try {
            const renewed = rows<JobRow>(
                await this.knex.raw(
                    "SELECT (public.v2_renew_release_job(?, ?, ?, ?)).*",
                    [lease.id, lease.owner, lease.leaseVersion, leaseMs]
                )
            );
            return asLease(renewed[0]);
        } catch (error) {
            if (this.isFenceError(error)) throw new V2JobLeaseLostError();
            throw error;
        }
    }

    async assertActive(lease: V2ReleaseJobLease): Promise<void> {
        await this.knex.transaction((transaction) =>
            this.assertActiveInTransaction(lease, transaction)
        );
    }

    async retry(
        lease: V2ReleaseJobLease,
        errorCode: string,
        baseDelayMs = 1000
    ): Promise<void> {
        this.assertLeaseShape(lease);
        assertReason(errorCode, "error code");
        if (
            !Number.isSafeInteger(baseDelayMs) ||
            baseDelayMs < 1 ||
            baseDelayMs > MAX_RETRY_DELAY_MS
        )
            throw new Error("release job retry base delay is outside bounds");
        const exponent = Math.max(0, Math.min(lease.attemptCount - 1, 20));
        const unjittered = Math.min(
            MAX_RETRY_DELAY_MS,
            baseDelayMs * 2 ** exponent
        );
        const maximumJitter = Math.min(
            Math.floor(unjittered / 4),
            MAX_RETRY_DELAY_MS - unjittered
        );
        const jitter =
            maximumJitter === 0
                ? 0
                : createHash("sha256")
                      .update(this.retryJitterSeed)
                      .update("\0")
                      .update(lease.id)
                      .update("\0")
                      .update(String(lease.leaseVersion))
                      .update("\0")
                      .update(errorCode)
                      .digest()
                      .readUInt32BE(0) %
                  (maximumJitter + 1);
        await this.finish(lease, "RETRY", errorCode, null, unjittered + jitter);
    }

    async succeed(
        lease: V2ReleaseJobLease,
        expectedManifestDigest?: string
    ): Promise<void> {
        if (
            lease.kind === "PROCESS_RELEASE" &&
            (expectedManifestDigest === undefined ||
                !/^[0-9a-f]{64}$/.test(expectedManifestDigest))
        )
            throw new Error(
                "processing job success requires an exact manifest digest"
            );
        await this.finish(
            lease,
            "SUCCEEDED",
            null,
            null,
            null,
            expectedManifestDigest
        );
    }

    async fail(
        lease: V2ReleaseJobLease,
        errorCode: string,
        terminalReason: string
    ): Promise<void> {
        assertReason(errorCode, "error code");
        assertReason(terminalReason, "terminal reason");
        await this.finish(lease, "FAILED", errorCode, terminalReason, null);
    }

    async bindWorkIdentity(
        lease: V2ReleaseJobLease,
        identity: string
    ): Promise<void> {
        this.assertLeaseShape(lease);
        if (!/^[0-9a-f]{64}$/.test(identity))
            throw new Error("invalid release job work identity");
        try {
            await this.knex.raw(
                "SELECT public.v2_bind_release_job_work(?, ?, ?, ?)",
                [lease.id, lease.owner, lease.leaseVersion, identity]
            );
        } catch (error) {
            if (this.isFenceError(error)) throw new V2JobLeaseLostError();
            throw error;
        }
    }

    async prepareQuarantineCleanup(
        lease: V2ReleaseJobLease,
        minimumAgeMs: number
    ): Promise<void> {
        this.assertLeaseShape(lease);
        if (lease.kind !== "CLEANUP_QUARANTINE")
            throw new Error("release job is not a quarantine cleanup job");
        if (
            !Number.isSafeInteger(minimumAgeMs) ||
            minimumAgeMs < 100 ||
            minimumAgeMs > MAX_CLEANUP_AGE_MS
        )
            throw new Error("quarantine cleanup minimum age is outside bounds");
        try {
            await this.knex.raw(
                "SELECT public.v2_prepare_quarantine_cleanup(?, ?, ?, ?)",
                [lease.id, lease.owner, lease.leaseVersion, minimumAgeMs]
            );
        } catch (error) {
            if (this.isFenceError(error)) throw new V2JobLeaseLostError();
            throw error;
        }
    }

    async assertActiveInTransaction(
        lease: V2ReleaseJobLease,
        transaction: Knex.Transaction
    ): Promise<void> {
        this.assertLeaseShape(lease);
        try {
            await transaction.raw(
                "SELECT public.v2_assert_release_job_lease(?, ?, ?)",
                [lease.id, lease.owner, lease.leaseVersion]
            );
        } catch (error) {
            if (this.isFenceError(error)) throw new V2JobLeaseLostError();
            throw error;
        }
    }

    private isFenceError(error: unknown): boolean {
        const candidate = error as { code?: string; message?: string };
        return (
            candidate.code === "55000" &&
            candidate.message?.includes("fencing does not match") === true
        );
    }

    private assertLeaseShape(lease: V2ReleaseJobLease): void {
        assertOwner(lease.owner);
        if (
            !Number.isSafeInteger(lease.leaseVersion) ||
            lease.leaseVersion < 1 ||
            !Number.isSafeInteger(lease.attemptCount) ||
            lease.attemptCount < 1
        )
            throw new Error("invalid release job lease identity");
    }

    private async finish(
        lease: V2ReleaseJobLease,
        outcome: "RETRY" | "SUCCEEDED" | "FAILED",
        errorCode: string | null,
        terminalReason: string | null,
        retryDelayMs: number | null,
        expectedManifestDigest?: string
    ): Promise<void> {
        this.assertLeaseShape(lease);
        try {
            await this.knex.raw(
                `SELECT public.v2_finish_release_job(
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )`,
                [
                    lease.id,
                    lease.releaseId,
                    lease.kind,
                    lease.owner,
                    lease.leaseVersion,
                    outcome,
                    errorCode,
                    terminalReason,
                    retryDelayMs,
                    expectedManifestDigest ?? null,
                ]
            );
        } catch (error) {
            if (this.isFenceError(error)) throw new V2JobLeaseLostError();
            throw error;
        }
    }
}

export class V2ReleaseJobWorker {
    constructor(
        private readonly queue: V2ReleaseJobQueue,
        private readonly objects: V2WorkerObjectStorage,
        private readonly leaseMs: number,
        private readonly cleanupMinimumAgeMs: number
    ) {
        assertLeaseDuration(leaseMs);
        if (
            !Number.isSafeInteger(cleanupMinimumAgeMs) ||
            cleanupMinimumAgeMs < 100 ||
            cleanupMinimumAgeMs > MAX_CLEANUP_AGE_MS
        )
            throw new Error("quarantine cleanup minimum age is outside bounds");
    }

    async finalizeRelease(
        lease: V2ReleaseJobLease,
        input: {
            applicationId: string;
            releaseId: string;
            uploadId: string;
            defaultPath: string;
        }
    ): Promise<V2ReleaseManifest> {
        if (lease.kind !== "PROCESS_RELEASE")
            throw new Error("release job is not a processing job");
        if (lease.releaseId !== input.releaseId)
            throw new Error("release job does not match release identity");
        let currentLease = await this.queue.renew(lease, this.leaseMs);
        if (
            currentLease.kind !== "PROCESS_RELEASE" ||
            currentLease.releaseId !== input.releaseId
        )
            throw new Error("release job does not match release identity");
        const fence: V2ReleaseFinalizationFence = {
            assertActive: (transaction) =>
                this.queue.assertActiveInTransaction(currentLease, transaction),
            bindWorkIdentity: async (identity) => {
                await this.queue.bindWorkIdentity(currentLease, identity);
            },
            checkpoint: async () => {
                currentLease = await this.queue.renew(
                    currentLease,
                    this.leaseMs
                );
            },
        };
        const result = await this.objects.finalizeRelease({
            ...input,
            finalizationFence: fence,
        });
        const manifestDigest = createHash("sha256")
            .update(Buffer.from(JSON.stringify(result)))
            .digest("hex");
        await this.queue.bindWorkIdentity(currentLease, manifestDigest);
        currentLease = await this.queue.renew(currentLease, this.leaseMs);
        await this.queue.succeed(currentLease, manifestDigest);
        return result;
    }

    async cleanupQuarantine(lease: V2ReleaseJobLease): Promise<void> {
        await this.queue.prepareQuarantineCleanup(
            lease,
            this.cleanupMinimumAgeMs
        );
        let currentLease = await this.queue.renew(lease, this.leaseMs);
        for (let round = 0; round < MAX_CLEANUP_LIST_ROUNDS; round += 1) {
            currentLease = await this.queue.renew(currentLease, this.leaseMs);
            const objects = await this.objects.listQuarantineObjects(
                currentLease.releaseId
            );
            if (objects.length === 0) {
                await this.queue.succeed(currentLease);
                return;
            }
            for (
                let offset = 0;
                offset < objects.length;
                offset += CLEANUP_CONCURRENCY
            ) {
                currentLease = await this.queue.renew(
                    currentLease,
                    this.leaseMs
                );
                await Promise.all(
                    objects
                        .slice(offset, offset + CLEANUP_CONCURRENCY)
                        .map((relativeKey) =>
                            this.objects.deleteQuarantineObject(
                                currentLease.releaseId,
                                relativeKey
                            )
                        )
                );
            }
        }
        throw new Error("quarantine cleanup batch limit reached before empty");
    }
}

export function createV2ReleaseJobQueue(
    knex: Knex,
    retryJitterSeed?: string
): V2ReleaseJobQueue {
    return new V2ReleaseJobQueue(knex, retryJitterSeed);
}
