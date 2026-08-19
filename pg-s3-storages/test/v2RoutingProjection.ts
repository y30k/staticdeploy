import {
    DeleteBucketCommand,
    DeleteObjectsCommand,
    GetObjectCommand,
    ListObjectsV2Command,
    PutObjectCommand,
    S3Client,
} from "@aws-sdk/client-s3";
import { expect } from "chai";
import { knex as createKnex, Knex } from "knex";
import { createHash, generateKeyPairSync, randomUUID } from "node:crypto";

import PgS3Storages, {
    normalizeV2RoutingHost,
    V2ContentRoutingCache,
    V2ProjectionConflictError,
    V2ProjectionReconciler,
    V2PublicationLease,
    V2PublicationQueue,
    V2PublicationWorker,
    V2RoutingSigner,
    V2RoutingSigningKey,
    V2RoutingVerifier,
    V2RoutingProjector,
} from "../src";

const endpoint = process.env.MINIO_TEST_URL ?? "http://127.0.0.1:9000";
const postgresUrl =
    process.env.POSTGRES_TEST_URL ??
    "postgres://postgres:password@127.0.0.1:5432/postgres";
const adminCredentials = {
    accessKeyId: "accessKeyId",
    secretAccessKey: "secretAccessKey",
};
const workerCredentials = {
    accessKeyId: "m304-worker",
    secretAccessKey: "m304-worker-secret",
};
const contentCredentials = {
    accessKeyId: "m304-content",
    secretAccessKey: "m304-content-secret",
};
const controlCredentials = {
    accessKeyId: "m304-control",
    secretAccessKey: "m304-control-secret",
};
const applicationId = randomUUID();
const routingId = randomUUID();
const releaseId = randomUUID();
const sessionId = randomUUID();
const issuer = "https://fixture-idp.invalid";
const subject = "m308-reviewer";
const actorId = `oidc:${createHash("sha256").update(`${issuer.length}:${issuer}${subject.length}:${subject}`).digest("hex")}`;
const host = normalizeV2RoutingHost(`route-${routingId}.fixture.invalid`);
const now = "2026-01-01T00:00:00.000Z";
const later = "2036-01-01T00:00:00.000Z";

function signingKey(
    kid: string,
    status: V2RoutingSigningKey["status"] = "ACTIVE",
    notBefore = now,
    notAfter = later
): V2RoutingSigningKey {
    const pair = generateKeyPairSync("ed25519");
    return {
        kid,
        purpose: "staticdeploy-routing-v1",
        status,
        publicKey: pair.publicKey,
        privateKey: pair.privateKey,
        notBefore,
        notAfter,
    };
}
function publicKeys(keys: readonly V2RoutingSigningKey[]) {
    return keys.map(({ privateKey: _privateKey, ...key }) => key);
}
function lease(input: Partial<V2PublicationLease> = {}): V2PublicationLease {
    return {
        id: randomUUID(),
        applicationId,
        routingId,
        releaseId,
        generation: 1,
        operation: "PUBLISH",
        idempotencyId: randomUUID(),
        manifestDigest: "b".repeat(64),
        objectPrefix: `v2/releases/${applicationId}/${releaseId}`,
        owner: "worker-1",
        leaseExpiresAt: new Date(Date.now() + 60_000),
        leaseVersion: 1,
        attemptCount: 1,
        maxAttempts: 10,
        createdAt: new Date("2026-08-19T00:00:00.000Z"),
        routingKid: "routing-1",
        routingHost: host,
        requestDigest: "d".repeat(64),
        requestActorId: actorId,
        requestAuditId: randomUUID(),
        ...input,
    };
}
function client(credentials: typeof adminCredentials): S3Client {
    return new S3Client({
        endpoint,
        region: "us-east-1",
        forcePathStyle: true,
        credentials,
    });
}

function canonicalForTest(value: unknown): string {
    if (
        value === null ||
        typeof value === "boolean" ||
        typeof value === "string"
    )
        return JSON.stringify(value);
    if (typeof value === "number") return String(value);
    if (Array.isArray(value))
        return `[${value.map(canonicalForTest).join(",")}]`;
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
        .sort()
        .map((key) => `${JSON.stringify(key)}:${canonicalForTest(record[key])}`)
        .join(",")}}`;
}

function manifest(): Buffer {
    return Buffer.from(
        JSON.stringify({
            version: 1,
            applicationId,
            releaseId,
            defaultPath: "index.html",
            files: [
                {
                    path: "index.html",
                    size: 2,
                    mime: "text/html; charset=utf-8",
                    sha256: createHash("sha256").update("ok").digest("hex"),
                },
            ],
            sourceDownload: { sha256: "c".repeat(64), size: 2 },
        })
    );
}

describe("M3-08 routing projection", () => {
    it("TM-KEY-01: enforces public-only verification, matching Ed25519 keys, windows, rotation and revocation", () => {
        const active = signingKey("routing-1");
        const overlap = signingKey("routing-old", "OVERLAP");
        const signer = new V2RoutingSigner([active, overlap]);
        const projected = lease();
        const body = new V2RoutingProjector(
            {} as S3Client,
            "routing-test",
            signer
        ).documentFor(projected);
        const verifier = new V2RoutingVerifier(publicKeys([active, overlap]));
        expect(
            verifier.verify(body, { routingId, applicationId, host }).kid
        ).to.equal("routing-1");
        expect(() => new V2RoutingVerifier([active])).to.throw("private key");
        expect(() => new V2RoutingSigner([active, active])).to.throw(
            "duplicate"
        );
        const wrongPair = {
            ...active,
            privateKey: signingKey("other").privateKey,
        };
        expect(() => new V2RoutingSigner([wrongPair])).to.throw("do not match");
        const oldBody = signer.sign(
            signer.verifier.verify(body, { routingId, applicationId, host })
                .payload,
            "routing-old"
        );
        const revoked = new V2RoutingVerifier(
            publicKeys([active, { ...overlap, status: "REVOKED" }])
        );
        expect(() =>
            revoked.verify(oldBody, { routingId, applicationId, host })
        ).to.throw("revoked");
        const expiredSigner = new V2RoutingSigner([
            signingKey(
                "expired",
                "ACTIVE",
                "2020-01-01T00:00:00.000Z",
                "2021-01-01T00:00:00.000Z"
            ),
        ]);
        expect(() =>
            expiredSigner.sign(
                signer.verifier.verify(body, { routingId, applicationId, host })
                    .payload
            )
        ).to.throw("not valid");
    });

    it("TM-PROJ-01: rejects tampering, wrong host/context, extra members, algorithms and noncanonical envelopes", () => {
        const key = signingKey("routing-1");
        const signer = new V2RoutingSigner([key]);
        const verifier = new V2RoutingVerifier(publicKeys([key]));
        const body = new V2RoutingProjector(
            {} as S3Client,
            "routing-test",
            signer
        ).documentFor(lease());
        expect(() =>
            verifier.verify(body, {
                routingId,
                applicationId,
                host: `wrong.${host}`,
            })
        ).to.throw("substitution");
        const tampered = Buffer.from(body);
        tampered[tampered.length - 2] ^= 1;
        expect(() =>
            verifier.verify(tampered, { routingId, applicationId, host })
        ).to.throw();
        const originalEnvelope = JSON.parse(body.toString());
        const originalHeader = JSON.parse(
            Buffer.from(originalEnvelope.protected, "base64url").toString()
        );
        for (const header of [
            { ...originalHeader, alg: "none" },
            { alg: "EdDSA", typ: originalHeader.typ },
            { ...originalHeader, kid: "unknown" },
            { ...originalHeader, kid: "bad kid" },
            { ...originalHeader, crit: ["exp"] },
            { ...originalHeader, extra: true },
        ]) {
            const envelope = {
                ...originalEnvelope,
                protected: Buffer.from(canonicalForTest(header)).toString(
                    "base64url"
                ),
            };
            expect(() =>
                verifier.verify(Buffer.from(canonicalForTest(envelope)), {
                    routingId,
                    applicationId,
                    host,
                })
            ).to.throw();
        }
        const duplicateHeader = Buffer.from(
            `{"alg":"EdDSA","alg":"EdDSA","kid":"routing-1","typ":"staticdeploy-routing+jws"}`
        ).toString("base64url");
        expect(() =>
            verifier.verify(
                Buffer.from(
                    canonicalForTest({
                        ...originalEnvelope,
                        protected: duplicateHeader,
                    })
                ),
                { routingId, applicationId, host }
            )
        ).to.throw();
        const payload = JSON.parse(
            Buffer.from(
                JSON.parse(body.toString()).payload,
                "base64url"
            ).toString()
        );
        payload.extra = true;
        expect(() => signer.sign(payload)).to.throw("not closed");
        delete payload.extra;
        for (const [field, value] of [
            ["purpose", "staticdeploy-preview-v1"],
            ["audience", "staticdeploy-preview"],
        ] as const) {
            const prior = payload[field];
            payload[field] = value;
            expect(() => signer.sign(payload)).to.throw();
            payload[field] = prior;
        }
        expect(() =>
            verifier.verify(Buffer.from(` ${body.toString()}`), {
                routingId,
                applicationId,
                host,
            })
        ).to.throw("canonical");
    });

    it("bounds an oversized chunked routing body when ContentLength is absent", async () => {
        const key = signingKey("routing-1");
        const verifier = new V2RoutingVerifier(publicKeys([key]));
        const oversized = {
            send: async () => ({
                Body: (async function* () {
                    yield Buffer.alloc(10 * 1024);
                    yield Buffer.alloc(10 * 1024);
                })(),
                ETag: '"oversized"',
            }),
        } as unknown as S3Client;
        let rejected: unknown;
        try {
            await new V2ContentRoutingCache(
                oversized,
                "routing-test",
                routingId,
                applicationId,
                host,
                verifier
            ).refresh();
        } catch (error) {
            rejected = error;
        }
        expect((rejected as Error).message).to.include("byte limit");
    });

    describe("disposable PostgreSQL and MinIO", () => {
        const bucket = `m304-m308-${randomUUID()}`;
        const admin = client(adminCredentials);
        const workerS3 = client(workerCredentials);
        const contentS3 = client(contentCredentials);
        const controlS3 = client(controlCredentials);
        const module = new PgS3Storages({
            postgresUrl,
            s3Config: {
                bucket,
                endpoint,
                region: "us-east-1",
                forcePathStyle: true,
                ...adminCredentials,
            },
        });
        const knex: Knex = (module as any).knex;
        const active = signingKey("routing-1");
        const signer = new V2RoutingSigner([active]);
        const verifier = new V2RoutingVerifier(publicKeys([active]));
        const projector = new V2RoutingProjector(workerS3, bucket, signer);
        const queue = new V2PublicationQueue(knex);
        let manifestDigest: string;

        before(async () => {
            await module.setup();
            await seedAuthorization(knex);
            const bytes = manifest();
            manifestDigest = createHash("sha256").update(bytes).digest("hex");
            await seedApplication(knex, manifestDigest);
            await admin.send(
                new PutObjectCommand({
                    Bucket: bucket,
                    Key: `v2/releases/${applicationId}/${releaseId}/manifest.json`,
                    Body: bytes,
                    IfNoneMatch: "*",
                })
            );
        });
        after(async () => {
            try {
                const listed = await admin.send(
                    new ListObjectsV2Command({ Bucket: bucket })
                );
                if ((listed.Contents ?? []).length > 0)
                    await admin.send(
                        new DeleteObjectsCommand({
                            Bucket: bucket,
                            Delete: {
                                Objects: listed.Contents!.map((object) => ({
                                    Key: object.Key!,
                                })),
                            },
                        })
                    );
                await admin.send(new DeleteBucketCommand({ Bucket: bucket }));
            } finally {
                await module.destroy();
                for (const item of [admin, workerS3, contentS3, controlS3])
                    item.destroy();
            }
        });

        it("rejects NULL publication claim bounds and preserves combined pending/expired priority", async () => {
            const snapshot = async () =>
                knex("v2_publication_outbox")
                    .select(
                        "id",
                        "state",
                        "lease_owner",
                        "lease_expires_at",
                        "attempt_count",
                        "lease_version",
                        "next_attempt_at"
                    )
                    .orderBy("id");
            const before = await snapshot();
            for (const values of [
                [null, 1000, 1],
                ["null-lease", null, 1],
                ["null-limit", 1000, null],
            ]) {
                let rejected: unknown;
                try {
                    await knex.raw(
                        "select * from public.v2_claim_publications(?, ?, ?)",
                        values
                    );
                } catch (error) {
                    rejected = error;
                }
                expect(rejected).to.be.instanceOf(Error);
                expect((rejected as Error).message).to.include(
                    "publication claim arguments are invalid"
                );
                expect(await snapshot()).to.deep.equal(before);
            }

            const expiredSeeds = await Promise.all([
                seedClaimCandidate(knex, new Date("2000-01-01T00:00:00.000Z")),
                seedClaimCandidate(knex, new Date("2000-01-01T00:00:01.000Z")),
            ]);
            const initiallyClaimed = (
                await knex.raw(
                    "select * from public.v2_claim_publications(?, ?, ?)",
                    ["priority-seed", 100, 2]
                )
            ).rows;
            expect(
                initiallyClaimed.map((row: { id: string }) => row.id)
            ).to.deep.equal(expiredSeeds.map((seed) => seed.outboxId));
            await knex.raw("select pg_sleep(0.15)");

            const pendingSeeds = await Promise.all([
                seedClaimCandidate(knex, new Date("2000-01-02T00:00:00.000Z")),
                seedClaimCandidate(knex, new Date("2000-01-02T00:00:01.000Z")),
            ]);
            const firstExpired = await knex("v2_publication_outbox")
                .whereIn(
                    "id",
                    expiredSeeds.map((seed) => seed.outboxId)
                )
                .orderBy("lease_expires_at")
                .orderBy("id")
                .first();
            const combined = (
                await knex.raw(
                    "select * from public.v2_claim_publications(?, ?, ?)",
                    ["priority-combined", 30_000, 3]
                )
            ).rows;
            expect(combined).to.have.length(3);
            expect(combined.map((row: { id: string }) => row.id)).to.deep.equal(
                [...pendingSeeds.map((seed) => seed.outboxId), firstExpired.id]
            );
            expect(
                combined.map((row: { lease_owner: string }) => row.lease_owner)
            ).to.deep.equal([
                "priority-combined",
                "priority-combined",
                "priority-combined",
            ]);
            expect(
                combined.map((row: { attempt_count: number }) =>
                    Number(row.attempt_count)
                )
            ).to.deep.equal([1, 1, 2]);
            expect(
                combined.map((row: { lease_version: string }) =>
                    Number(row.lease_version)
                )
            ).to.deep.equal([1, 1, 2]);
        });

        it("starts a minimum publication lease from the post-lock update clock", async () => {
            await queue.claimDue({
                owner: "post-lock-drain",
                leaseMs: 30_000,
                limit: 100,
            });
            const seed = await seedClaimCandidate(
                knex,
                new Date("2000-01-03T00:00:00.000Z")
            );
            const lockConnection = createKnex({
                client: "pg",
                connection: postgresUrl,
                pool: { min: 0, max: 1 },
            });
            const claimConnection = createKnex({
                client: "pg",
                connection: postgresUrl,
                pool: { min: 0, max: 1 },
            });
            const transaction = await lockConnection.transaction();
            try {
                await transaction.raw(
                    "LOCK TABLE public.v2_applications IN ACCESS EXCLUSIVE MODE"
                );
                let settled = false;
                const claim = new V2PublicationQueue(claimConnection)
                    .claimDue({
                        owner: "post-lock-clock",
                        leaseMs: 100,
                        limit: 1,
                    })
                    .finally(() => {
                        settled = true;
                    });
                await new Promise((resolve) => setTimeout(resolve, 175));
                expect(settled).to.equal(false);
                await transaction.commit();
                const claimed = await claim;
                expect(claimed.map((row) => row.id)).to.deep.equal([
                    seed.outboxId,
                ]);
                const liveness = (
                    await knex.raw(
                        `SELECT lease_expires_at > clock_timestamp() AS live,
                                extract(epoch FROM
                                    (lease_expires_at - clock_timestamp())) * 1000
                                    AS remaining_ms
                           FROM public.v2_publication_outbox WHERE id = ?`,
                        [seed.outboxId]
                    )
                ).rows[0];
                expect(liveness.live).to.equal(true);
                expect(Number(liveness.remaining_ms)).to.be.greaterThan(0);
            } finally {
                if (!transaction.isCompleted()) await transaction.rollback();
                await Promise.all([
                    lockConnection.destroy(),
                    claimConnection.destroy(),
                ]);
            }
        });

        it("qualifies real LOGIN control/worker identities and rejects every excess database capability", async () => {
            const suffix = randomUUID().replace(/-/g, "");
            const controlRole = `m308_control_${suffix}`;
            const workerRole = `m308_worker_${suffix}`;
            const parentRole = `m308_parent_${suffix}`;
            const password = `m308-${suffix}`;
            const quote = (value: string) => `"${value}"`;
            const controlFunctions = [
                "v2_begin_oidc_login(uuid,text,text,text,bytea,bytea,text,text,text,integer)",
                "v2_consume_oidc_login(uuid,text)",
                "v2_create_or_replace_session(uuid,uuid,text,text,jsonb,text,text,bytea,bytea,integer,integer)",
                "v2_read_session(uuid)",
                "v2_use_session(uuid,integer)",
                "v2_rotate_session_envelope(uuid,text,text,bytea,bytea)",
                "v2_revoke_session(uuid,text)",
                "v2_cleanup_auth_state(bigint,integer)",
                "v2_initialize_authorization_policy(text[],bigint,text)",
                "v2_authorization_policy_identity()",
                "v2_authorize_operation(uuid,uuid,text[],bigint,uuid,text)",
                "v2_replace_bindings(uuid,uuid,text[],bigint,uuid,bigint,text,text,jsonb)",
                "v2_request_publication(uuid,uuid,text,uuid,uuid,uuid,uuid,uuid,text[],bigint,text,text)",
                "v2_publication_operation(uuid)",
            ];
            const workerFunctions = [
                "v2_claim_release_jobs(text,integer,integer)",
                "v2_renew_release_job(uuid,text,bigint,integer)",
                "v2_assert_release_job_lease(uuid,text,bigint)",
                "v2_bind_release_job_work(uuid,text,bigint,text)",
                "v2_prepare_quarantine_cleanup(uuid,text,bigint,bigint)",
                "v2_finish_release_job(uuid,uuid,text,text,bigint,text,text,text,integer,text)",
                "v2_claim_publications(text,integer,integer)",
                "v2_bind_publication_key(uuid,text,bigint,text)",
                "v2_renew_publication(uuid,text,bigint,integer)",
                "v2_assert_publication_projectable(uuid,text,bigint)",
                "v2_finish_projected_publication_attempt(uuid,text,bigint,text,text,integer,uuid)",
                "v2_acknowledge_projected_publication(uuid,text,bigint,text,text,text,uuid)",
            ];
            await knex.raw(
                `CREATE ROLE ${quote(controlRole)} LOGIN PASSWORD '${password}'`
            );
            await knex.raw(
                `CREATE ROLE ${quote(workerRole)} LOGIN PASSWORD '${password}'`
            );
            await knex.raw(`CREATE ROLE ${quote(parentRole)} NOLOGIN`);
            await knex.raw(
                `GRANT USAGE ON SCHEMA public TO ${quote(controlRole)}, ${quote(workerRole)}`
            );
            await knex.raw(
                `GRANT EXECUTE ON FUNCTION ${controlFunctions.map((name) => `public.${name}`).join(",")} TO ${quote(controlRole)}`
            );
            await knex.raw(
                `GRANT EXECUTE ON FUNCTION ${workerFunctions.map((name) => `public.${name}`).join(",")} TO ${quote(workerRole)}`
            );
            const urlFor = (role: string): string => {
                const url = new URL(postgresUrl);
                url.username = role;
                url.password = password;
                return url.toString();
            };
            const controlDb = createKnex({
                client: "pg",
                connection: urlFor(controlRole),
                pool: { min: 0, max: 2 },
            });
            const workerDb = createKnex({
                client: "pg",
                connection: urlFor(workerRole),
                pool: { min: 0, max: 2 },
            });
            const controlQueue = new V2PublicationQueue(controlDb);
            const workerQueue = new V2PublicationQueue(workerDb);
            const expectNotReady = async (): Promise<void> => {
                let rejected: unknown;
                try {
                    await controlQueue.verifyReady("CONTROL");
                } catch (error) {
                    rejected = error;
                }
                expect(rejected).to.be.instanceOf(Error);
            };
            try {
                const ambientSchemaCapability = await controlDb.raw(
                    "select has_schema_privilege(current_user, 'public', 'CREATE') as can_create"
                );
                expect(ambientSchemaCapability.rows[0].can_create).to.equal(
                    false
                );
                await controlQueue.verifyReady("CONTROL");
                await workerQueue.verifyReady("WORKER");
                const roleDigest = "8".repeat(64);
                const roleIdempotency = await seedIdempotency(
                    knex,
                    "release.publish",
                    roleDigest
                );
                const roleRequested = await controlQueue.request({
                    actor: principal(),
                    applicationId,
                    routingHost: host,
                    releaseId,
                    operation: "PUBLISH",
                    idempotencyId: roleIdempotency,
                    requestDigest: roleDigest,
                });
                const roleClaims = await workerQueue.claimDue({
                    owner: "role-qualified-worker",
                    leaseMs: 30_000,
                    limit: 100,
                });
                const roleLease = roleClaims.find(
                    (item) => item.id === roleRequested.id
                );
                expect(roleLease).not.to.equal(undefined);
                await workerQueue.fail(
                    roleLease!,
                    "CONTROLLED_ROLE_QUALIFICATION"
                );
                let deniedWorker: unknown;
                let deniedControlClaim: unknown;
                let deniedControlAck: unknown;
                try {
                    await controlQueue.claimDue({
                        owner: "forbidden",
                        leaseMs: 1000,
                    });
                } catch (error) {
                    deniedControlClaim = error;
                }
                try {
                    await controlDb.raw(
                        "SELECT public.v2_acknowledge_projected_publication(?::uuid, ?, ?, ?, ?, ?, ?::uuid)",
                        [
                            randomUUID(),
                            "forbidden",
                            1,
                            "0".repeat(64),
                            '"etag"',
                            null,
                            randomUUID(),
                        ]
                    );
                } catch (error) {
                    deniedControlAck = error;
                }
                try {
                    await workerQueue.request({
                        actor: principal(),
                        applicationId,
                        routingHost: host,
                        releaseId,
                        operation: "PUBLISH",
                        idempotencyId: randomUUID(),
                        requestDigest: "9".repeat(64),
                    });
                } catch (error) {
                    deniedWorker = error;
                }
                expect(deniedControlClaim).to.be.instanceOf(Error);
                expect(deniedControlAck).to.be.instanceOf(Error);
                expect(deniedWorker).to.be.instanceOf(Error);

                await knex.raw(`ALTER ROLE ${quote(controlRole)} SUPERUSER`);
                await expectNotReady();
                await knex.raw(`ALTER ROLE ${quote(controlRole)} NOSUPERUSER`);
                await knex.raw(
                    `GRANT CREATE ON DATABASE ${quote(new URL(postgresUrl).pathname.slice(1))} TO ${quote(controlRole)}`
                );
                await expectNotReady();
                await knex.raw(
                    `REVOKE CREATE ON DATABASE ${quote(new URL(postgresUrl).pathname.slice(1))} FROM ${quote(controlRole)}`
                );
                await knex.raw(
                    `GRANT CREATE ON SCHEMA public TO ${quote(controlRole)}`
                );
                await expectNotReady();
                await knex.raw(
                    `REVOKE CREATE ON SCHEMA public FROM ${quote(controlRole)}`
                );
                await knex.raw(
                    `GRANT SELECT ON public.v2_publication_outbox TO ${quote(controlRole)}`
                );
                await expectNotReady();
                await knex.raw(
                    `REVOKE SELECT ON public.v2_publication_outbox FROM ${quote(controlRole)}`
                );
                await knex.raw(
                    `GRANT ${quote(parentRole)} TO ${quote(controlRole)}`
                );
                await expectNotReady();
                await knex.raw(
                    `REVOKE ${quote(parentRole)} FROM ${quote(controlRole)}`
                );
                await knex.raw(
                    `GRANT EXECUTE ON FUNCTION public.v2_claim_publications(text,integer,integer) TO ${quote(controlRole)}`
                );
                await expectNotReady();
                await knex.raw(
                    `REVOKE EXECUTE ON FUNCTION public.v2_claim_publications(text,integer,integer) FROM ${quote(controlRole)}`
                );
                await knex.raw(
                    `GRANT EXECUTE ON FUNCTION public.v2_acknowledge_publication(uuid,text,bigint,text) TO ${quote(controlRole)}`
                );
                await expectNotReady();
                await knex.raw(
                    `REVOKE EXECUTE ON FUNCTION public.v2_acknowledge_publication(uuid,text,bigint,text) FROM ${quote(controlRole)}`
                );
                await knex.raw(
                    `CREATE TABLE public.${quote(`m308_owned_${suffix}`)} (id integer)`
                );
                await knex.raw(
                    `ALTER TABLE public.${quote(`m308_owned_${suffix}`)} OWNER TO ${quote(controlRole)}`
                );
                await expectNotReady();
                await knex.raw(
                    `DROP TABLE public.${quote(`m308_owned_${suffix}`)}`
                );
                await controlQueue.verifyReady("CONTROL");
            } finally {
                await controlDb.destroy();
                await workerDb.destroy();
                await knex.raw(`DROP OWNED BY ${quote(controlRole)} CASCADE`);
                await knex.raw(`DROP OWNED BY ${quote(workerRole)} CASCADE`);
                await knex.raw(`DROP ROLE ${quote(controlRole)}`);
                await knex.raw(`DROP ROLE ${quote(workerRole)}`);
                await knex.raw(`DROP ROLE ${quote(parentRole)}`);
            }
        });

        it("denies publication before desired/idempotency mutation while retaining the bounded authorization audit", async () => {
            const deniedSession = randomUUID();
            const deniedSubject = "denied-user";
            const deniedActor = `oidc:${createHash("sha256").update(`${issuer.length}:${issuer}${deniedSubject.length}:${deniedSubject}`).digest("hex")}`;
            await knex("v2_sessions").insert({
                id: deniedSession,
                subject_id: deniedSubject,
                issuer,
                claims: JSON.stringify({ groups: [] }),
                claims_version: 1,
                csrf_token_digest: "b".repeat(64),
                token_key_id: "fixture",
                token_nonce: Buffer.alloc(12),
                encrypted_token_material: Buffer.alloc(32),
                created_at: new Date(),
                last_seen_at: new Date(),
                idle_expires_at: new Date(Date.now() + 3_600_000),
                absolute_expires_at: new Date(Date.now() + 7_200_000),
            });
            const id = randomUUID();
            await knex("v2_idempotency").insert({
                id,
                actor_id: deniedActor,
                scope: "release.publish",
                idempotency_key: `m308-${randomUUID()}`,
                request_digest: "f".repeat(64),
                state: "IN_PROGRESS",
                expires_at: new Date(Date.now() + 3_600_000),
            });
            const before = await knex("v2_applications")
                .where({ id: applicationId })
                .first();
            let denied: unknown;
            try {
                await queue.request({
                    actor: {
                        sessionId: deniedSession,
                        subjectId: deniedSubject,
                        issuer,
                        groups: [],
                        claimsVersion: 1,
                    },
                    applicationId,
                    routingHost: host,
                    releaseId,
                    operation: "PUBLISH",
                    idempotencyId: id,
                    requestDigest: "f".repeat(64),
                });
            } catch (error) {
                denied = error;
            }
            expect(denied).to.be.instanceOf(Error);
            const after = await knex("v2_applications")
                .where({ id: applicationId })
                .first();
            expect(after.desired_generation).to.equal(
                before.desired_generation
            );
            expect(
                await knex("v2_publication_outbox").where({
                    idempotency_id: id,
                })
            ).to.have.length(0);
            expect(
                await knex("v2_audit_events").where({
                    action: "AUTHORIZATION_DECISION",
                    actor_id: deniedActor,
                })
            ).to.have.length(1);
        });

        it("rolls desired state, requested audit, and outbox back together on a late audit failure", async () => {
            const duplicateAuditId = randomUUID();
            await knex.raw(
                "SELECT * FROM public.v2_authorize_operation(?, ?, ?, ?, ?, ?)",
                [
                    duplicateAuditId,
                    sessionId,
                    ["fixture-admin"],
                    1,
                    applicationId,
                    "PUBLISH",
                ]
            );
            const idempotencyId = await seedIdempotency(
                knex,
                "release.publish",
                "6".repeat(64)
            );
            const before = await knex("v2_applications")
                .where({ id: applicationId })
                .first();
            let failure: unknown;
            try {
                await queue.request({
                    actor: principal(),
                    applicationId,
                    routingHost: host,
                    releaseId,
                    operation: "PUBLISH",
                    idempotencyId,
                    requestDigest: "6".repeat(64),
                    auditId: duplicateAuditId,
                });
            } catch (error) {
                failure = error;
            }
            expect(failure).to.be.instanceOf(Error);
            const after = await knex("v2_applications")
                .where({ id: applicationId })
                .first();
            expect(after.desired_generation).to.equal(
                before.desired_generation
            );
            expect(
                await knex("v2_publication_outbox").where({
                    idempotency_id: idempotencyId,
                })
            ).to.have.length(0);
            expect(
                (
                    await knex("v2_idempotency")
                        .where({ id: idempotencyId })
                        .first()
                ).state
            ).to.equal("IN_PROGRESS");
        });

        it("serializes concurrent authorized requests on independent connections into monotonic generations", async () => {
            const leftDigest = "a".repeat(64);
            const rightDigest = "b".repeat(64);
            const [leftId, rightId] = await Promise.all([
                seedIdempotency(knex, "release.publish", leftDigest),
                seedIdempotency(knex, "release.publish", rightDigest),
            ]);
            const leftDb = createKnex({
                client: "pg",
                connection: postgresUrl,
                pool: { min: 0, max: 1 },
            });
            const rightDb = createKnex({
                client: "pg",
                connection: postgresUrl,
                pool: { min: 0, max: 1 },
            });
            try {
                const [left, right] = await Promise.all([
                    new V2PublicationQueue(leftDb).request({
                        actor: principal(),
                        applicationId,
                        routingHost: host,
                        releaseId,
                        operation: "PUBLISH",
                        idempotencyId: leftId,
                        requestDigest: leftDigest,
                    }),
                    new V2PublicationQueue(rightDb).request({
                        actor: principal(),
                        applicationId,
                        routingHost: host,
                        releaseId,
                        operation: "PUBLISH",
                        idempotencyId: rightId,
                        requestDigest: rightDigest,
                    }),
                ]);
                expect(Math.abs(left.generation - right.generation)).to.equal(
                    1
                );
                expect(
                    new Set([left.generation, right.generation]).size
                ).to.equal(2);
            } finally {
                await Promise.all([leftDb.destroy(), rightDb.destroy()]);
            }
        });

        it("rejects expired publication idempotency before desired state mutation", async () => {
            const id = randomUUID();
            const digest = createHash("sha256")
                .update(`expired:${id}`)
                .digest("hex");
            await knex("v2_idempotency").insert({
                id,
                actor_id: actorId,
                scope: "release.publish",
                idempotency_key: `m308-${randomUUID()}`,
                request_digest: digest,
                state: "IN_PROGRESS",
                created_at: new Date(Date.now() - 7_200_000),
                expires_at: new Date(Date.now() - 3_600_000),
            });
            const before = await knex("v2_applications")
                .where({ id: applicationId })
                .first();
            let rejected: unknown;
            try {
                await queue.request({
                    actor: principal(),
                    applicationId,
                    routingHost: host,
                    releaseId,
                    operation: "PUBLISH",
                    idempotencyId: id,
                    requestDigest: digest,
                });
            } catch (error) {
                rejected = error;
            }
            expect(rejected).to.be.instanceOf(Error);
            const after = await knex("v2_applications")
                .where({ id: applicationId })
                .first();
            expect(after.desired_generation).to.equal(
                before.desired_generation
            );
        });

        it("rejects a missing READY manifest before any routing generation or pointer write", async () => {
            const missingRoutingId = randomUUID();
            const missingReleaseId = randomUUID();
            let failure: unknown;
            try {
                await projector.project(
                    lease({
                        routingId: missingRoutingId,
                        releaseId: missingReleaseId,
                        objectPrefix: `v2/releases/${applicationId}/${missingReleaseId}`,
                    })
                );
            } catch (error) {
                failure = error;
            }
            expect(failure).to.be.instanceOf(Error);
            let generation: unknown;
            let current: unknown;
            try {
                generation = await admin.send(
                    new GetObjectCommand({
                        Bucket: bucket,
                        Key: `v2/routing/${missingRoutingId}/generations/1.json`,
                    })
                );
            } catch (error) {
                expect(error).to.be.instanceOf(Error);
            }
            try {
                current = await admin.send(
                    new GetObjectCommand({
                        Bucket: bucket,
                        Key: `v2/routing/${missingRoutingId}/current.json`,
                    })
                );
            } catch (error) {
                expect(error).to.be.instanceOf(Error);
            }
            expect(generation).to.equal(undefined);
            expect(current).to.equal(undefined);
        });

        it("rejects corrupt and cross-release substituted manifests before routing writes", async () => {
            for (const kind of ["corrupt", "substituted"] as const) {
                const testRoutingId = randomUUID();
                const testReleaseId = randomUUID();
                const bytes =
                    kind === "corrupt" ? Buffer.from("{not-json") : manifest();
                const digest = createHash("sha256").update(bytes).digest("hex");
                await admin.send(
                    new PutObjectCommand({
                        Bucket: bucket,
                        Key: `v2/releases/${applicationId}/${testReleaseId}/manifest.json`,
                        Body: bytes,
                    })
                );
                let rejected: unknown;
                try {
                    await projector.project(
                        lease({
                            routingId: testRoutingId,
                            releaseId: testReleaseId,
                            objectPrefix: `v2/releases/${applicationId}/${testReleaseId}`,
                            manifestDigest: digest,
                        })
                    );
                } catch (error) {
                    rejected = error;
                }
                expect(rejected).to.be.instanceOf(Error);
                let generation: unknown;
                try {
                    generation = await admin.send(
                        new GetObjectCommand({
                            Bucket: bucket,
                            Key: `v2/routing/${testRoutingId}/generations/1.json`,
                        })
                    );
                } catch (error) {
                    expect(error).to.be.instanceOf(Error);
                }
                expect(generation).to.equal(undefined);
            }
        });

        it("PROJ-01: atomically authorizes, requests, fences, verifies READY bytes, projects, reads back and acknowledges", async () => {
            const idempotencyId = await seedIdempotency(
                knex,
                "release.publish",
                "d".repeat(64)
            );
            const requested = await queue.request({
                actor: principal(),
                applicationId,
                routingHost: host,
                releaseId,
                operation: "PUBLISH",
                idempotencyId,
                requestDigest: "d".repeat(64),
            });
            const claimed = await claimForApplication(
                queue,
                requested.id,
                "worker-1"
            );
            expect(claimed.objectPrefix).to.equal(
                `v2/releases/${applicationId}/${releaseId}`
            );
            await workerS3.send(
                new GetObjectCommand({
                    Bucket: bucket,
                    Key: `${claimed.objectPrefix}/manifest.json`,
                })
            );
            const receipt = await new V2PublicationWorker(
                queue,
                projector,
                signer
            ).apply(claimed);
            expect(receipt.document.payload.host).to.equal(host);
            const app = await knex("v2_applications")
                .where({ id: applicationId })
                .first();
            expect(Number(app.served_generation)).to.equal(
                requested.generation
            );
            const outbox = await knex("v2_publication_outbox")
                .where({ id: requested.id })
                .first();
            expect(outbox.state).to.equal("ACKNOWLEDGED");
            expect(outbox.request_digest).to.equal("d".repeat(64));
            expect(
                (
                    await knex("v2_idempotency")
                        .where({ id: idempotencyId })
                        .first()
                ).state
            ).to.equal("COMPLETED");
        });

        it("leaves serving unchanged and retries when pointer read-back differs", async () => {
            const idempotencyId = await seedIdempotency(
                knex,
                "application.unpublish",
                "5".repeat(64)
            );
            const requested = await queue.request({
                actor: principal(),
                applicationId,
                routingHost: host,
                releaseId: null,
                operation: "UNPUBLISH",
                idempotencyId,
                requestDigest: "5".repeat(64),
            });
            const claimed = await claimForApplication(
                queue,
                requested.id,
                "worker-readback"
            );
            const servedBefore = await knex("v2_applications")
                .where({ id: applicationId })
                .first();
            let currentReads = 0;
            const readbackFault = {
                send: async (command: unknown, options: unknown) => {
                    if (
                        command instanceof GetObjectCommand &&
                        command.input.Key?.endsWith("/current.json")
                    ) {
                        currentReads += 1;
                        if (currentReads === 2)
                            return {
                                Body: (async function* () {
                                    yield Buffer.from(
                                        "controlled-readback-drift"
                                    );
                                })(),
                                ETag: '"controlled-readback-drift"',
                            };
                    }
                    return workerS3.send(command as any, options as any);
                },
            } as S3Client;
            let failure: unknown;
            try {
                await new V2PublicationWorker(
                    queue,
                    new V2RoutingProjector(readbackFault, bucket, signer),
                    signer
                ).apply(claimed);
            } catch (error) {
                failure = error;
            }
            expect(failure).to.be.instanceOf(Error);
            await queue.retry(claimed, "READBACK_MISMATCH", 900_000);
            const outbox = await knex("v2_publication_outbox")
                .where({ id: requested.id })
                .first();
            const servedAfter = await knex("v2_applications")
                .where({ id: applicationId })
                .first();
            expect(outbox.state).to.equal("PENDING");
            expect(servedAfter.served_generation).to.equal(
                servedBefore.served_generation
            );
            expect(
                await knex("v2_audit_events").where({
                    action: "UNPUBLISHED",
                    application_id: applicationId,
                })
            ).to.have.length(0);
        });

        it("fences and terminalizes a superseded pending generation before any S3 side effect", async () => {
            const release = await knex("v2_releases")
                .where({ id: releaseId })
                .first();
            const published = release.published_at !== null;
            const staleOperation = published ? "UNPUBLISH" : "PUBLISH";
            const desiredOperation = published ? "RESTORE" : "UNPUBLISH";
            const staleId = await seedIdempotency(
                knex,
                published ? "application.unpublish" : "release.publish",
                "1".repeat(64)
            );
            const desiredId = await seedIdempotency(
                knex,
                published ? "release.restore" : "application.unpublish",
                "2".repeat(64)
            );
            const stale = await queue.request({
                actor: principal(),
                applicationId,
                routingHost: host,
                releaseId: published ? null : releaseId,
                operation: staleOperation,
                idempotencyId: staleId,
                requestDigest: "1".repeat(64),
            });
            const desired = await queue.request({
                actor: principal(),
                applicationId,
                routingHost: host,
                releaseId: published ? releaseId : null,
                operation: desiredOperation,
                idempotencyId: desiredId,
                requestDigest: "2".repeat(64),
            });
            const claimed = await claimForApplication(
                queue,
                desired.id,
                "worker-superseded"
            );
            expect(claimed.id).to.equal(desired.id);
            expect(
                (
                    await knex("v2_publication_outbox")
                        .where({ id: stale.id })
                        .first()
                ).state
            ).to.equal("FAILED");
            await queue.fail(claimed, "CONTROLLED_TEST_TERMINATION");
        });

        it("reclaims and terminalizes an expired superseded LEASED row with attempts remaining", async () => {
            const release = await knex("v2_releases")
                .where({ id: releaseId })
                .first();
            const published = release.published_at !== null;
            const firstOperation = published ? "UNPUBLISH" : "PUBLISH";
            const secondOperation = published ? "RESTORE" : "UNPUBLISH";
            const firstDigest = "7".repeat(64);
            const secondDigest = "0".repeat(64);
            const firstId = await seedIdempotency(
                knex,
                published ? "application.unpublish" : "release.publish",
                firstDigest
            );
            const first = await queue.request({
                actor: principal(),
                applicationId,
                routingHost: host,
                releaseId: published ? null : releaseId,
                operation: firstOperation,
                idempotencyId: firstId,
                requestDigest: firstDigest,
            });
            const leased = await claimForApplication(
                queue,
                first.id,
                "expired-superseded",
                100
            );
            expect(leased.attemptCount).to.be.lessThan(leased.maxAttempts);
            const secondId = await seedIdempotency(
                knex,
                published ? "release.restore" : "application.unpublish",
                secondDigest
            );
            const second = await queue.request({
                actor: principal(),
                applicationId,
                routingHost: host,
                releaseId: published ? releaseId : null,
                operation: secondOperation,
                idempotencyId: secondId,
                requestDigest: secondDigest,
            });
            await new Promise((resolve) => setTimeout(resolve, 150));
            const desired = await claimForApplication(
                queue,
                second.id,
                "superseded-reclaimer"
            );
            const stale = await knex("v2_publication_outbox")
                .where({ id: first.id })
                .first();
            expect(stale.state).to.equal("FAILED");
            expect(stale.last_error_code).to.equal("SUPERSEDED_GENERATION");
            expect(Number(stale.lease_version)).to.be.greaterThan(
                leased.leaseVersion
            );
            await queue.fail(desired, "CONTROLLED_TEST_TERMINATION");
        });

        it("derives publication retry scheduling from PostgreSQL time instead of host time", async () => {
            const release = await knex("v2_releases")
                .where({ id: releaseId })
                .first();
            const published = release.published_at !== null;
            const operation = published ? "UNPUBLISH" : "PUBLISH";
            const scope = published
                ? "application.unpublish"
                : "release.publish";
            const idempotencyId = await seedIdempotency(
                knex,
                scope,
                "3".repeat(64)
            );
            const requested = await queue.request({
                actor: principal(),
                applicationId,
                routingHost: host,
                releaseId: published ? null : releaseId,
                operation,
                idempotencyId,
                requestDigest: "3".repeat(64),
            });
            const claimed = await claimForApplication(
                queue,
                requested.id,
                "worker-db-clock"
            );
            const before = (
                await knex.raw("SELECT clock_timestamp() AS observed_at")
            ).rows[0].observed_at as Date;
            const originalNow = Date.now;
            Date.now = () => 0;
            try {
                await queue.retry(claimed, "CONTROLLED_RETRY", 900_000);
            } finally {
                Date.now = originalNow;
            }
            const row = await knex("v2_publication_outbox")
                .where({ id: requested.id })
                .first();
            expect(new Date(row.next_attempt_at).getTime()).to.be.greaterThan(
                before.getTime() + 899_000
            );
        });

        it("fences all twelve release S3 checkpoints and rejects an actually expired database lease", async () => {
            for (let failAt = 1; failAt <= 12; failAt += 1) {
                const isolatedRoutingId = randomUUID();
                let checkpoints = 0;
                let rejected: unknown;
                try {
                    await projector.project(
                        lease({
                            routingId: isolatedRoutingId,
                            generation: failAt,
                            manifestDigest,
                        }),
                        async () => {
                            checkpoints += 1;
                            if (checkpoints === failAt)
                                throw new Error("controlled lease fence loss");
                        }
                    );
                } catch (error) {
                    rejected = error;
                }
                expect(rejected).to.be.instanceOf(Error);
                expect(checkpoints).to.equal(failAt);
            }

            const release = await knex("v2_releases")
                .where({ id: releaseId })
                .first();
            const published = release.published_at !== null;
            const operation = published ? "UNPUBLISH" : "PUBLISH";
            const digest = createHash("sha256")
                .update(`expired-worker:${randomUUID()}`)
                .digest("hex");
            const idempotencyId = await seedIdempotency(
                knex,
                published ? "application.unpublish" : "release.publish",
                digest
            );
            const requested = await queue.request({
                actor: principal(),
                applicationId,
                routingHost: host,
                releaseId: published ? null : releaseId,
                operation,
                idempotencyId,
                requestDigest: digest,
            });
            const expired = await claimForApplication(
                queue,
                requested.id,
                "worker-expiry-fence",
                100
            );
            await new Promise((resolve) => setTimeout(resolve, 150));
            let leaseLoss: unknown;
            try {
                await new V2PublicationWorker(queue, projector, signer).apply(
                    expired
                );
            } catch (error) {
                leaseLoss = error;
            }
            expect(leaseLoss).to.be.instanceOf(Error);
            const reclaimed = await claimForApplication(
                queue,
                requested.id,
                "worker-expiry-reclaimer"
            );
            expect(reclaimed.leaseVersion).to.be.greaterThan(
                expired.leaseVersion
            );
            await queue.fail(reclaimed, "CONTROLLED_TEST_TERMINATION");
        });

        it("PROJ-02: deterministically rejects a stale ETag and treats exact duplicate bytes idempotently", async () => {
            const generation50 = lease({
                generation: 50,
                operation: "UNPUBLISH",
                releaseId: null,
                manifestDigest: null,
                objectPrefix: null,
            });
            const first = await projector.project(generation50);
            const duplicate = await projector.project(generation50);
            expect(duplicate.document.digest).to.equal(first.document.digest);
            let olderError: unknown;
            try {
                await projector.project(
                    lease({
                        generation: 49,
                        operation: "UNPUBLISH",
                        releaseId: null,
                        manifestDigest: null,
                        objectPrefix: null,
                    })
                );
            } catch (caught) {
                olderError = caught;
            }
            expect(olderError).to.be.instanceOf(V2ProjectionConflictError);

            const generation52 = lease({
                generation: 52,
                operation: "UNPUBLISH",
                releaseId: null,
                manifestDigest: null,
                objectPrefix: null,
            });
            const generation52Body = projector.documentFor(generation52);
            let injected = false;
            const staleEtagClient = {
                send: async (command: unknown, options: unknown) => {
                    if (
                        !injected &&
                        command instanceof PutObjectCommand &&
                        command.input.Key?.endsWith("/current.json") &&
                        command.input.IfMatch !== undefined
                    ) {
                        injected = true;
                        await admin.send(
                            new PutObjectCommand({
                                Bucket: bucket,
                                Key: `v2/routing/${routingId}/generations/52.json`,
                                Body: generation52Body,
                                IfNoneMatch: "*",
                            })
                        );
                        await admin.send(
                            new PutObjectCommand({
                                Bucket: bucket,
                                Key: `v2/routing/${routingId}/current.json`,
                                Body: generation52Body,
                            })
                        );
                    }
                    return workerS3.send(command as any, options as any);
                },
            } as unknown as S3Client;
            let staleEtagError: unknown;
            try {
                await new V2RoutingProjector(
                    staleEtagClient,
                    bucket,
                    signer
                ).project(
                    lease({
                        generation: 51,
                        operation: "UNPUBLISH",
                        releaseId: null,
                        manifestDigest: null,
                        objectPrefix: null,
                    })
                );
            } catch (error) {
                staleEtagError = error;
            }
            expect(injected).to.equal(true);
            expect(staleEtagError).to.be.instanceOf(V2ProjectionConflictError);
            const current = await admin.send(
                new GetObjectCommand({
                    Bucket: bucket,
                    Key: `v2/routing/${routingId}/current.json`,
                })
            );
            const currentBody = Buffer.from(
                await current.Body!.transformToByteArray()
            );
            expect(
                verifier.verify(currentBody, { routingId, applicationId, host })
                    .payload.generation
            ).to.equal(52);
        });

        it("PROJ-03: preserves last-known-good when current readback is malformed and cold start fails closed", async () => {
            await projector.project(
                lease({
                    generation: 60,
                    operation: "UNPUBLISH",
                    releaseId: null,
                    manifestDigest: null,
                    objectPrefix: null,
                })
            );
            const cache = new V2ContentRoutingCache(
                contentS3,
                bucket,
                routingId,
                applicationId,
                host,
                verifier,
                60
            );
            const initial = await cache.refresh();
            expect(initial.document.payload.generation).to.equal(60);
            const validOld = projector.documentFor(
                lease({
                    generation: 59,
                    operation: "UNPUBLISH",
                    releaseId: null,
                    manifestDigest: null,
                    objectPrefix: null,
                })
            );
            await admin.send(
                new PutObjectCommand({
                    Bucket: bucket,
                    Key: `v2/routing/${routingId}/generations/59.json`,
                    Body: validOld,
                })
            );
            await admin.send(
                new PutObjectCommand({
                    Bucket: bucket,
                    Key: `v2/routing/${routingId}/current.json`,
                    Body: validOld,
                })
            );
            const replay = await cache.refresh();
            expect(replay.source).to.equal("LAST_KNOWN_GOOD");
            expect(replay.document.digest).to.equal(initial.document.digest);
            const sameGenerationConflict = projector.documentFor(
                lease({ generation: 60 })
            );
            await admin.send(
                new PutObjectCommand({
                    Bucket: bucket,
                    Key: `v2/routing/${routingId}/generations/60.json`,
                    Body: sameGenerationConflict,
                })
            );
            await admin.send(
                new PutObjectCommand({
                    Bucket: bucket,
                    Key: `v2/routing/${routingId}/current.json`,
                    Body: sameGenerationConflict,
                })
            );
            const conflicting = await cache.refresh();
            expect(conflicting.source).to.equal("LAST_KNOWN_GOOD");
            expect(conflicting.document.digest).to.equal(
                initial.document.digest
            );
            await admin.send(
                new PutObjectCommand({
                    Bucket: bucket,
                    Key: `v2/routing/${routingId}/current.json`,
                    Body: Buffer.from("tampered"),
                })
            );
            expect((await cache.refresh()).source).to.equal("LAST_KNOWN_GOOD");
            let coldError: unknown;
            try {
                await new V2ContentRoutingCache(
                    contentS3,
                    bucket,
                    routingId,
                    applicationId,
                    host,
                    verifier
                ).refresh();
            } catch (error) {
                coldError = error;
            }
            expect(coldError).to.be.instanceOf(Error);
        });

        it("PROJ-04: completed retries observe the same durable operation and conflicting digest reuse fails", async () => {
            let first = await knex("v2_publication_outbox")
                .where({ application_id: applicationId, state: "ACKNOWLEDGED" })
                .orderBy("generation", "asc")
                .first();
            if (first === undefined) {
                const idempotencyId = await seedIdempotency(
                    knex,
                    "release.publish",
                    "4".repeat(64)
                );
                const requested = await queue.request({
                    actor: principal(),
                    applicationId,
                    routingHost: host,
                    releaseId,
                    operation: "PUBLISH",
                    idempotencyId,
                    requestDigest: "4".repeat(64),
                });
                const claimed = await claimForApplication(
                    queue,
                    requested.id,
                    "worker-proj04"
                );
                await new V2PublicationWorker(queue, projector, signer).apply(
                    claimed
                );
                first = await knex("v2_publication_outbox")
                    .where({ id: requested.id })
                    .first();
            }
            const repeated = await queue.request({
                actor: principal(),
                applicationId,
                routingHost: host,
                releaseId,
                operation: "PUBLISH",
                idempotencyId: first.idempotency_id,
                requestDigest: first.request_digest,
            });
            expect(repeated.id).to.equal(first.id);
            expect((await queue.operation(first.id)).state).to.equal(
                "ACKNOWLEDGED"
            );
            let conflict: unknown;
            try {
                await queue.request({
                    actor: principal(),
                    applicationId,
                    routingHost: host,
                    releaseId,
                    operation: "PUBLISH",
                    idempotencyId: first.idempotency_id,
                    requestDigest: "e".repeat(64),
                });
            } catch (error) {
                conflict = error;
            }
            expect(conflict).to.be.instanceOf(Error);

            const beforeRestore = await knex("v2_releases")
                .where({ id: releaseId })
                .first();
            const routingObjects = await admin.send(
                new ListObjectsV2Command({
                    Bucket: bucket,
                    Prefix: `v2/routing/${routingId}/`,
                })
            );
            if ((routingObjects.Contents ?? []).length > 0)
                await admin.send(
                    new DeleteObjectsCommand({
                        Bucket: bucket,
                        Delete: {
                            Objects: routingObjects.Contents!.map((object) => ({
                                Key: object.Key!,
                            })),
                        },
                    })
                );
            const unpublishDigest = createHash("sha256")
                .update(`unpublish:${randomUUID()}`)
                .digest("hex");
            const unpublishId = await seedIdempotency(
                knex,
                "application.unpublish",
                unpublishDigest
            );
            const unpublish = await queue.request({
                actor: principal(),
                applicationId,
                routingHost: host,
                releaseId: null,
                operation: "UNPUBLISH",
                idempotencyId: unpublishId,
                requestDigest: unpublishDigest,
            });
            await new V2PublicationWorker(queue, projector, signer).apply(
                await claimForApplication(
                    queue,
                    unpublish.id,
                    "worker-unpublish"
                )
            );
            const restoreDigest = createHash("sha256")
                .update(`restore:${randomUUID()}`)
                .digest("hex");
            const restoreId = await seedIdempotency(
                knex,
                "release.restore",
                restoreDigest
            );
            const restore = await queue.request({
                actor: principal(),
                applicationId,
                routingHost: host,
                releaseId,
                operation: "RESTORE",
                idempotencyId: restoreId,
                requestDigest: restoreDigest,
            });
            await new V2PublicationWorker(queue, projector, signer).apply(
                await claimForApplication(queue, restore.id, "worker-restore")
            );
            const afterRestore = await knex("v2_releases")
                .where({ id: releaseId })
                .first();
            expect(afterRestore.version_label).to.equal(
                beforeRestore.version_label
            );
            expect(afterRestore.published_at).to.deep.equal(
                beforeRestore.published_at
            );
            expect(
                await knex("v2_audit_events").where({
                    action: "UNPUBLISHED",
                    application_id: applicationId,
                })
            ).to.have.length(1);
            expect(
                await knex("v2_audit_events").where({
                    action: "RESTORED",
                    application_id: applicationId,
                })
            ).to.have.length(1);
        });

        it("PROJ-05: reports desired, served, outbox, digest, ETag, version, key and release drift without immutable repair", async () => {
            const existingObjects = await admin.send(
                new ListObjectsV2Command({
                    Bucket: bucket,
                    Prefix: `v2/routing/${routingId}/`,
                })
            );
            if ((existingObjects.Contents ?? []).length > 0)
                await admin.send(
                    new DeleteObjectsCommand({
                        Bucket: bucket,
                        Delete: {
                            Objects: existingObjects.Contents!.map(
                                (object) => ({
                                    Key: object.Key!,
                                })
                            ),
                        },
                    })
                );

            const release = await knex("v2_releases")
                .where({ id: releaseId })
                .first();
            if (release.published_at === null) {
                const publishDigest = createHash("sha256")
                    .update(`proj05-publish:${randomUUID()}`)
                    .digest("hex");
                const publishId = await seedIdempotency(
                    knex,
                    "release.publish",
                    publishDigest
                );
                const publish = await queue.request({
                    actor: principal(),
                    applicationId,
                    routingHost: host,
                    releaseId,
                    operation: "PUBLISH",
                    idempotencyId: publishId,
                    requestDigest: publishDigest,
                });
                await new V2PublicationWorker(queue, projector, signer).apply(
                    await claimForApplication(
                        queue,
                        publish.id,
                        "proj05-publish"
                    )
                );
            }
            const unpublishDigest = createHash("sha256")
                .update(`proj05-unpublish:${randomUUID()}`)
                .digest("hex");
            const unpublishId = await seedIdempotency(
                knex,
                "application.unpublish",
                unpublishDigest
            );
            const unpublish = await queue.request({
                actor: principal(),
                applicationId,
                routingHost: host,
                releaseId: null,
                operation: "UNPUBLISH",
                idempotencyId: unpublishId,
                requestDigest: unpublishDigest,
            });
            await new V2PublicationWorker(queue, projector, signer).apply(
                await claimForApplication(
                    queue,
                    unpublish.id,
                    "proj05-unpublish"
                )
            );
            const served = await knex("v2_applications")
                .where({ id: applicationId })
                .first();
            const servedGeneration = Number(served.served_generation);
            expect(servedGeneration).to.equal(unpublish.generation);
            expect(servedGeneration).to.be.greaterThan(1);

            const driftKey = signingKey("routing-drift", "OVERLAP");
            const driftSigner = new V2RoutingSigner([active, driftKey]);
            const driftVerifier = new V2RoutingVerifier(
                publicKeys([active, driftKey])
            );
            const validOldGeneration = servedGeneration - 1;
            const validOld = new V2RoutingProjector(
                workerS3,
                bucket,
                driftSigner
            ).documentFor(
                lease({
                    generation: validOldGeneration,
                    operation: "PUBLISH",
                })
            );
            await admin.send(
                new PutObjectCommand({
                    Bucket: bucket,
                    Key: `v2/routing/${routingId}/generations/${validOldGeneration}.json`,
                    Body: validOld,
                })
            );
            await admin.send(
                new PutObjectCommand({
                    Bucket: bucket,
                    Key: `v2/routing/${routingId}/current.json`,
                    Body: validOld,
                })
            );
            const replay = await new V2ProjectionReconciler(
                knex,
                contentS3,
                bucket,
                driftVerifier
            ).inspect(applicationId, host);
            expect(replay.objectGeneration).to.equal(validOldGeneration);
            expect(replay.reasons).to.include("SERVED_OBJECT_DRIFT");
            expect(replay.reasons).to.include("DESIRED_OBJECT_DRIFT");
            expect(replay.reasons).to.include("VERSION_HISTORY_UNATTESTABLE");

            const conflicting = new V2RoutingProjector(
                workerS3,
                bucket,
                driftSigner
            ).documentFor(
                lease({
                    generation: servedGeneration,
                    operation: "PUBLISH",
                    routingKid: driftKey.kid,
                })
            );
            await admin.send(
                new PutObjectCommand({
                    Bucket: bucket,
                    Key: `v2/routing/${routingId}/generations/${servedGeneration}.json`,
                    Body: conflicting,
                })
            );
            await admin.send(
                new PutObjectCommand({
                    Bucket: bucket,
                    Key: `v2/routing/${routingId}/current.json`,
                    Body: conflicting,
                })
            );
            await knex.raw(
                "ALTER TABLE public.v2_publication_outbox DISABLE TRIGGER v2_publication_outbox_guard"
            );
            await knex.raw(
                "ALTER TABLE public.v2_publication_outbox DISABLE TRIGGER v2_outbox_projection_context_guard"
            );
            try {
                await knex("v2_publication_outbox")
                    .where({ id: unpublish.id })
                    .update({ acknowledged_version_id: "expected-version" });
            } finally {
                await knex.raw(
                    "ALTER TABLE public.v2_publication_outbox ENABLE TRIGGER v2_outbox_projection_context_guard"
                );
                await knex.raw(
                    "ALTER TABLE public.v2_publication_outbox ENABLE TRIGGER v2_publication_outbox_guard"
                );
            }
            const versionDriftS3 = {
                send: async (command: unknown, options: unknown) => {
                    const result = await contentS3.send(
                        command as any,
                        options as any
                    );
                    if (
                        command instanceof GetObjectCommand &&
                        command.input.Key?.endsWith("/current.json")
                    )
                        return Object.assign(result, {
                            VersionId: "observed-version",
                        });
                    return result;
                },
            } as unknown as S3Client;
            const drift = await new V2ProjectionReconciler(
                knex,
                versionDriftS3,
                bucket,
                driftVerifier
            ).inspect(applicationId, host);
            expect(drift.repair).to.equal("REPORT_AMBIGUITY");
            for (const reason of [
                "DESIRED_RELEASE_DRIFT",
                "OUTBOX_OPERATION_DRIFT",
                "OUTBOX_KEY_DRIFT",
                "OUTBOX_MANIFEST_DRIFT",
                "OUTBOX_PREFIX_DRIFT",
                "OUTBOX_RELEASE_DRIFT",
                "ACKNOWLEDGED_IDENTITY_DRIFT",
                "VERSION_ID_DRIFT",
            ])
                expect(drift.reasons).to.include(reason);
            expect(
                drift.reasons.every((reason) => /^[A-Z_]+$/.test(reason))
            ).to.equal(true);
        });

        it("PROJ-06: content uses public keys and S3 GET only while component policies deny cross-capability access", async () => {
            const projectedTombstone = lease({
                generation: 50,
                operation: "UNPUBLISH",
                releaseId: null,
                manifestDigest: null,
                objectPrefix: null,
            });
            const projectedBody = projector.documentFor(projectedTombstone);
            await admin.send(
                new PutObjectCommand({
                    Bucket: bucket,
                    Key: `v2/routing/${routingId}/generations/50.json`,
                    Body: projectedBody,
                })
            );
            await admin.send(
                new PutObjectCommand({
                    Bucket: bucket,
                    Key: `v2/routing/${routingId}/current.json`,
                    Body: projectedBody,
                })
            );
            await projector.project(projectedTombstone);
            let controlRead: unknown;
            let contentWrite: unknown;
            let workerDelete: unknown;
            try {
                await controlS3.send(
                    new GetObjectCommand({
                        Bucket: bucket,
                        Key: `v2/routing/${routingId}/current.json`,
                    })
                );
            } catch (error) {
                controlRead = error;
            }
            try {
                await contentS3.send(
                    new PutObjectCommand({
                        Bucket: bucket,
                        Key: `v2/routing/${routingId}/forbidden.json`,
                        Body: "x",
                    })
                );
            } catch (error) {
                contentWrite = error;
            }
            try {
                const response = await workerS3.send(
                    new DeleteObjectsCommand({
                        Bucket: bucket,
                        Delete: {
                            Objects: [
                                { Key: `v2/routing/${routingId}/current.json` },
                            ],
                        },
                    })
                );
                if ((response.Errors ?? []).length > 0)
                    workerDelete = new Error("worker delete denied");
            } catch (error) {
                workerDelete = error;
            }
            expect(controlRead).to.be.instanceOf(Error);
            expect(contentWrite).to.be.instanceOf(Error);
            expect(workerDelete).to.be.instanceOf(Error);
            const immutable = await admin.send(
                new GetObjectCommand({
                    Bucket: bucket,
                    Key: `v2/routing/${routingId}/generations/50.json`,
                })
            );
            const fixtureBody = Buffer.from(
                await immutable.Body!.transformToByteArray()
            );
            await admin.send(
                new PutObjectCommand({
                    Bucket: bucket,
                    Key: `v2/routing/${routingId}/current.json`,
                    Body: fixtureBody,
                })
            );
            let storageAvailable = true;
            const outageClient = {
                send: async (command: unknown, options: unknown) => {
                    if (!storageAvailable)
                        throw new Error("controlled content storage outage");
                    return contentS3.send(command as any, options as any);
                },
            } as unknown as S3Client;
            const contentOnly = new V2ContentRoutingCache(
                outageClient,
                bucket,
                routingId,
                applicationId,
                host,
                verifier,
                50
            );
            expect((await contentOnly.refresh()).source).to.equal("OBJECT");
            expect("knex" in (contentOnly as unknown as object)).to.equal(
                false
            );
            storageAvailable = false;
            const duringControlDatabaseAndStorageOutage =
                await contentOnly.refresh();
            expect(duringControlDatabaseAndStorageOutage.source).to.equal(
                "LAST_KNOWN_GOOD"
            );
        });
    });
});

async function claimForApplication(
    queue: V2PublicationQueue,
    expectedId: string,
    owner: string,
    leaseMs = 30_000
): Promise<V2PublicationLease> {
    const claimed = await queue.claimDue({
        owner,
        leaseMs,
        limit: 100,
    });
    const expected = claimed.find((item) => item.id === expectedId);
    if (expected === undefined)
        throw new Error(
            "expected publication was not claimed from the disposable queue"
        );
    return expected;
}

function principal() {
    return {
        sessionId,
        subjectId: subject,
        issuer,
        groups: ["fixture-admin"],
        claimsVersion: 1,
    };
}
async function seedAuthorization(knex: Knex): Promise<void> {
    await knex("v2_authorization_policy")
        .insert({
            singleton: true,
            administrator_groups: ["fixture-admin"],
            required_claims_version: 1,
            configuration_digest: "a".repeat(64),
        })
        .onConflict("singleton")
        .ignore();
    await knex("v2_sessions")
        .insert({
            id: sessionId,
            subject_id: subject,
            issuer,
            claims: JSON.stringify({ groups: ["fixture-admin"] }),
            claims_version: 1,
            csrf_token_digest: "a".repeat(64),
            token_key_id: "fixture",
            token_nonce: Buffer.alloc(12),
            encrypted_token_material: Buffer.alloc(32),
            created_at: new Date(),
            last_seen_at: new Date(),
            idle_expires_at: new Date(Date.now() + 3_600_000),
            absolute_expires_at: new Date(Date.now() + 7_200_000),
        })
        .onConflict("id")
        .ignore();
}
async function seedApplication(
    knex: Knex,
    manifestDigest: string
): Promise<void> {
    await knex("v2_applications")
        .insert({
            id: applicationId,
            name: `m308-${randomUUID()}`,
            description: "",
            tags: JSON.stringify([]),
            owner_metadata: JSON.stringify({}),
            visibility: "INTERNAL",
            status: "ACTIVE",
            routing_id: routingId,
        })
        .onConflict("id")
        .ignore();
    await knex("v2_releases")
        .insert({
            id: releaseId,
            application_id: applicationId,
            state: "READY",
            default_path: "index.html",
            manifest_digest: manifestDigest,
            finalized_at: new Date(),
            created_at: new Date(),
            updated_at: new Date(),
        })
        .onConflict("id")
        .ignore();
}
async function seedClaimCandidate(
    knex: Knex,
    nextAttemptAt: Date
): Promise<{ applicationId: string; outboxId: string }> {
    const candidateApplicationId = randomUUID();
    const candidateRoutingId = randomUUID();
    const idempotencyId = randomUUID();
    const outboxId = randomUUID();
    const digest = createHash("sha256")
        .update(`claim-candidate:${outboxId}`)
        .digest("hex");
    await knex("v2_idempotency").insert({
        id: idempotencyId,
        actor_id: actorId,
        scope: "application.unpublish",
        idempotency_key: `m308-claim-${randomUUID()}`,
        request_digest: digest,
        state: "IN_PROGRESS",
        expires_at: new Date(Date.now() + 3_600_000),
    });
    await knex("v2_applications").insert({
        id: candidateApplicationId,
        name: `m308-claim-${randomUUID()}`,
        routing_id: candidateRoutingId,
        desired_generation: 1,
        served_generation: 0,
    });
    await knex("v2_publication_outbox").insert({
        id: outboxId,
        application_id: candidateApplicationId,
        routing_id: candidateRoutingId,
        release_id: null,
        generation: 1,
        operation: "UNPUBLISH",
        idempotency_id: idempotencyId,
        payload_kind: "TOMBSTONE",
        state: "PENDING",
        next_attempt_at: nextAttemptAt,
        routing_kid: "routing-claim-test",
        routing_host: `route-${candidateRoutingId}.fixture.invalid`,
        request_digest: digest,
        request_actor_id: actorId,
        request_audit_id: randomUUID(),
    });
    return { applicationId: candidateApplicationId, outboxId };
}

async function seedIdempotency(
    knex: Knex,
    scope: string,
    digest: string
): Promise<string> {
    const id = randomUUID();
    await knex("v2_idempotency").insert({
        id,
        actor_id: actorId,
        scope,
        idempotency_key: `m308-${randomUUID()}`,
        request_digest: digest,
        state: "IN_PROGRESS",
        expires_at: new Date(Date.now() + 3_600_000),
    });
    return id;
}
