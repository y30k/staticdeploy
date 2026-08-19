import {
    CopyObjectCommand,
    CreateBucketCommand,
    CreateMultipartUploadCommand,
    DeleteBucketCommand,
    DeleteObjectCommand,
    DeleteObjectsCommand,
    GetObjectCommand,
    ListObjectsV2Command,
    paginateListObjectsV2,
    PutObjectCommand,
    S3Client,
} from "@aws-sdk/client-s3";
import { expect } from "chai";
import { knex, Knex } from "knex";
import { createHash, randomUUID } from "node:crypto";

import PgS3Storages, {
    createV2ObjectStorages,
    createV2WorkerObjectStorage,
    normalizeV2RelativePath,
    verifyV2CreateOnlyCapability,
    V2_OBJECT_LIMITS,
    V2ControlObjectStorage,
} from "../src";
import tables from "../src/common/tables";

const postgresAdminUrl =
    process.env.POSTGRES_TEST_URL ??
    "postgres://postgres:password@127.0.0.1:5432/postgres";
const s3Endpoint = process.env.MINIO_TEST_URL ?? "http://127.0.0.1:9000";
const credentials = {
    accessKeyId: "accessKeyId",
    secretAccessKey: "secretAccessKey",
};
const roleCredentials = {
    control: {
        accessKeyId: "m304-control",
        secretAccessKey: "m304-control-secret",
    },
    worker: {
        accessKeyId: "m304-worker",
        secretAccessKey: "m304-worker-secret",
    },
    content: {
        accessKeyId: "m304-content",
        secretAccessKey: "m304-content-secret",
    },
};

function envelope(content: Uint8Array) {
    return {
        size: content.byteLength,
        sha256: createHash("sha256").update(content).digest("hex"),
    };
}

async function expectFailure(operation: PromiseLike<unknown>, text: string) {
    let failure: unknown;
    try {
        await operation;
    } catch (error) {
        failure = error;
    }
    expect(failure).to.be.instanceOf(Error);
    expect((failure as Error).message).to.include(text);
}

function client(
    selectedCredentials: {
        accessKeyId: string;
        secretAccessKey: string;
    } = credentials
): S3Client {
    return new S3Client({
        endpoint: s3Endpoint,
        region: "us-east-1",
        forcePathStyle: true,
        credentials: selectedCredentials,
    });
}

async function expectAccessDenied(operation: PromiseLike<unknown>) {
    let failure: unknown;
    try {
        await operation;
    } catch (error) {
        failure = error;
    }
    expect(failure).to.not.equal(undefined);
    expect(
        (failure as { name?: string }).name === "AccessDenied" ||
            (failure as { $metadata?: { httpStatusCode?: number } }).$metadata
                ?.httpStatusCode === 403
    ).to.equal(true);
}

describe("M3-04 quarantine and immutable release objects", () => {
    const databaseName = `m304_${randomUUID().replace(/-/g, "")}`;
    const bucket = `m304-${randomUUID()}`;
    let admin: Knex;
    let module: PgS3Storages;
    let database: Knex;
    let controlDatabase: Knex;
    let workerDatabase: Knex;
    let root: S3Client;
    let controlClient: S3Client;
    let workerClient: S3Client;
    let contentClient: S3Client;
    let stores: ReturnType<typeof createV2ObjectStorages>;
    let nextSuffix = 1;

    before(async () => {
        admin = knex({ client: "pg", connection: postgresAdminUrl });
        await admin.raw(`create database ??`, [databaseName]);
        const databaseUrl = new URL(postgresAdminUrl);
        databaseUrl.pathname = `/${databaseName}`;
        module = new PgS3Storages({
            postgresUrl: databaseUrl.toString(),
            s3Config: {
                bucket,
                endpoint: s3Endpoint,
                forcePathStyle: true,
                ...credentials,
            },
        });
        await module.setup();
        database = (module as any).knex;
        root = (module as any).s3Client;
        controlDatabase = knex({
            client: "pg",
            connection: databaseUrl.toString(),
        });
        workerDatabase = knex({
            client: "pg",
            connection: databaseUrl.toString(),
        });
        controlClient = client(roleCredentials.control);
        workerClient = client(roleCredentials.worker);
        contentClient = client(roleCredentials.content);
        stores = createV2ObjectStorages({
            control: { knex: controlDatabase, client: controlClient },
            worker: { knex: workerDatabase, client: workerClient },
            content: { client: contentClient },
            bucket,
        });
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
            contentClient.destroy();
            await controlDatabase.destroy();
            await workerDatabase.destroy();
            await module.destroy();
            await admin.raw(`drop database ??`, [databaseName]);
            await admin.destroy();
        }
    });

    it("enforces role-specific construction and local MinIO conditional-create capability", async () => {
        expect(() =>
            createV2ObjectStorages({
                control: { knex: database, client: root },
                worker: { knex: database, client: root },
                content: { client: root },
                bucket,
            })
        ).to.throw("distinct client identities");
        const firstProbeClient = client();
        const secondProbeClient = client();
        try {
            await verifyV2CreateOnlyCapability(
                firstProbeClient,
                secondProbeClient,
                bucket
            );
        } finally {
            firstProbeClient.destroy();
            secondProbeClient.destroy();
        }
        await expectAccessDenied(
            controlClient.send(
                new PutObjectCommand({
                    Bucket: bucket,
                    Key: "v2/releases/blocked/control.txt",
                    Body: Buffer.from("blocked"),
                })
            )
        );
        await expectAccessDenied(
            contentClient.send(
                new GetObjectCommand({
                    Bucket: bucket,
                    Key: "v2/quarantine/blocked/files/secret.txt",
                })
            )
        );
        await expectAccessDenied(
            contentClient.send(
                new PutObjectCommand({
                    Bucket: bucket,
                    Key: "v2/releases/blocked/content.txt",
                    Body: Buffer.from("blocked"),
                })
            )
        );
        await expectAccessDenied(
            controlClient.send(
                new GetObjectCommand({
                    Bucket: bucket,
                    Key: "v2/releases/blocked/control.txt",
                })
            )
        );
        await expectAccessDenied(
            workerClient.send(new ListObjectsV2Command({ Bucket: bucket }))
        );
        await expectAccessDenied(
            workerClient.send(
                new DeleteObjectCommand({
                    Bucket: bucket,
                    Key: "v2/releases/blocked/immutable.txt",
                })
            )
        );
        await expectAccessDenied(
            contentClient.send(
                new DeleteObjectCommand({
                    Bucket: bucket,
                    Key: "v2/releases/blocked/content.txt",
                })
            )
        );
        await expectAccessDenied(
            contentClient.send(
                new CopyObjectCommand({
                    Bucket: bucket,
                    Key: "v2/releases/blocked/copy.txt",
                    CopySource: `${bucket}/v2/releases/blocked/source.txt`,
                })
            )
        );
        await expectAccessDenied(
            contentClient.send(
                new CreateMultipartUploadCommand({
                    Bucket: bucket,
                    Key: "v2/releases/blocked/multipart.txt",
                })
            )
        );
        await expectAccessDenied(
            contentClient.send(
                new CreateBucketCommand({ Bucket: `${bucket}-blocked` })
            )
        );

        const ignored = {
            send: async (command: unknown) => {
                if (command instanceof PutObjectCommand) return {};
                throw new Error("unexpected command");
            },
        } as S3Client;
        await expectFailure(
            verifyV2CreateOnlyCapability(
                ignored,
                { ...ignored } as S3Client,
                bucket
            ),
            "does not enforce conditional create"
        );
        let request = 0;
        const unrelatedFailure = {
            send: async (command: unknown) => {
                if (command instanceof PutObjectCommand && request++ === 0)
                    return {};
                if (command instanceof PutObjectCommand)
                    throw new Error("network unavailable");
                if (command instanceof GetObjectCommand)
                    return {
                        Body: {
                            transformToByteArray: async () =>
                                Buffer.from("first"),
                        },
                    };
                throw new Error("unexpected command");
            },
        } as S3Client;
        await expectFailure(
            verifyV2CreateOnlyCapability(
                unrelatedFailure,
                { ...unrelatedFailure } as S3Client,
                bucket
            ),
            "unrelated reason"
        );
        for (const candidate of [
            { name: "PreconditionFailed", httpStatusCode: 500 },
            { name: "UnrelatedConflict", httpStatusCode: 409 },
        ]) {
            let conditionalRequest = 0;
            const falseConflict = {
                send: async (command: unknown) => {
                    if (
                        command instanceof PutObjectCommand &&
                        conditionalRequest++ === 0
                    )
                        return {};
                    const error = new Error(
                        "not a conditional conflict"
                    ) as Error & {
                        $metadata: { httpStatusCode: number };
                    };
                    error.name = candidate.name;
                    error.$metadata = {
                        httpStatusCode: candidate.httpStatusCode,
                    };
                    throw error;
                },
            } as S3Client;
            await expectFailure(
                verifyV2CreateOnlyCapability(
                    falseConflict,
                    { ...falseConflict } as S3Client,
                    bucket
                ),
                "unrelated reason"
            );
        }
    });

    it("rejects unsafe, colliding, malformed, and overlong paths while accepting astral UTF-8", async () => {
        for (const unsafe of [
            "/absolute",
            "../escape",
            "a/../b",
            "a/./b",
            "a//b",
            "a\\b",
            "a/",
            "e\u0301.txt",
            "nul\0file",
            "bad\ud800.txt",
        ])
            expect(() => normalizeV2RelativePath(unsafe)).to.throw();
        expect(normalizeV2RelativePath("nested/😀.txt")).to.equal(
            "nested/😀.txt"
        );

        for (const paths of [
            ["A.txt", "a.txt"],
            ["Straße.txt", "STRASSE.txt"],
            ["STRAẞE.txt", "STRASSE.txt"],
            ["Σ.txt", "ς.txt"],
            ["assets", "assets/app.js"],
        ]) {
            const ids = await insertRelease(paths);
            await expectFailure(
                stores.worker.finalizeRelease({
                    ...ids,
                    uploadId: ids.releaseId,
                    defaultPath: paths[0],
                }),
                paths[0] === "assets"
                    ? "file-directory collision"
                    : "object path collision"
            );
        }
        const ids = await insertRelease(["index.html"]);
        await expectFailure(
            stores.worker.finalizeRelease({
                ...ids,
                uploadId: "30000000-0000-4000-8000-000000999999",
                defaultPath: "index.html",
            }),
            "upload prefix is not bound"
        );
        const nonHtml = await insertRelease(["README"]);
        await expectFailure(
            stores.worker.finalizeRelease({
                ...nonHtml,
                uploadId: nonHtml.releaseId,
                defaultPath: "README",
            }),
            "must be an HTML document"
        );

        const exactPath = [
            "a".repeat(186),
            ...Array(3).fill("a".repeat(185)),
            `${"a".repeat(180)}.html`,
        ].join("/");
        const exact = await insertRelease([exactPath]);
        await declareAndUpload(exact.releaseId, {
            [exactPath]: Buffer.from("x"),
        });
        await stores.worker.finalizeRelease({
            ...exact,
            uploadId: exact.releaseId,
            defaultPath: exactPath,
        });
        const overPath = [
            "a".repeat(187),
            ...Array(3).fill("a".repeat(185)),
            `${"a".repeat(180)}.html`,
        ].join("/");
        const over = await insertRelease([overPath]);
        await declareAndUpload(over.releaseId, {
            [overPath]: Buffer.from("x"),
        });
        await expectFailure(
            stores.worker.finalizeRelease({
                ...over,
                uploadId: over.releaseId,
                defaultPath: overPath,
            }),
            "key exceeds"
        );
    });

    it("bounds declaration envelopes and verifies quarantine bytes", async () => {
        const ids = await insertRelease(["index.html"]);
        const body = Buffer.from("verified bytes");
        const expected = envelope(body);
        await setDeclaration(ids.releaseId, "index.html", expected);
        await expectFailure(
            stores.control.putQuarantineFile(
                ids.releaseId,
                "index.html",
                body,
                {
                    ...expected,
                    size: body.length + 1,
                }
            ),
            "database declaration"
        );
        await stores.control.putQuarantineFile(
            ids.releaseId,
            "index.html",
            body,
            expected
        );
        await stores.control.putQuarantineFile(
            ids.releaseId,
            "index.html",
            body,
            expected
        );
        await expectFailure(
            stores.control.putQuarantineFile(
                ids.releaseId,
                "index.html",
                body,
                {
                    size: V2_OBJECT_LIMITS.maxFileBytes + 1,
                    sha256: expected.sha256,
                }
            ),
            "oversized"
        );
    });

    it("finalizes deterministic MIME, manifest, and source-download objects and retries after quarantine cleanup", async () => {
        const ids = await insertRelease([
            "z.txt",
            "assets/app.js",
            "html",
            "index.html",
        ]);
        const files = {
            "z.txt": Buffer.from("z"),
            "assets/app.js": Buffer.from("console.log('ready')"),
            html: Buffer.from("extensionless"),
            "index.html": Buffer.from("<h1>ready</h1>"),
        };
        await declareAndUpload(ids.releaseId, files);
        const first = await stores.worker.finalizeRelease({
            ...ids,
            uploadId: ids.releaseId,
            defaultPath: "index.html",
        });
        expect(first.files.map((file) => file.path)).to.deep.equal([
            "assets/app.js",
            "html",
            "index.html",
            "z.txt",
        ]);
        expect(first.files.map((file) => file.mime)).to.deep.equal([
            "text/javascript; charset=utf-8",
            "application/octet-stream",
            "text/html; charset=utf-8",
            "text/plain; charset=utf-8",
        ]);
        const row = await database(tables.v2Releases)
            .where({ id: ids.releaseId })
            .first();
        expect(row.state).to.equal("READY");
        expect(row.manifest_digest).to.equal(
            envelope(Buffer.from(JSON.stringify(first))).sha256
        );
        for (const path of Object.keys(files))
            await stores.worker.deleteQuarantineFile(ids.releaseId, path);
        const restartedClient = client(roleCredentials.worker);
        const restarted = createV2WorkerObjectStorage(
            workerDatabase,
            restartedClient,
            bucket
        );
        try {
            expect(
                await restarted.finalizeRelease({
                    ...ids,
                    uploadId: ids.releaseId,
                    defaultPath: "index.html",
                })
            ).to.deep.equal(first);
        } finally {
            restartedClient.destroy();
        }
        expect(
            await stores.content.readReleaseContent(
                ids.applicationId,
                ids.releaseId,
                row.manifest_digest,
                "index.html"
            )
        ).to.deep.equal(files["index.html"]);

        const keys = await keysFor(
            `v2/releases/${ids.applicationId}/${ids.releaseId}/`
        );
        const archiveKey = `v2/releases/${ids.applicationId}/${ids.releaseId}/source-download.zip`;
        expect(keys).to.include(archiveKey);
        expect(envelope(await body(archiveKey))).to.deep.equal(
            first.sourceDownload
        );
    });

    it("rejects illegal release states and declaration races without READY revival", async () => {
        for (const state of ["PENDING_UPLOAD", "UPLOADED", "FAILED"]) {
            const ids = await insertRelease(["index.html"], state);
            await expectFailure(
                stores.worker.finalizeRelease({
                    ...ids,
                    uploadId: ids.releaseId,
                    defaultPath: "index.html",
                }),
                "not eligible"
            );
        }
        const ids = await insertRelease(["index.html"]);
        await declareAndUpload(ids.releaseId, {
            "index.html": Buffer.from("snapshot"),
        });
        let changed = false;
        const proxy = {
            send: async (command: any) => {
                const response = await (workerClient as any).send(command);
                if (
                    !changed &&
                    command instanceof PutObjectCommand &&
                    command.input.Key?.endsWith("/manifest.json")
                ) {
                    changed = true;
                    await database(tables.v2UploadFiles)
                        .where({ release_id: ids.releaseId })
                        .update({ declared_digest: "f".repeat(64) });
                }
                return response;
            },
        } as S3Client;
        const raced = createV2WorkerObjectStorage(
            workerDatabase,
            proxy,
            bucket
        );
        await expectFailure(
            raced.finalizeRelease({
                ...ids,
                uploadId: ids.releaseId,
                defaultPath: "index.html",
            }),
            "declarations changed"
        );
        expect(
            (
                await database(tables.v2Releases)
                    .where({ id: ids.releaseId })
                    .first()
            ).state
        ).to.equal("PROCESSING");
    });

    it("reconciles 409 and 412 while retaining conditional writes", async () => {
        const ids = await insertRelease(["index.html"]);
        await declareAndUpload(ids.releaseId, {
            "index.html": Buffer.from("same"),
        });
        let injected409 = false;
        const conflict = {
            send: async (command: any) => {
                if (!injected409 && command instanceof PutObjectCommand) {
                    injected409 = true;
                    const error: any = new Error("conditional race");
                    error.$metadata = { httpStatusCode: 409 };
                    throw error;
                }
                if (command instanceof PutObjectCommand)
                    expect(command.input.IfNoneMatch).to.equal("*");
                return (workerClient as any).send(command);
            },
        } as S3Client;
        await createV2WorkerObjectStorage(
            workerDatabase,
            conflict,
            bucket
        ).finalizeRelease({
            ...ids,
            uploadId: ids.releaseId,
            defaultPath: "index.html",
        });

        const identical = await insertRelease(["index.html"]);
        const bytes = Buffer.from("preexisting");
        await declareAndUpload(identical.releaseId, { "index.html": bytes });
        await root.send(
            new PutObjectCommand({
                Bucket: bucket,
                Key: `v2/releases/${identical.applicationId}/${identical.releaseId}/source/index.html`,
                Body: bytes,
            })
        );
        await stores.worker.finalizeRelease({
            ...identical,
            uploadId: identical.releaseId,
            defaultPath: "index.html",
        });

        const conflicting = await insertRelease(["index.html"]);
        await declareAndUpload(conflicting.releaseId, {
            "index.html": Buffer.from("expected"),
        });
        const key = `v2/releases/${conflicting.applicationId}/${conflicting.releaseId}/source/index.html`;
        await root.send(
            new PutObjectCommand({
                Bucket: bucket,
                Key: key,
                Body: Buffer.from("attacker"),
            })
        );
        await expectFailure(
            stores.worker.finalizeRelease({
                ...conflicting,
                uploadId: conflicting.releaseId,
                defaultPath: "index.html",
            }),
            "digest or size mismatch"
        );
        expect(Buffer.from(await body(key)).toString()).to.equal("attacker");
    });

    it("concurrent independent workers converge and content rejects undeclared or corrupt objects", async () => {
        const ids = await insertRelease(["index.html"]);
        const bytes = Buffer.from("winner");
        await declareAndUpload(ids.releaseId, { "index.html": bytes });
        const otherDatabase = knex({
            client: "pg",
            connection: (workerDatabase.client.config as any).connection,
        });
        const firstClient = client(roleCredentials.worker);
        const otherClient = client(roleCredentials.worker);
        let arrivals = 0;
        let releaseBarrier!: () => void;
        const barrier = new Promise<void>((resolve) => {
            releaseBarrier = resolve;
        });
        const synchronize = (s3: S3Client) => {
            let waited = false;
            return {
                send: async (command: any) => {
                    if (
                        !waited &&
                        command instanceof PutObjectCommand &&
                        command.input.Key?.endsWith("/source/index.html")
                    ) {
                        waited = true;
                        arrivals += 1;
                        if (arrivals === 2) releaseBarrier();
                        await barrier;
                    }
                    return (s3 as any).send(command);
                },
            } as S3Client;
        };
        const first = createV2WorkerObjectStorage(
            workerDatabase,
            synchronize(firstClient),
            bucket
        );
        const other = createV2WorkerObjectStorage(
            otherDatabase,
            synchronize(otherClient),
            bucket
        );
        const input = {
            ...ids,
            uploadId: ids.releaseId,
            defaultPath: "index.html",
        };
        let left;
        let right;
        try {
            [left, right] = await Promise.all([
                first.finalizeRelease(input),
                other.finalizeRelease(input),
            ]);
        } finally {
            firstClient.destroy();
            otherClient.destroy();
            await otherDatabase.destroy();
        }
        expect(arrivals).to.equal(2);
        expect(left).to.deep.equal(right);
        const release = await database(tables.v2Releases)
            .where({ id: ids.releaseId })
            .first();
        const evilKey = `v2/releases/${ids.applicationId}/${ids.releaseId}/content/evil.js`;
        await root.send(
            new PutObjectCommand({
                Bucket: bucket,
                Key: evilKey,
                Body: Buffer.from("evil"),
            })
        );
        expect(
            await stores.content.readReleaseContent(
                ids.applicationId,
                ids.releaseId,
                release.manifest_digest,
                "evil.js"
            )
        ).to.equal(null);
        const contentKey = `v2/releases/${ids.applicationId}/${ids.releaseId}/content/index.html`;
        await root.send(
            new PutObjectCommand({
                Bucket: bucket,
                Key: contentKey,
                Body: Buffer.from("corrupt"),
            })
        );
        await expectFailure(
            stores.content.readReleaseContent(
                ids.applicationId,
                ids.releaseId,
                release.manifest_digest,
                "index.html"
            ),
            "digest or size mismatch"
        );
    });

    async function insertRelease(
        paths: string[],
        state = "PROCESSING"
    ): Promise<{ applicationId: string; releaseId: string }> {
        const suffix = String(nextSuffix++).padStart(12, "0");
        const applicationId = `10000000-0000-4000-8000-${suffix}`;
        const releaseId = `30000000-0000-4000-8000-${suffix}`;
        await database(tables.v2Applications).insert({
            id: applicationId,
            name: `m304-${suffix}`,
            description: "M3-04 fixture",
            tags: JSON.stringify([]),
            owner_metadata: JSON.stringify({}),
            routing_id: `40000000-0000-4000-8000-${suffix}`,
        });
        await database(tables.v2Releases).insert({
            id: releaseId,
            application_id: applicationId,
            state,
        });
        for (let index = 0; index < paths.length; index += 1)
            await database(tables.v2UploadFiles).insert({
                id: `50000000-0000-4${String(index).padStart(3, "0")}-8000-${suffix}`,
                release_id: releaseId,
                declared_path: paths[index],
                declared_size: 1,
                declared_digest: "0".repeat(64),
            });
        return { applicationId, releaseId };
    }

    async function setDeclaration(
        releaseId: string,
        path: string,
        expected: { size: number; sha256: string }
    ) {
        await database(tables.v2UploadFiles)
            .where({ release_id: releaseId, declared_path: path })
            .update({
                declared_size: expected.size,
                declared_digest: expected.sha256,
            });
    }

    async function declareAndUpload(
        releaseId: string,
        files: Record<string, Buffer>,
        control: V2ControlObjectStorage = stores.control
    ) {
        for (const [path, content] of Object.entries(files)) {
            const expected = envelope(content);
            await setDeclaration(releaseId, path, expected);
            await control.putQuarantineFile(releaseId, path, content, expected);
        }
    }

    async function keysFor(prefix: string): Promise<string[]> {
        const keys: string[] = [];
        for await (const page of paginateListObjectsV2(
            { client: root },
            { Bucket: bucket, Prefix: prefix }
        ))
            for (const object of page.Contents ?? [])
                if (object.Key) keys.push(object.Key);
        return keys.sort();
    }

    async function body(key: string): Promise<Uint8Array> {
        const result = await root.send(
            new GetObjectCommand({ Bucket: bucket, Key: key })
        );
        return result.Body!.transformToByteArray();
    }
});
