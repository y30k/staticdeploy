import {
    CreateBucketCommand,
    DeleteBucketCommand,
    DeleteObjectsCommand,
    HeadBucketCommand,
    paginateListObjectsV2,
    S3Client,
} from "@aws-sdk/client-s3";
import registerStoragesTests from "@staticdeploy/storages-test-suite";
import { expect } from "chai";
import { Knex } from "knex";
import { Readable } from "node:stream";

import PgS3Storages, { IS3Config } from "../src";
import BundlesStorage from "../src/BundlesStorage";
import { StorageSetupError } from "../src/common/errors";
import tables from "../src/common/tables";

const environmentCredentialKeys = [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_REGION",
    "AWS_EC2_METADATA_DISABLED",
] as const;

type EnvironmentCredentialKey = (typeof environmentCredentialKeys)[number];
type SavedEnvironment = Record<EnvironmentCredentialKey, string | undefined>;

execStorageTests({
    name: "explicit credentials and bulk deletes",
    bucket: "staticdeploy-explicit-credentials",
    enableGCSCompatibility: false,
    environment: {
        AWS_ACCESS_KEY_ID: "unusedAccessKeyId",
        AWS_SECRET_ACCESS_KEY: "unusedSecretAccessKey",
        AWS_REGION: "unused-region",
        AWS_EC2_METADATA_DISABLED: "true",
    },
    credentials: {
        accessKeyId: "accessKeyId",
        secretAccessKey: "secretAccessKey",
    },
});

execStorageTests({
    name: "default Node credential provider chain and GCS-compatible deletes",
    bucket: "staticdeploy-default-provider-chain",
    enableGCSCompatibility: true,
    environment: {
        AWS_ACCESS_KEY_ID: "accessKeyId",
        AWS_SECRET_ACCESS_KEY: "secretAccessKey",
        AWS_REGION: "us-east-1",
        AWS_EC2_METADATA_DISABLED: "true",
    },
});

function execStorageTests(options: {
    name: string;
    bucket: string;
    enableGCSCompatibility: boolean;
    environment: Record<EnvironmentCredentialKey, string>;
    credentials?: { accessKeyId: string; secretAccessKey: string };
}) {
    describe(options.name, () => {
        const savedEnvironment = saveEnvironment();
        const pgS3Storages = new PgS3Storages({
            postgresUrl: "postgres://postgres:password@localhost/postgres",
            s3Config: {
                bucket: options.bucket,
                endpoint: "http://127.0.0.1:9000",
                region: "us-east-1",
                forcePathStyle: true,
                enableGCSCompatibility: options.enableGCSCompatibility,
                ...options.credentials,
            },
        });
        const knex: Knex = (pgS3Storages as any).knex;
        const s3Client: S3Client = (pgS3Storages as any).s3Client;

        before(() => setEnvironment(options.environment));

        const eraseStorages = async () => {
            // Empty the database, starting from entrypoints since they
            // reference apps and bundles.
            await knex(tables.entrypoints).delete();
            await knex(tables.apps).delete();
            await knex(tables.bundles).delete();
            await knex(tables.operationLogs).delete();
            await knex(tables.usersAndGroups).delete();
            await knex(tables.groups).delete();
            await knex(tables.users).delete();

            // Empty every paginated S3 listing. DeleteObjects accepts at most
            // 1,000 keys per request, so keep cleanup bounded to that limit.
            const keys = await listAllKeys(s3Client, options.bucket);
            for (let index = 0; index < keys.length; index += 1000) {
                await s3Client.send(
                    new DeleteObjectsCommand({
                        Bucket: options.bucket,
                        Delete: {
                            Objects: keys
                                .slice(index, index + 1000)
                                .map((Key) => ({ Key })),
                        },
                    })
                );
            }
        };

        registerStoragesTests({
            storagesName: `pg-s3-storages (${options.name})`,
            storages: pgS3Storages.getStorages(),
            setupStorages: () => pgS3Storages.setup(),
            eraseStorages,
        });

        describe("AWS SDK v3 integration", () => {
            it("uploads, streams, lists, deletes, and classifies not-found responses", async () => {
                const storages = pgS3Storages.getStorages();
                await storages.bundles.createOne({
                    id: "sdk-v3-bundle",
                    name: "sdk-v3",
                    tag: "test",
                    description: "SDK v3 integration",
                    hash: "hash",
                    assets: [
                        {
                            path: "/nested/file.txt",
                            content: Buffer.from("streamed content"),
                            mimeType: "text/plain",
                            headers: {},
                        },
                    ],
                    fallbackAssetPath: "/nested/file.txt",
                    fallbackStatusCode: 200,
                    createdAt: new Date("2026-08-18T00:00:00.000Z"),
                });

                expect(
                    await storages.bundles.getBundleAssetContent(
                        "sdk-v3-bundle",
                        "/nested/file.txt"
                    )
                ).to.deep.equal(Buffer.from("streamed content"));
                expect(await listAllKeys(s3Client, options.bucket)).to.include(
                    "sdk-v3-bundle/nested/file.txt"
                );

                await storages.bundles.deleteMany(["sdk-v3-bundle"]);
                expect(
                    await storages.bundles.getBundleAssetContent(
                        "sdk-v3-bundle",
                        "/nested/file.txt"
                    )
                ).to.equal(null);
                expect(
                    await listAllKeys(s3Client, options.bucket)
                ).not.to.include("sdk-v3-bundle/nested/file.txt");
            });

            it("keeps non-404 S3 failures distinct from not-found", async () => {
                const invalidConfig: IS3Config = {
                    bucket: options.bucket,
                    endpoint: "http://127.0.0.1:9000",
                    region: "us-east-1",
                    forcePathStyle: true,
                    enableGCSCompatibility: options.enableGCSCompatibility,
                    ...(options.credentials
                        ? {
                              accessKeyId: "invalidAccessKeyId",
                              secretAccessKey: "invalidSecretAccessKey",
                          }
                        : {}),
                };
                const invalidStorages = new PgS3Storages({
                    postgresUrl:
                        "postgres://postgres:password@localhost/postgres",
                    s3Config: invalidConfig,
                });
                if (!options.credentials) {
                    process.env.AWS_ACCESS_KEY_ID = "invalidAccessKeyId";
                    process.env.AWS_SECRET_ACCESS_KEY =
                        "invalidSecretAccessKey";
                }
                try {
                    let setupError: unknown;
                    try {
                        await invalidStorages.setup();
                    } catch (error) {
                        setupError = error;
                    }
                    expect(setupError).to.be.instanceOf(StorageSetupError);
                    const originalError = (setupError as StorageSetupError)
                        .originalError;
                    expect(originalError.$metadata.httpStatusCode).not.to.equal(
                        404
                    );
                    expect((setupError as Error).message).to.equal(
                        `Error accessing bucket = ${options.bucket}`
                    );
                } finally {
                    setEnvironment(options.environment);
                    await invalidStorages.destroy();
                }
            });
        });

        after(async () => {
            try {
                await eraseStorages();
                await s3Client.send(
                    new DeleteBucketCommand({ Bucket: options.bucket })
                );
            } finally {
                try {
                    await pgS3Storages.destroy();
                } finally {
                    restoreEnvironment(savedEnvironment);
                }
            }
        });
    });
}

describe("AWS SDK v3 command contracts", () => {
    it("chunks production bulk deletes at the 1,000-object S3 limit", async () => {
        const batchSizes: number[] = [];
        const s3Client = {
            send: async (command: DeleteObjectsCommand) => {
                batchSizes.push(command.input.Delete!.Objects!.length);
                return {};
            },
        } as unknown as S3Client;
        const storage = new BundlesStorage({} as Knex, s3Client, "test", false);

        await (storage as any).deleteObjectsInBulk(
            Array.from({ length: 1001 }, (_, index) => `key-${index}`)
        );

        expect(batchSizes).to.deep.equal([1000, 1]);
    });

    it("keeps SQL metadata when a bulk response contains object errors", async () => {
        let sqlQueryCount = 0;
        const knex = (() => ({
            whereIn: async () => {
                sqlQueryCount += 1;
                return [
                    {
                        id: "bundle",
                        assets: [{ path: "/sensitive/path" }],
                    },
                ];
            },
        })) as unknown as Knex;
        const s3Client = {
            send: async () => ({ Errors: [{ Code: "AccessDenied" }] }),
        } as unknown as S3Client;
        const storage = new BundlesStorage(knex, s3Client, "test", false);

        let error: unknown;
        try {
            await storage.deleteMany(["bundle"]);
        } catch (caught) {
            error = caught;
        }
        expect(error).to.be.instanceOf(Error);
        expect((error as Error).message).to.equal(
            "S3 bulk delete failed for 1 object(s)"
        );
        expect((error as Error).message).not.to.include("sensitive/path");
        expect(sqlQueryCount).to.equal(1);
    });

    it("sends Content-MD5 without flexible checksum headers", async () => {
        const module = new PgS3Storages({
            postgresUrl: "postgres://unused",
            s3Config: {
                bucket: "test",
                endpoint: "http://127.0.0.1:9000",
                accessKeyId: "accessKeyId",
                secretAccessKey: "secretAccessKey",
            },
        });
        const originalClient: S3Client = (module as any).s3Client;
        let headers: Record<string, string> = {};
        const client = new S3Client({
            endpoint: "http://127.0.0.1:9000",
            region: "us-east-1",
            forcePathStyle: true,
            credentials: {
                accessKeyId: "accessKeyId",
                secretAccessKey: "secretAccessKey",
            },
            requestHandler: {
                handle: async (request: {
                    headers: Record<string, string>;
                }) => {
                    headers = request.headers;
                    return {
                        response: {
                            statusCode: 200,
                            headers: {},
                            body: Readable.from([
                                '<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>',
                            ]),
                        },
                    };
                },
            } as any,
        });
        (module as any).s3Client = client;
        (module as any).addDeleteObjectsContentMd5Middleware();
        try {
            await client.send(
                new DeleteObjectsCommand({
                    Bucket: "test",
                    Delete: { Objects: [{ Key: "key" }] },
                })
            );
        } finally {
            try {
                await (module as any).knex.destroy();
            } finally {
                try {
                    client.destroy();
                } finally {
                    originalClient.destroy();
                }
            }
        }

        const contentMd5 = headers["content-md5"];
        expect(contentMd5).to.be.a("string");
        expect(contentMd5.length).to.be.greaterThan(0);
        expect(headers).not.to.have.property("x-amz-checksum-crc32");
        expect(headers).not.to.have.property("x-amz-sdk-checksum-algorithm");
    });

    for (const [region, expectedLocation] of [
        ["us-east-1", undefined],
        ["eu-west-1", "eu-west-1"],
    ] as const) {
        it(`uses the correct bucket location constraint for ${region}`, async () => {
            const module = new PgS3Storages({
                postgresUrl: "postgres://unused",
                s3Config: {
                    bucket: "test",
                    endpoint: "http://127.0.0.1:9000",
                    region,
                    accessKeyId: "accessKeyId",
                    secretAccessKey: "secretAccessKey",
                },
            });
            const commands: unknown[] = [];
            const originalClient: S3Client = (module as any).s3Client;
            (module as any).s3Client = {
                send: async (command: unknown) => {
                    commands.push(command);
                    if (command instanceof HeadBucketCommand) {
                        throw { $metadata: { httpStatusCode: 404 } };
                    }
                    return {};
                },
            };
            try {
                await (module as any).createS3Bucket();
            } finally {
                try {
                    await (module as any).knex.destroy();
                } finally {
                    originalClient.destroy();
                }
            }

            const createCommand = commands.find(
                (command) => command instanceof CreateBucketCommand
            ) as CreateBucketCommand;
            expect(
                createCommand.input.CreateBucketConfiguration
                    ?.LocationConstraint
            ).to.equal(expectedLocation);
        });
    }
});

async function listAllKeys(
    client: S3Client,
    bucket: string
): Promise<string[]> {
    const keys: string[] = [];
    for await (const page of paginateListObjectsV2(
        { client },
        { Bucket: bucket }
    )) {
        for (const object of page.Contents ?? []) {
            if (object.Key !== undefined) {
                keys.push(object.Key);
            }
        }
    }
    return keys;
}

function saveEnvironment(): SavedEnvironment {
    return Object.fromEntries(
        environmentCredentialKeys.map((key) => [key, process.env[key]])
    ) as SavedEnvironment;
}

function setEnvironment(
    environment: Record<EnvironmentCredentialKey, string>
): void {
    for (const key of environmentCredentialKeys) {
        process.env[key] = environment[key];
    }
}

function restoreEnvironment(environment: SavedEnvironment): void {
    for (const key of environmentCredentialKeys) {
        const value = environment[key];
        if (value === undefined) {
            delete process.env[key];
        } else {
            process.env[key] = value;
        }
    }
}
