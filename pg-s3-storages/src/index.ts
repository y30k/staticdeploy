import {
    BucketLocationConstraint,
    CreateBucketCommand,
    HeadBucketCommand,
    S3Client,
    S3ClientConfig,
} from "@aws-sdk/client-s3";
import {
    IHealthCheckResult,
    IStorages,
    IStoragesModule,
} from "@staticdeploy/core";
import { Knex } from "knex";
import { createHash } from "node:crypto";
import { extname, join } from "path";

import AppsStorage from "./AppsStorage";
import BundlesStorage from "./BundlesStorage";
import { StorageSetupError } from "./common/errors";
import { isS3NotFoundError } from "./common/s3Errors";
import EntrypointsStorage from "./EntrypointsStorage";
import GroupsStorage from "./GroupsStorage";
import OperationLogsStorage from "./OperationLogsStorage";
import { createPostgresKnex } from "./postgres";
import UsersStorage from "./UsersStorage";
export * from "./V2ObjectStorage";

export interface IS3Config {
    bucket: string;
    endpoint: string;
    region?: string;
    forcePathStyle?: boolean;
    accessKeyId?: string;
    secretAccessKey?: string;
    enableGCSCompatibility?: boolean;
}

export default class PgS3Storages implements IStoragesModule {
    private knex: Knex;
    private s3Client: S3Client;
    private s3Bucket: string;
    private s3Region: string;
    private s3EnableGCSCompatibility: boolean;
    private destroyPromise?: Promise<void>;

    constructor(options: { postgresUrl: string; s3Config: IS3Config }) {
        const s3ClientConfig = this.getS3ClientConfig(options.s3Config);

        // Instantiate Knex with an explicit PostgreSQL client and bounded pool.
        this.knex = createPostgresKnex(options.postgresUrl);

        // Instantiate S3 client. Omitting both credential values intentionally
        // leaves credential resolution to the AWS SDK's default Node provider
        // chain (environment, shared config, and workload identity providers).
        this.s3Bucket = options.s3Config.bucket;
        this.s3Region = options.s3Config.region ?? "us-east-1";
        this.s3Client = new S3Client(s3ClientConfig);
        this.addDeleteObjectsContentMd5Middleware();
        this.s3EnableGCSCompatibility =
            options.s3Config.enableGCSCompatibility ?? false;
    }

    async setup() {
        await this.runSqlMigrations();
        await this.createS3Bucket();
    }

    getStorages(): IStorages {
        return {
            apps: new AppsStorage(this.knex),
            bundles: new BundlesStorage(
                this.knex,
                this.s3Client,
                this.s3Bucket,
                this.s3EnableGCSCompatibility
            ),
            entrypoints: new EntrypointsStorage(this.knex),
            groups: new GroupsStorage(this.knex),
            operationLogs: new OperationLogsStorage(this.knex),
            users: new UsersStorage(this.knex),
            checkHealth: this.checkHealth.bind(this),
        };
    }

    destroy(): Promise<void> {
        if (this.destroyPromise === undefined) {
            this.destroyPromise = (async () => {
                let destroyError: unknown;
                try {
                    this.s3Client.destroy();
                } catch (error) {
                    destroyError = error;
                }
                try {
                    await this.knex.destroy();
                } catch (error) {
                    if (destroyError === undefined) destroyError = error;
                }
                if (destroyError !== undefined) throw destroyError;
            })();
        }
        return this.destroyPromise;
    }

    private getS3ClientConfig(s3Config: IS3Config): S3ClientConfig {
        const hasAccessKeyId = s3Config.accessKeyId !== undefined;
        const hasSecretAccessKey = s3Config.secretAccessKey !== undefined;
        if (hasAccessKeyId !== hasSecretAccessKey) {
            throw new Error(
                "S3 accessKeyId and secretAccessKey must either both be set or both be omitted"
            );
        }

        return {
            endpoint: s3Config.endpoint,
            region: s3Config.region ?? "us-east-1",
            forcePathStyle: s3Config.forcePathStyle ?? true,
            credentials:
                hasAccessKeyId && hasSecretAccessKey
                    ? {
                          accessKeyId: s3Config.accessKeyId!,
                          secretAccessKey: s3Config.secretAccessKey!,
                      }
                    : undefined,
        };
    }

    private addDeleteObjectsContentMd5Middleware(): void {
        // DeleteObjects requires a checksum. AWS SDK v3 defaults to newer
        // checksum headers that older S3-compatible services do not accept,
        // while AWS SDK v2 sent Content-MD5. Retain that interoperable wire
        // behavior by hashing the body after command serialization.
        this.s3Client.middlewareStack.add(
            (next, context) => async (args) => {
                if (context.commandName === "DeleteObjectsCommand") {
                    const request = args.request as {
                        body?: string | Uint8Array;
                        headers: Record<string, string>;
                    };
                    if (request.body !== undefined) {
                        request.headers["content-md5"] = createHash("md5")
                            .update(request.body)
                            .digest("base64");
                        // DeleteObjects historically requires Content-MD5.
                        // Remove the newer flexible-checksum negotiation so
                        // older S3-compatible endpoints receive the v2 wire
                        // contract rather than conflicting dual checksums.
                        delete request.headers["x-amz-checksum-crc32"];
                        delete request.headers["x-amz-sdk-checksum-algorithm"];
                    }
                }
                return next(args);
            },
            {
                step: "build",
                priority: "low",
                name: "deleteObjectsContentMd5Middleware",
            }
        );
    }

    private async checkHealth(): Promise<IHealthCheckResult> {
        const healthCheckResult: IHealthCheckResult = {
            isHealthy: true,
            details: {},
        };

        try {
            await this.knex.raw("select 1");
        } catch (err) {
            healthCheckResult.isHealthy = false;
            healthCheckResult.details.postgres = {
                message: "Unable to run query 'select 1'",
                err: err,
            };
        }

        try {
            await this.s3Client.send(
                new HeadBucketCommand({ Bucket: this.s3Bucket })
            );
        } catch (err) {
            healthCheckResult.isHealthy = false;
            healthCheckResult.details.s3 = {
                message: `Unable to HEAD bucket ${this.s3Bucket}`,
                err: err,
            };
        }

        return healthCheckResult;
    }

    private async runSqlMigrations() {
        const isCurrentFileTs = extname(__filename) === ".ts";
        try {
            await this.knex.migrate.latest({
                directory: join(__dirname, "./migrations"),
                loadExtensions: [isCurrentFileTs ? ".ts" : ".js"],
            });
        } catch (err) {
            throw new StorageSetupError("Error running sql migration", err);
        }
    }

    private async createS3Bucket() {
        // Check if the bucket exists and can be accessed with our credentials.
        try {
            await this.s3Client.send(
                new HeadBucketCommand({ Bucket: this.s3Bucket })
            );
            return;
        } catch (err) {
            if (!isS3NotFoundError(err)) {
                throw new StorageSetupError(
                    `Error accessing bucket = ${this.s3Bucket}`,
                    err
                );
            }
        }

        // If the bucket doesn't exist, create it.
        try {
            await this.s3Client.send(
                new CreateBucketCommand({
                    Bucket: this.s3Bucket,
                    CreateBucketConfiguration:
                        this.s3Region === "us-east-1"
                            ? undefined
                            : {
                                  LocationConstraint: this
                                      .s3Region as BucketLocationConstraint,
                              },
                })
            );
        } catch (err) {
            throw new StorageSetupError(
                `Error creating bucket = ${this.s3Bucket}`,
                err
            );
        }
    }
}
