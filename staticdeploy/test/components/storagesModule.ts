import assert from "node:assert/strict";

import MemoryStorages from "@staticdeploy/memory-storages";
import PgS3Storages from "@staticdeploy/pg-s3-storages";
import Logger from "bunyan";

import IConfig from "../../src/common/IConfig";
import getStoragesModule from "../../src/components/storagesModule";

const baseConfig: IConfig = {
    appName: "staticdeploy-test",
    appVersion: "test",
    nodeEnv: "test",
    logLevel: "fatal",
    port: "3000",
    managementHostname: "localhost",
    enableManagementEndpoints: true,
    maxRequestBodySize: "1mb",
    enforceAuth: false,
    createRootUser: false,
    postgresUrl: "postgres://postgres:password@localhost/postgres",
    s3Bucket: "test",
    s3Endpoint: "http://127.0.0.1:9000",
    s3Region: "us-east-1",
    s3ForcePathStyle: true,
    s3EnableGCSCompatibility: false,
};

const logMessages: unknown[][] = [];
const logger = {
    info: (...args: unknown[]) => logMessages.push(args),
} as unknown as Logger;

describe("storagesModule configuration", () => {
    const modulesToClose: PgS3Storages[] = [];

    beforeEach(() => logMessages.splice(0));

    afterEach(async () => {
        let cleanupError: unknown;
        for (const module of modulesToClose.splice(0)) {
            try {
                await (module as any).knex.destroy();
            } catch (error) {
                if (cleanupError === undefined) cleanupError = error;
            } finally {
                try {
                    (module as any).s3Client.destroy();
                } catch (error) {
                    if (cleanupError === undefined) cleanupError = error;
                }
            }
        }
        if (cleanupError !== undefined) throw cleanupError;
    });

    function getPgS3Storages(config: IConfig): PgS3Storages {
        const module = getStoragesModule(config, logger);
        assert.ok(module instanceof PgS3Storages);
        modulesToClose.push(module);
        return module;
    }

    it("uses memory storage when a required endpoint is omitted", () => {
        const module = getStoragesModule(
            { ...baseConfig, s3Endpoint: undefined },
            logger
        );
        assert.ok(module instanceof MemoryStorages);
    });

    it("uses endpoint and defaults with credentials omitted for the provider chain", async () => {
        const module = getPgS3Storages({
            ...baseConfig,
            s3Region: undefined,
            s3ForcePathStyle: undefined,
            s3AccessKeyId: undefined,
            s3SecretAccessKey: undefined,
        });
        const clientConfig = (module as any).s3Client.config;
        assert.ok(clientConfig.credentials);
        assert.equal(await clientConfig.region(), "us-east-1");
        assert.equal(clientConfig.forcePathStyle, true);
        assert.equal((await clientConfig.endpoint()).hostname, "127.0.0.1");
    });

    it("passes an explicit credential pair to the S3 client", async () => {
        const module = getPgS3Storages({
            ...baseConfig,
            s3AccessKeyId: "explicitAccessKeyId",
            s3SecretAccessKey: "explicitSecretAccessKey",
        });
        const credentials = await (module as any).s3Client.config.credentials();
        assert.equal(credentials.accessKeyId, "explicitAccessKeyId");
        assert.equal(credentials.secretAccessKey, "explicitSecretAccessKey");
    });

    for (const partialCredentials of [
        { s3AccessKeyId: "partial", s3SecretAccessKey: undefined },
        { s3AccessKeyId: undefined, s3SecretAccessKey: "partial" },
    ]) {
        it("rejects a partial explicit credential pair without logging credential values", () => {
            assert.throws(
                () =>
                    getStoragesModule(
                        { ...baseConfig, ...partialCredentials },
                        logger
                    ),
                (error: Error) => {
                    assert.equal(
                        error.message,
                        "S3 accessKeyId and secretAccessKey must either both be set or both be omitted"
                    );
                    assert.equal(error.message.includes("partial"), false);
                    assert.equal(
                        JSON.stringify(logMessages).includes("partial"),
                        false
                    );
                    return true;
                }
            );
        });
    }

    it("passes explicit region and virtual-host-style choice to the S3 client", async () => {
        const module = getPgS3Storages({
            ...baseConfig,
            s3Region: "eu-west-1",
            s3ForcePathStyle: false,
        });
        const clientConfig = (module as any).s3Client.config;
        assert.equal(await clientConfig.region(), "eu-west-1");
        assert.equal(clientConfig.forcePathStyle, false);
    });
});
