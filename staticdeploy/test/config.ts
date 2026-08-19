import assert from "node:assert/strict";

import IConfig from "../src/common/IConfig";
import getV2Sessions from "../src/components/v2Sessions";
import { parseLogLevel, parseSessionEncryptionKeys } from "../src/config";

describe("service config", () => {
    it("accepts every supported LOG_LEVEL", () => {
        for (const level of [
            "trace",
            "debug",
            "info",
            "warn",
            "error",
            "fatal",
        ]) {
            assert.equal(parseLogLevel(level), level);
        }
    });

    it("rejects unsupported LOG_LEVEL values", () => {
        assert.throws(
            () => parseLogLevel("verbose"),
            /LOG_LEVEL must be one of trace, debug, info, warn, error, fatal/
        );
    });

    it("fails closed on partial or unsafe server OIDC configuration", async () => {
        await assert.rejects(
            getV2Sessions({ oidcPostgresUrl: "postgres://runtime" } as IConfig),
            /complete OIDC/
        );
        const complete = {
            nodeEnv: "production",
            enforceAuth: true,
            oidcConfigurationUrl:
                "https://idp.example/.well-known/openid-configuration",
            oidcClientId: "client",
            oidcExpectedIssuer: "https://idp.example",
            oidcRedirectUri: "https://portal.example/api/v2/auth/callback",
            portalOrigin: "https://portal.example",
            oidcSessionPrimaryKeyId: "key-1",
            oidcSessionEncryptionKeys: [
                { id: "key-1", key: Buffer.alloc(32, 7) },
            ],
            oidcPostgresUrl: "postgres://runtime",
        } as IConfig;
        await assert.rejects(
            getV2Sessions({ ...complete, enforceAuth: false }),
            /ENFORCE_AUTH=true/
        );
        await assert.rejects(
            getV2Sessions({
                ...complete,
                oidcAllowHttpLoopbackForTests: true,
            }),
            /restricted to NODE_ENV=test/
        );
    });

    it("parses only canonical 32-byte OIDC session encryption keys", () => {
        const key = Buffer.alloc(32, 7).toString("base64");
        assert.deepEqual(
            parseSessionEncryptionKeys(JSON.stringify([{ id: "key-1", key }])),
            [{ id: "key-1", key: Buffer.alloc(32, 7) }]
        );
        assert.throws(() => parseSessionEncryptionKeys("not-json"));
        assert.throws(() =>
            parseSessionEncryptionKeys(
                JSON.stringify([{ id: "key-1", key: "too-short" }])
            )
        );
    });
});
