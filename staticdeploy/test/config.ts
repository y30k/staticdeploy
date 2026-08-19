import assert from "node:assert/strict";

import IConfig from "../src/common/IConfig";
import getV2Sessions from "../src/components/v2Sessions";
import {
    parseAdministratorGroupIds,
    parseAuthorizationClaimsVersion,
    parseLogLevel,
    parseSessionEncryptionKeys,
    parseTrustedProxyHops,
} from "../src/config";

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
            oidcAdministratorGroupIds: ["stable-admin-id"],
            oidcAuthorizationClaimsVersion: 1,
            oidcPostgresUrl: "postgres://runtime",
            oidcTrustedProxyHops: 0,
        } as IConfig;
        await assert.rejects(
            getV2Sessions({
                ...complete,
                oidcTrustedProxyHops: undefined,
            }),
            /complete OIDC/
        );
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

    it("requires a bounded explicit trusted-proxy hop contract", () => {
        assert.equal(parseTrustedProxyHops("0"), 0);
        assert.equal(parseTrustedProxyHops("1"), 1);
        assert.equal(parseTrustedProxyHops("8"), 8);
        for (const invalid of ["", "-1", "01", "9", "1.5", "true"])
            assert.throws(() => parseTrustedProxyHops(invalid));
    });

    it("parses exact stable authorization policy configuration", () => {
        assert.deepEqual(
            parseAdministratorGroupIds('["z-stable","a-stable"]'),
            ["a-stable", "z-stable"]
        );
        for (const invalid of ["[]", '[""]', '["duplicate","duplicate"]'])
            assert.throws(() => parseAdministratorGroupIds(invalid));
        assert.equal(parseAuthorizationClaimsVersion("1"), 1);
        for (const invalid of ["0", "2", "01", "1.0"])
            assert.throws(() => parseAuthorizationClaimsVersion(invalid));
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
