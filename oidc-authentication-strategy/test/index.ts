import { generateKeyPairSync, KeyObject } from "crypto";
import axios, { AxiosRequestConfig } from "axios";
import { expect } from "chai";
import { SignJWT } from "jose";
import nock from "nock";

import OidcAuthenticationStrategy, { ILogger } from "../src";

type SigningKey = KeyObject | Uint8Array;

interface ITokenOptions {
    algorithm?: "HS256" | "PS256" | "RS256";
    signingKey?: SigningKey;
    kid?: string;
    expirationTime?: number | false;
    notBefore?: number;
}

describe("OidcAuthenticationStrategy", () => {
    const openidConfigurationUrl =
        "https://openid-configuration.example/.well-known/openid-configuration";
    const jwksUrl = "https://jwks.example/keys";
    const clientId = "clientId";
    const logger: ILogger = { error: () => undefined };
    const { publicKey, privateKey } = generateKeyPairSync("rsa", {
        modulusLength: 2048,
    });
    const signingKeyId = "signing-key";
    const publicJwk = {
        ...publicKey.export({ format: "jwk" }),
        alg: "RS256",
        kid: signingKeyId,
        use: "sig",
    };
    const jwks = { keys: [publicJwk] };
    const issuer = "https://issuer.localhost";
    const sub = "sub";

    const makeToken = async (
        claims: Record<string, unknown> = {
            sub,
            iss: issuer,
            aud: clientId,
        },
        options: ITokenOptions = {}
    ): Promise<string> => {
        const algorithm = options.algorithm ?? "RS256";
        const signingKey = options.signingKey ?? privateKey;
        let token = new SignJWT(claims).setProtectedHeader({
            alg: algorithm,
            kid: options.kid ?? signingKeyId,
        });
        if (options.expirationTime !== false) {
            token = token.setExpirationTime(
                options.expirationTime ?? Math.floor(Date.now() / 1000) + 300
            );
        }
        if (options.notBefore !== undefined) {
            token = token.setNotBefore(options.notBefore);
        }
        return token.sign(signingKey);
    };

    const mockConfiguration = () =>
        nock("https://openid-configuration.example")
            .get("/.well-known/openid-configuration")
            .reply(200, { issuer, jwks_uri: jwksUrl });

    const mockJwks = () =>
        nock("https://jwks.example").get("/keys").reply(200, jwks);

    const createStrategy = (
        configurationUrl = openidConfigurationUrl,
        strategyLogger = logger
    ) =>
        new OidcAuthenticationStrategy(
            configurationUrl,
            clientId,
            strategyLogger
        );

    beforeEach(() => {
        nock.cleanAll();
    });

    after(() => {
        nock.cleanAll();
    });

    it("uses bounded, fail-closed HTTP request options for discovery and JWKS", async () => {
        const requests: Array<{
            url: string;
            options: AxiosRequestConfig | undefined;
        }> = [];
        const originalGet = axios.get;
        axios.get = (async (url: string, options?: AxiosRequestConfig) => {
            requests.push({ url, options });
            return {
                data:
                    url === openidConfigurationUrl
                        ? { issuer, jwks_uri: jwksUrl }
                        : jwks,
            };
        }) as unknown as typeof axios.get;

        try {
            const result = await createStrategy().getIdpUserFromAuthToken(
                await makeToken()
            );
            expect(result).to.deep.equal({ id: sub, idp: issuer });
        } finally {
            axios.get = originalGet;
        }

        expect(requests.map(({ url }) => url)).to.deep.equal([
            openidConfigurationUrl,
            jwksUrl,
        ]);
        for (const { options } of requests) {
            expect(options).to.include({
                timeout: 5000,
                maxContentLength: 1024 * 1024,
                maxBodyLength: 1024 * 1024,
                maxRedirects: 0,
                responseType: "json",
            });
            expect(options?.transitional).to.deep.equal({
                silentJSONParsing: false,
            });
        }
    });

    it("fetches and caches one successful configuration across concurrent authentication", async () => {
        const configurationScope = mockConfiguration();
        const jwksScope = mockJwks();
        const strategy = createStrategy();
        const authToken = await makeToken();

        const users = await Promise.all(
            Array.from({ length: 5 }, () =>
                strategy.getIdpUserFromAuthToken(authToken)
            )
        );

        expect(users).to.deep.equal(
            Array.from({ length: 5 }, () => ({ id: sub, idp: issuer }))
        );
        configurationScope.done();
        jwksScope.done();
    });

    it("shares refreshes at expiry and retries after a shared failed refresh", async () => {
        const originalGet = axios.get;
        const originalDateNow = Date.now;
        let now = originalDateNow();
        let discoveryAttempts = 0;
        let jwksAttempts = 0;
        const authToken = await makeToken(undefined, {
            expirationTime: Math.floor(now / 1000) + 60 * 60,
        });
        Date.now = () => now;
        axios.get = (async (url: string) => {
            if (url === openidConfigurationUrl) {
                discoveryAttempts += 1;
                if (discoveryAttempts === 3) {
                    throw new Error("shared refresh failure");
                }
                return { data: { issuer, jwks_uri: jwksUrl } };
            }
            jwksAttempts += 1;
            return { data: jwks };
        }) as typeof axios.get;

        try {
            const strategy = createStrategy();
            expect(
                await strategy.getIdpUserFromAuthToken(authToken)
            ).to.deep.equal({ id: sub, idp: issuer });
            now += 5 * 60 * 1000 - 1;
            expect(
                await strategy.getIdpUserFromAuthToken(authToken)
            ).to.deep.equal({ id: sub, idp: issuer });
            expect([discoveryAttempts, jwksAttempts]).to.deep.equal([1, 1]);

            now += 2;
            expect(
                await Promise.all(
                    Array.from({ length: 5 }, () =>
                        strategy.getIdpUserFromAuthToken(authToken)
                    )
                )
            ).to.deep.equal(
                Array.from({ length: 5 }, () => ({ id: sub, idp: issuer }))
            );
            expect([discoveryAttempts, jwksAttempts]).to.deep.equal([2, 2]);

            now += 5 * 60 * 1000 + 1;
            expect(
                await Promise.all(
                    Array.from({ length: 5 }, () =>
                        strategy.getIdpUserFromAuthToken(authToken)
                    )
                )
            ).to.deep.equal(Array.from({ length: 5 }, () => null));
            expect([discoveryAttempts, jwksAttempts]).to.deep.equal([3, 2]);

            expect(
                await strategy.getIdpUserFromAuthToken(authToken)
            ).to.deep.equal({ id: sub, idp: issuer });
            expect([discoveryAttempts, jwksAttempts]).to.deep.equal([4, 3]);
        } finally {
            axios.get = originalGet;
            Date.now = originalDateNow;
        }
    });

    it("does not cache a failed configuration and retries discovery", async () => {
        const configurationScope = nock("https://openid-configuration.example")
            .get("/.well-known/openid-configuration")
            .reply(503)
            .get("/.well-known/openid-configuration")
            .reply(200, { issuer, jwks_uri: jwksUrl });
        const jwksScope = mockJwks();
        const strategy = createStrategy();
        const authToken = await makeToken();

        expect(await strategy.getIdpUserFromAuthToken(authToken)).to.equal(
            null
        );
        expect(await strategy.getIdpUserFromAuthToken(authToken)).to.deep.equal(
            { id: sub, idp: issuer }
        );
        configurationScope.done();
        jwksScope.done();
    });

    it("rejects discovery redirects without following them", async () => {
        const redirectTarget = nock("http://redirect.localhost")
            .get("/configuration")
            .reply(200, { issuer, jwks_uri: jwksUrl });
        const discovery = nock("https://openid-configuration.example")
            .get("/.well-known/openid-configuration")
            .reply(302, undefined, {
                Location: "http://redirect.localhost/configuration",
            });

        expect(
            await createStrategy().getIdpUserFromAuthToken(await makeToken())
        ).to.equal(null);
        discovery.done();
        expect(redirectTarget.isDone()).to.equal(false);
    });

    it("rejects JWKS redirects without following them", async () => {
        const discovery = mockConfiguration();
        const jwksScope = nock("https://jwks.example")
            .get("/keys")
            .reply(302, undefined, {
                Location: "http://redirect.localhost/keys",
            });
        const redirectTarget = nock("http://redirect.localhost")
            .get("/keys")
            .reply(200, jwks);

        expect(
            await createStrategy().getIdpUserFromAuthToken(await makeToken())
        ).to.equal(null);
        discovery.done();
        jwksScope.done();
        expect(redirectTarget.isDone()).to.equal(false);
    });

    for (const testCase of [
        {
            name: "oversized discovery responses",
            discovery: {
                issuer,
                jwks_uri: jwksUrl,
                padding: "x".repeat(1024 * 1024),
            },
            jwks: undefined,
        },
        {
            name: "oversized JWKS responses",
            discovery: { issuer, jwks_uri: jwksUrl },
            jwks: {
                ...jwks,
                padding: "x".repeat(1024 * 1024),
            },
        },
    ]) {
        it(`rejects ${testCase.name}`, async () => {
            const discovery = nock("https://openid-configuration.example")
                .get("/.well-known/openid-configuration")
                .reply(200, testCase.discovery);
            const jwksScope = testCase.jwks
                ? nock("https://jwks.example")
                      .get("/keys")
                      .reply(200, testCase.jwks)
                : undefined;

            expect(
                await createStrategy().getIdpUserFromAuthToken(
                    await makeToken()
                )
            ).to.equal(null);
            discovery.done();
            jwksScope?.done();
        });
    }

    it("rejects malformed discovery JSON", async () => {
        const discovery = nock("https://openid-configuration.example")
            .get("/.well-known/openid-configuration")
            .reply(200, "{", { "Content-Type": "application/json" });

        expect(
            await createStrategy().getIdpUserFromAuthToken(await makeToken())
        ).to.equal(null);
        discovery.done();
    });

    it("rejects malformed JWKS responses", async () => {
        const discovery = mockConfiguration();
        const jwksScope = nock("https://jwks.example")
            .get("/keys")
            .reply(200, { keys: "not-an-array" });

        expect(
            await createStrategy().getIdpUserFromAuthToken(await makeToken())
        ).to.equal(null);
        discovery.done();
        jwksScope.done();
    });

    it("requires HTTPS except for explicit loopback URLs", async () => {
        const authToken = await makeToken();
        const originalGet = axios.get;
        let unsafeRequests = 0;
        axios.get = (async () => {
            unsafeRequests += 1;
            throw new Error("Unsafe URL reached the HTTP client");
        }) as unknown as typeof axios.get;
        try {
            for (const unsafeUrl of [
                "file:///tmp/openid-configuration",
                "http://idp.example/.well-known/openid-configuration",
                "https://user:password@idp.example/.well-known/openid-configuration",
            ]) {
                expect(
                    await createStrategy(unsafeUrl).getIdpUserFromAuthToken(
                        authToken
                    )
                ).to.equal(null);
            }
            expect(unsafeRequests).to.equal(0);
        } finally {
            axios.get = originalGet;
        }

        const loopbackIssuer = "http://127.0.0.1:4455";
        const loopbackDiscovery = nock(loopbackIssuer)
            .get("/.well-known/openid-configuration")
            .reply(200, {
                issuer: loopbackIssuer,
                jwks_uri: `${loopbackIssuer}/keys`,
            });
        const loopbackJwks = nock(loopbackIssuer).get("/keys").reply(200, jwks);
        expect(
            await createStrategy(
                `${loopbackIssuer}/.well-known/openid-configuration`
            ).getIdpUserFromAuthToken(
                await makeToken({
                    sub,
                    iss: loopbackIssuer,
                    aud: clientId,
                })
            )
        ).to.deep.equal({ id: sub, idp: loopbackIssuer });
        loopbackDiscovery.done();
        loopbackJwks.done();

        const discovery = nock("https://openid-configuration.example")
            .get("/.well-known/openid-configuration")
            .reply(200, { issuer, jwks_uri: "file:///tmp/jwks" });
        expect(
            await createStrategy().getIdpUserFromAuthToken(authToken)
        ).to.equal(null);
        discovery.done();
    });

    it("logs configuration failures and returns null", async () => {
        const errors: unknown[][] = [];
        const recordingLogger = {
            error: (...args: unknown[]) => errors.push(args),
        } as ILogger;
        const strategy = createStrategy("not-a-valid-url", recordingLogger);

        expect(
            await strategy.getIdpUserFromAuthToken(await makeToken())
        ).to.equal(null);
        expect(errors).to.have.length(1);
        expect(errors[0][1]).to.equal(
            "Error configuring OidcAuthenticationStrategy"
        );
    });

    it("logs verification failures and returns null", async () => {
        const errors: unknown[][] = [];
        const recordingLogger = {
            error: (...args: unknown[]) => errors.push(args),
        } as ILogger;
        mockConfiguration();
        mockJwks();

        expect(
            await createStrategy(
                openidConfigurationUrl,
                recordingLogger
            ).getIdpUserFromAuthToken("un-decodable")
        ).to.equal(null);
        expect(errors).to.have.length(1);
        expect(errors[0][1]).to.equal(
            "Error verifying token with OidcAuthenticationStrategy"
        );
    });

    describe("token verification", () => {
        let strategy: OidcAuthenticationStrategy;

        before(async () => {
            nock.cleanAll();
            mockConfiguration();
            mockJwks();
            strategy = createStrategy();
            await strategy.getIdpUserFromAuthToken("un-decodable");
        });

        it("returns null on an un-decodable jwt", async () => {
            expect(
                await strategy.getIdpUserFromAuthToken("un-decodable")
            ).to.equal(null);
        });

        it("returns null when header.kid has no signing key", async () => {
            const authToken = await makeToken(undefined, {
                kid: "different-kid",
            });
            expect(await strategy.getIdpUserFromAuthToken(authToken)).to.equal(
                null
            );
        });

        it("returns null for the wrong issuer", async () => {
            const authToken = await makeToken({
                sub,
                iss: "https://different-issuer.localhost",
                aud: clientId,
            });
            expect(await strategy.getIdpUserFromAuthToken(authToken)).to.equal(
                null
            );
        });

        it("returns null when the ID token has no issuer", async () => {
            const authToken = await makeToken({ sub, aud: clientId });
            expect(await strategy.getIdpUserFromAuthToken(authToken)).to.equal(
                null
            );
        });

        it("returns null for the wrong audience", async () => {
            const authToken = await makeToken({
                sub,
                iss: issuer,
                aud: "different-clientId",
            });
            expect(await strategy.getIdpUserFromAuthToken(authToken)).to.equal(
                null
            );
        });

        it("returns null when the ID token has no audience", async () => {
            const authToken = await makeToken({ sub, iss: issuer });
            expect(await strategy.getIdpUserFromAuthToken(authToken)).to.equal(
                null
            );
        });

        it("returns null for an invalid signature", async () => {
            const differentPrivateKey = generateKeyPairSync("rsa", {
                modulusLength: 2048,
            }).privateKey;
            const authToken = await makeToken(undefined, {
                signingKey: differentPrivateKey,
            });
            expect(await strategy.getIdpUserFromAuthToken(authToken)).to.equal(
                null
            );
        });

        it("returns null when the ID token has no subject", async () => {
            const authToken = await makeToken({
                iss: issuer,
                aud: clientId,
            });
            expect(await strategy.getIdpUserFromAuthToken(authToken)).to.equal(
                null
            );
        });

        it("returns null when the ID token has no expiration", async () => {
            const authToken = await makeToken(undefined, {
                expirationTime: false,
            });
            expect(await strategy.getIdpUserFromAuthToken(authToken)).to.equal(
                null
            );
        });

        it("returns null when the ID token is expired", async () => {
            const authToken = await makeToken(undefined, {
                expirationTime: Math.floor(Date.now() / 1000) - 60,
            });
            expect(await strategy.getIdpUserFromAuthToken(authToken)).to.equal(
                null
            );
        });

        it("returns null before the ID token not-before time", async () => {
            const authToken = await makeToken(undefined, {
                notBefore: Math.floor(Date.now() / 1000) + 300,
            });
            expect(await strategy.getIdpUserFromAuthToken(authToken)).to.equal(
                null
            );
        });

        it("rejects an HS256 algorithm-confusion token", async () => {
            const rsaPublicKey = Buffer.from(
                publicKey.export({ type: "spki", format: "pem" })
            );
            const authToken = await makeToken(undefined, {
                algorithm: "HS256",
                signingKey: new Uint8Array(rsaPublicKey),
            });
            expect(await strategy.getIdpUserFromAuthToken(authToken)).to.equal(
                null
            );
        });

        it("rejects unsupported RSA algorithms", async () => {
            const authToken = await makeToken(undefined, {
                algorithm: "PS256",
            });
            expect(await strategy.getIdpUserFromAuthToken(authToken)).to.equal(
                null
            );
        });

        it("returns the idp user for a valid jwt", async () => {
            expect(
                await strategy.getIdpUserFromAuthToken(await makeToken())
            ).to.deep.equal({ id: sub, idp: issuer });
        });
    });
});
