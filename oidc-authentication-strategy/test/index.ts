import { JWK, JWKS, JWT } from "@panva/jose";
import axios, { AxiosRequestConfig } from "axios";
import Logger from "bunyan";
import { expect } from "chai";
import nock from "nock";

import OidcAuthenticationStrategy from "../src";

describe("OidcAuthenticationStrategy", () => {
    const openidConfigurationUrl =
        "http://openid-configuration.localhost/.well-known/openid-configuration";
    const jwksUrl = "http://jwks.localhost/keys";
    const clientId = "clientId";
    const logger = Logger.createLogger({ name: "test", streams: [] });
    const signingKey = JWK.generateSync("RSA");
    const issuer = "https://issuer.localhost";
    const sub = "sub";

    const validToken = () =>
        JWT.sign({ sub, iss: issuer, aud: clientId }, signingKey, {
            expiresIn: "5 minutes",
        });

    const mockConfiguration = () =>
        nock("http://openid-configuration.localhost")
            .get("/.well-known/openid-configuration")
            .reply(200, { issuer, jwks_uri: jwksUrl });

    const mockJwks = () =>
        nock("http://jwks.localhost")
            .get("/keys")
            .reply(200, new JWKS.KeyStore([signingKey]).toJWKS());

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
                        : new JWKS.KeyStore([signingKey]).toJWKS(),
            };
        }) as unknown as typeof axios.get;

        try {
            const result =
                await createStrategy().getIdpUserFromAuthToken(validToken());
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

    it("fetches and caches discovery and JWKS across concurrent authentication", async () => {
        const configurationScope = mockConfiguration();
        const jwksScope = mockJwks();
        const strategy = createStrategy();

        const users = await Promise.all(
            Array.from({ length: 5 }, () =>
                strategy.getIdpUserFromAuthToken(validToken())
            )
        );

        expect(users).to.deep.equal(
            Array.from({ length: 5 }, () => ({ id: sub, idp: issuer }))
        );
        configurationScope.done();
        jwksScope.done();
    });

    it("retries configuration after a failed discovery request", async () => {
        const configurationScope = nock("http://openid-configuration.localhost")
            .get("/.well-known/openid-configuration")
            .reply(503)
            .get("/.well-known/openid-configuration")
            .reply(200, { issuer, jwks_uri: jwksUrl });
        const jwksScope = mockJwks();
        const strategy = createStrategy();

        expect(await strategy.getIdpUserFromAuthToken(validToken())).to.equal(
            null
        );
        expect(
            await strategy.getIdpUserFromAuthToken(validToken())
        ).to.deep.equal({ id: sub, idp: issuer });
        configurationScope.done();
        jwksScope.done();
    });

    it("rejects discovery redirects without following them", async () => {
        const redirectTarget = nock("http://redirect.localhost")
            .get("/configuration")
            .reply(200, { issuer, jwks_uri: jwksUrl });
        const discovery = nock("http://openid-configuration.localhost")
            .get("/.well-known/openid-configuration")
            .reply(302, undefined, {
                Location: "http://redirect.localhost/configuration",
            });

        expect(
            await createStrategy().getIdpUserFromAuthToken(validToken())
        ).to.equal(null);
        discovery.done();
        expect(redirectTarget.isDone()).to.equal(false);
    });

    it("rejects JWKS redirects without following them", async () => {
        const discovery = mockConfiguration();
        const jwks = nock("http://jwks.localhost")
            .get("/keys")
            .reply(302, undefined, {
                Location: "http://redirect.localhost/keys",
            });
        const redirectTarget = nock("http://redirect.localhost")
            .get("/keys")
            .reply(200, new JWKS.KeyStore([signingKey]).toJWKS());

        expect(
            await createStrategy().getIdpUserFromAuthToken(validToken())
        ).to.equal(null);
        discovery.done();
        jwks.done();
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
                ...new JWKS.KeyStore([signingKey]).toJWKS(),
                padding: "x".repeat(1024 * 1024),
            },
        },
    ]) {
        it(`rejects ${testCase.name}`, async () => {
            const discovery = nock("http://openid-configuration.localhost")
                .get("/.well-known/openid-configuration")
                .reply(200, testCase.discovery);
            const jwks = testCase.jwks
                ? nock("http://jwks.localhost")
                      .get("/keys")
                      .reply(200, testCase.jwks)
                : undefined;

            expect(
                await createStrategy().getIdpUserFromAuthToken(validToken())
            ).to.equal(null);
            discovery.done();
            jwks?.done();
        });
    }

    it("rejects malformed discovery JSON", async () => {
        const discovery = nock("http://openid-configuration.localhost")
            .get("/.well-known/openid-configuration")
            .reply(200, "{", { "Content-Type": "application/json" });

        expect(
            await createStrategy().getIdpUserFromAuthToken(validToken())
        ).to.equal(null);
        discovery.done();
    });

    it("rejects malformed JWKS responses", async () => {
        const discovery = mockConfiguration();
        const jwks = nock("http://jwks.localhost")
            .get("/keys")
            .reply(200, { keys: "not-an-array" });

        expect(
            await createStrategy().getIdpUserFromAuthToken(validToken())
        ).to.equal(null);
        discovery.done();
        jwks.done();
    });

    it("rejects non-http(s) configured and discovered URLs", async () => {
        expect(
            await createStrategy(
                "file:///tmp/openid-configuration"
            ).getIdpUserFromAuthToken(validToken())
        ).to.equal(null);

        const discovery = nock("http://openid-configuration.localhost")
            .get("/.well-known/openid-configuration")
            .reply(200, { issuer, jwks_uri: "file:///tmp/jwks" });
        expect(
            await createStrategy().getIdpUserFromAuthToken(validToken())
        ).to.equal(null);
        discovery.done();
    });

    it("logs configuration failures and returns null", async () => {
        const errors: unknown[][] = [];
        const recordingLogger = {
            error: (...args: unknown[]) => errors.push(args),
        } as unknown as Logger;
        const strategy = createStrategy("not-a-valid-url", recordingLogger);

        expect(await strategy.getIdpUserFromAuthToken(validToken())).to.equal(
            null
        );
        expect(errors).to.have.length(1);
        expect(errors[0][1]).to.equal(
            "Error configuring OidcAuthenticationStrategy"
        );
    });

    it("logs verification failures and returns null", async () => {
        const errors: unknown[][] = [];
        const recordingLogger = {
            error: (...args: unknown[]) => errors.push(args),
        } as unknown as Logger;
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
            const authToken = JWT.sign(
                { sub, iss: issuer, aud: clientId },
                signingKey,
                {
                    expiresIn: "5 minutes",
                    kid: false,
                    header: { kid: "different-kid" },
                }
            );
            expect(await strategy.getIdpUserFromAuthToken(authToken)).to.equal(
                null
            );
        });

        it("returns null for the wrong issuer", async () => {
            const authToken = JWT.sign(
                {
                    sub,
                    iss: "https://different-issuer.localhost",
                    aud: clientId,
                },
                signingKey,
                { expiresIn: "5 minutes" }
            );
            expect(await strategy.getIdpUserFromAuthToken(authToken)).to.equal(
                null
            );
        });

        it("returns null for the wrong audience", async () => {
            const authToken = JWT.sign(
                { sub, iss: issuer, aud: "different-clientId" },
                signingKey,
                { expiresIn: "5 minutes" }
            );
            expect(await strategy.getIdpUserFromAuthToken(authToken)).to.equal(
                null
            );
        });

        it("returns null for an invalid signature", async () => {
            const authToken = JWT.sign(
                { sub, iss: issuer, aud: clientId },
                JWK.generateSync("RSA"),
                {
                    expiresIn: "5 minutes",
                    kid: false,
                    header: { kid: signingKey.kid },
                }
            );
            expect(await strategy.getIdpUserFromAuthToken(authToken)).to.equal(
                null
            );
        });

        it("returns null when the ID token has no subject", async () => {
            const authToken = JWT.sign(
                { iss: issuer, aud: clientId },
                signingKey,
                { expiresIn: "5 minutes" }
            );
            expect(await strategy.getIdpUserFromAuthToken(authToken)).to.equal(
                null
            );
        });

        it("returns null when the ID token has no expiration", async () => {
            const authToken = JWT.sign(
                { sub, iss: issuer, aud: clientId },
                signingKey
            );
            expect(await strategy.getIdpUserFromAuthToken(authToken)).to.equal(
                null
            );
        });

        it("returns the idp user for a valid jwt", async () => {
            expect(
                await strategy.getIdpUserFromAuthToken(validToken())
            ).to.deep.equal({ id: sub, idp: issuer });
        });
    });
});
