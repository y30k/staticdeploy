import JwtAuthenticationStrategy from "@staticdeploy/jwt-authentication-strategy";
import { V2OidcSessions } from "@staticdeploy/pg-s3-storages";
import { expect } from "chai";
import express from "express";
import { createHmac } from "node:crypto";
import request from "supertest";

import V2SessionAuthenticationStrategy from "../../src/components/V2SessionAuthenticationStrategy";
import v2SessionRouter, {
    loginAdmissionSource,
    requireV2ApiSession,
} from "../../src/components/v2SessionRouter";

const cookie =
    "__Host-staticdeploy-session=10000000-0000-4000-8000-000000000001; Path=/; HttpOnly; Secure; SameSite=Lax";
const session = {
    id: "10000000-0000-4000-8000-000000000001",
    subjectId: "subject",
    issuer: "https://idp.example",
    claims: { sub: "subject" },
    csrfToken: "csrf-browser-value",
    csrfTokenDigest: "digest",
};

describe("M3-06 v2 session control routes", () => {
    let finishCalls: number;
    let failedCalls: number;
    let logoutCalls: number;
    let databaseReads: number;
    let touches: number;
    let loginSources: string[];

    const sessions = {
        portalRedirectUrl: "https://portal.example/",
        clearLoginCookie:
            "__Host-staticdeploy-oidc-tx=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
        clearSessionCookie:
            "__Host-staticdeploy-session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
        beginLogin: async (source: string) => {
            loginSources.push(source);
            return {
                authorizationUrl: "https://idp.example/authorize?safe=1",
                state: "state-is-server-side",
                loginCookie:
                    "__Host-staticdeploy-oidc-tx=10000000-0000-4000-8000-000000000099; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=300",
            };
        },
        finishLogin: async () => {
            finishCalls++;
            return {
                cookie,
                clearLoginCookie:
                    "__Host-staticdeploy-oidc-tx=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
                sessionId: session.id,
            };
        },
        consumeFailedLogin: async () => {
            failedCalls++;
        },
        inspect: async (cookieHeader?: string) => {
            databaseReads++;
            return cookieHeader?.includes(session.id) ? session : null;
        },
        authenticate: async (cookieHeader?: string) => {
            databaseReads++;
            return cookieHeader?.includes(session.id) ? session : null;
        },
        assertRequestShape: (
            origin?: string,
            contentType?: string,
            expected?: string
        ) => {
            if (
                origin !== "https://portal.example" ||
                contentType !== "application/json" ||
                expected !== "application/json"
            )
                throw new Error("secret provider diagnostic");
        },
        validateMutation: (
            _session: unknown,
            _origin?: string,
            csrf?: string
        ) => {
            if (csrf !== "csrf-browser-value") throw new Error("invalid csrf");
        },
        acceptInspected: async () => {
            touches++;
            return session;
        },
        logout: async () => {
            logoutCalls++;
            return "__Host-staticdeploy-session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
        },
    } as unknown as V2OidcSessions;

    const app = () =>
        express()
            .disable("x-powered-by")
            .use("/api/v2/auth", v2SessionRouter(sessions, 0));

    beforeEach(() => {
        finishCalls = 0;
        failedCalls = 0;
        logoutCalls = 0;
        databaseReads = 0;
        touches = 0;
        loginSources = [];
    });

    it("AUTH-01 redirects callbacks to a clean URL and bootstraps CSRF separately", async () => {
        await request(app())
            .get("/api/v2/auth/login")
            .expect(302)
            .expect("location", "https://idp.example/authorize?safe=1")
            .expect("set-cookie", /__Host-staticdeploy-oidc-tx=.*HttpOnly/)
            .expect("cache-control", "no-store");
        const callback = await request(app())
            .get("/api/v2/auth/callback?state=valid&code=valid")
            .expect(303)
            .expect("location", "https://portal.example/")
            .expect("cache-control", "no-store");
        expect(callback.headers["set-cookie"][0]).to.equal(cookie);
        expect(callback.headers["set-cookie"][1]).to.include(
            "__Host-staticdeploy-oidc-tx=;"
        );
        expect(callback.text).not.to.include("valid");
        const restored = await request(app())
            .get("/api/v2/auth/session")
            .set("cookie", cookie)
            .expect(200);
        expect(restored.body.csrfToken).to.equal("csrf-browser-value");
        expect(finishCalls).to.equal(1);
    });

    it("AUTH-02 consumes provider errors and every terminal malformed callback", async () => {
        for (const query of [
            "state=valid&error=access_denied",
            "state=valid",
            "state=valid&code=value&error=access_denied",
            "state=valid&code=",
            `state=valid&code=${"x".repeat(4097)}`,
        ])
            await request(app())
                .get(`/api/v2/auth/callback?${query}`)
                .expect(303)
                .expect("location", "https://portal.example/");
        expect(failedCalls).to.equal(5);
        const response = await request(app())
            .get("/api/v2/auth/callback?state=one&state=two&code=value")
            .expect(303);
        expect(response.text).not.to.include("value");
        expect(finishCalls).to.equal(0);
    });

    it("AUTH-01 bridges a cookie session to API identity without a browser bearer", async () => {
        const authentication = new V2SessionAuthenticationStrategy();
        let browserAuthorization: string | undefined;
        const api = express().use(
            "/api",
            requireV2ApiSession(sessions, authentication, "1kb"),
            async (req, res) => {
                browserAuthorization = req.headers.authorization;
                const token = (req as any).authToken as string;
                const user =
                    await authentication.getIdpUserFromAuthToken(token);
                res.json(user);
            }
        );
        const response = await request(api)
            .get("/api/currentUser")
            .set("cookie", cookie)
            .expect(200);
        expect(response.body).to.deep.equal({
            id: "subject",
            idp: "https://idp.example",
        });
        expect(browserAuthorization).to.equal(undefined);
    });

    it("AUTH-01 preserves exactly one bearer for the existing machine authentication pipeline", async () => {
        const authentication = new V2SessionAuthenticationStrategy();
        const jwtSecret = Buffer.from("machine-automation-secret");
        const jwt = new JwtAuthenticationStrategy(jwtSecret, "HS256");
        const encodedHeader = Buffer.from(
            JSON.stringify({ alg: "HS256", typ: "JWT" })
        ).toString("base64url");
        const encodedPayload = Buffer.from(
            JSON.stringify({ iss: "machine-idp", sub: "ci-agent" })
        ).toString("base64url");
        const unsigned = `${encodedHeader}.${encodedPayload}`;
        const validToken = `${unsigned}.${createHmac("sha256", jwtSecret)
            .update(unsigned)
            .digest("base64url")}`;
        let downstreamCalls = 0;
        const api = express().use(
            "/api",
            requireV2ApiSession(sessions, authentication, "1kb"),
            async (req, res) => {
                downstreamCalls++;
                const authorization = req.headers.authorization;
                const user =
                    typeof authorization === "string" &&
                    /^Bearer /i.test(authorization)
                        ? await jwt.getIdpUserFromAuthToken(
                              authorization.slice("Bearer ".length)
                          )
                        : null;
                if (user === null) return res.status(401).end();
                return res.status(200).json(user);
            }
        );
        await request(api)
            .get("/api/apps")
            .set("authorization", `Bearer ${validToken}`)
            .expect(200, { id: "ci-agent", idp: "machine-idp" });
        await request(api)
            .get("/api/apps")
            .set("authorization", "not-a-bearer")
            .expect(401);
        await request(api)
            .get("/api/apps")
            .set("authorization", [
                `Bearer ${validToken}`,
                "Bearer duplicate",
            ] as any)
            .expect(401);
        expect(downstreamCalls).to.equal(2);
        expect(databaseReads).to.equal(0);
        expect(touches).to.equal(0);
    });

    it("AUTH-01 derives admission identity only through the explicit proxy-hop contract", async () => {
        const candidate = (
            peer: string,
            forwarded?: string,
            duplicate = false
        ) =>
            ({
                socket: { remoteAddress: peer },
                headers:
                    forwarded === undefined
                        ? {}
                        : { "x-forwarded-for": forwarded },
                rawHeaders:
                    forwarded === undefined
                        ? []
                        : duplicate
                          ? [
                                "X-Forwarded-For",
                                forwarded,
                                "X-Forwarded-For",
                                "192.0.2.99",
                            ]
                          : ["X-Forwarded-For", forwarded],
            }) as any;
        expect(
            loginAdmissionSource(candidate("10.0.0.8", "spoofed, not-an-ip"), 0)
        ).to.equal("10.0.0.8");
        expect(
            loginAdmissionSource(candidate("10.0.0.8", "198.51.100.10"), 1)
        ).to.equal("198.51.100.10");
        expect(
            loginAdmissionSource(
                candidate("10.0.0.8", "203.0.113.7, 10.0.0.9"),
                2
            )
        ).to.equal("203.0.113.7");
        expect(() => loginAdmissionSource(candidate("10.0.0.8"), 1)).to.throw(
            "missing or ambiguous"
        );
        expect(() =>
            loginAdmissionSource(candidate("10.0.0.8", "not-an-ip"), 1)
        ).to.throw("rejected");
        expect(() =>
            loginAdmissionSource(
                candidate("10.0.0.8", "198.51.100.10", true),
                1
            )
        ).to.throw("missing or ambiguous");

        const proxied = express().use(
            "/api/v2/auth",
            v2SessionRouter(sessions, 1)
        );
        await request(proxied)
            .get("/api/v2/auth/login")
            .set("x-forwarded-for", "198.51.100.10")
            .expect(302);
        await request(proxied)
            .get("/api/v2/auth/login")
            .set("x-forwarded-for", "198.51.100.11")
            .expect(302);
        expect(loginSources).to.deep.equal(["198.51.100.10", "198.51.100.11"]);
    });

    it("AUTH-04 rejects request shape before database touch and clears stale cookies", async () => {
        const rejected = await request(app())
            .post("/api/v2/auth/logout")
            .set("cookie", cookie)
            .set("origin", "https://evil.example")
            .set("x-staticdeploy-csrf", "csrf-browser-value")
            .set("content-type", "application/json")
            .send({})
            .expect(401);
        expect(rejected.text).not.to.include("secret provider diagnostic");
        expect(databaseReads).to.equal(0);
        expect(logoutCalls).to.equal(0);

        const protectedApi = express().use(
            "/api",
            requireV2ApiSession(
                sessions,
                new V2SessionAuthenticationStrategy(),
                "32b"
            ),
            (_request, response) => response.status(204).end()
        );
        await request(protectedApi)
            .post("/api/apps")
            .set("cookie", cookie)
            .set("origin", "https://portal.example")
            .set("x-staticdeploy-csrf", "csrf-browser-value")
            .set("content-type", "application/json")
            .send('{"malformed"')
            .expect(400);
        expect(touches).to.equal(0);

        await request(app())
            .post("/api/v2/auth/logout")
            .set("cookie", cookie)
            .set("origin", "https://portal.example")
            .set("x-staticdeploy-csrf", "csrf-browser-value")
            .set("content-type", "application/json")
            .send({})
            .expect(204);
        expect(logoutCalls).to.equal(1);
        expect(touches).to.equal(1);

        await request(app())
            .post("/api/v2/auth/logout")
            .set("cookie", cookie)
            .set("origin", "https://portal.example")
            .set("x-staticdeploy-csrf", "csrf-browser-value")
            .set("content-type", "application/json")
            .send({ unexpected: true })
            .expect(400);
        expect(touches).to.equal(1);

        const stale = await request(app())
            .get("/api/v2/auth/session")
            .set("cookie", "__Host-staticdeploy-session=malformed")
            .expect(401);
        expect(stale.headers["set-cookie"][0]).to.include("Max-Age=0");
    });
});
