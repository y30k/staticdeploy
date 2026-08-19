import { V2OidcSessions } from "@staticdeploy/pg-s3-storages";
import { expect } from "chai";
import express from "express";
import request from "supertest";

import V2SessionAuthenticationStrategy from "../../src/components/V2SessionAuthenticationStrategy";
import v2SessionRouter, {
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

    const sessions = {
        portalRedirectUrl: "https://portal.example/",
        clearLoginCookie:
            "__Host-staticdeploy-oidc-tx=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
        clearSessionCookie:
            "__Host-staticdeploy-session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
        beginLogin: async () => ({
            authorizationUrl: "https://idp.example/authorize?safe=1",
            state: "state-is-server-side",
            loginCookie:
                "__Host-staticdeploy-oidc-tx=10000000-0000-4000-8000-000000000099; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=300",
        }),
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
            .use("/api/v2/auth", v2SessionRouter(sessions));

    beforeEach(() => {
        finishCalls = 0;
        failedCalls = 0;
        logoutCalls = 0;
        databaseReads = 0;
        touches = 0;
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
