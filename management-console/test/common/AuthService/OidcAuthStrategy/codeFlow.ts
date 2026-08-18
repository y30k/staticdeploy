// @vitest-environment node

import { expect } from "chai";
import { createHash } from "node:crypto";
import type { Server } from "node:http";
import { createRemoteJWKSet, jwtVerify } from "jose";
import {
    InMemoryWebStorage,
    OidcClient,
    WebStorageStateStore,
} from "oidc-client-ts";
import { afterAll, beforeAll } from "vitest";

import { createMockApp } from "../../../../mock-server";
import {
    CLIENT_ID,
    DEV_ORIGIN,
    ISSUER,
    MOCK_HOST,
    MOCK_PORT,
} from "../../../../mock-server/oidc/state";

const redirectUri = `${DEV_ORIGIN}/?oidcRedirect=true`;
let server: Server;

beforeAll(async () => {
    const app = await createMockApp();
    server = await new Promise((resolve) => {
        const listener = app.listen(MOCK_PORT, MOCK_HOST, () =>
            resolve(listener)
        );
    });
});

afterAll(() => {
    server.closeAllConnections();
    return new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve()))
    );
});

describe("local OIDC Authorization Code + PKCE flow", () => {
    it("exchanges a real oidc-client-ts callback for signed tokens", async () => {
        const client = new OidcClient({
            authority: ISSUER,
            client_id: CLIENT_ID,
            metadataUrl: `${ISSUER}/oidc/configuration`,
            redirect_uri: redirectUri,
            response_mode: "query",
            response_type: "code",
            scope: "openid profile",
            stateStore: new WebStorageStateStore({
                store: new InMemoryWebStorage(),
            }),
        });
        const request = await client.createSigninRequest({
            nonce: "test-signin-nonce",
        });
        const authorizeUrl = new URL(request.url);
        expect(authorizeUrl.searchParams.get("code_challenge_method")).to.equal(
            "S256"
        );
        expect(authorizeUrl.searchParams.get("code_challenge")).to.match(
            /^[A-Za-z0-9_-]{43,128}$/
        );

        const authorization = await fetch(authorizeUrl, {
            redirect: "manual",
        });
        expect(authorization.status).to.equal(302);
        const callbackUrl = authorization.headers.get("location");
        expect(callbackUrl).to.be.a("string");

        const response = await client.processSigninResponse(callbackUrl!);
        expect(response.id_token).to.be.a("string").and.not.equal("");
        expect(response.access_token).to.be.a("string").and.not.equal("");
        expect(response.profile.iss).to.equal(ISSUER);
        expect(response.profile.aud).to.equal(CLIENT_ID);
        expect(response.profile.sub).to.equal("mock-user");
        const verification = await jwtVerify(
            response.id_token!,
            createRemoteJWKSet(new URL(`${ISSUER}/oidc/jwks`)),
            { audience: CLIENT_ID, issuer: ISSUER }
        );
        expect(verification.payload.sub).to.equal("mock-user");
    });

    it("rejects an unregistered redirect URI", async () => {
        const response = await fetch(
            `${ISSUER}/oidc/authorize?client_id=${CLIENT_ID}` +
                "&response_type=code&code_challenge_method=S256" +
                `&code_challenge=${"a".repeat(43)}&nonce=nonce&state=state` +
                "&redirect_uri=https%3A%2F%2Fevil.example%2Fcallback",
            { redirect: "manual" }
        );
        expect(response.status).to.equal(400);
        expect(response.headers.get("location")).to.equal(null);
    });

    it("rejects missing nonce, verifier mismatch, and authorization-code replay", async () => {
        const missingNonce = await fetch(
            `${ISSUER}/oidc/authorize?client_id=${CLIENT_ID}` +
                "&response_type=code&code_challenge_method=S256" +
                `&code_challenge=${"a".repeat(43)}&state=${"s".repeat(8)}` +
                `&redirect_uri=${encodeURIComponent(redirectUri)}`,
            { redirect: "manual" }
        );
        expect(missingNonce.status).to.equal(400);

        const verifier = "v".repeat(43);
        const challenge = createHash("sha256")
            .update(verifier)
            .digest("base64url");
        const authorize = new URL(`${ISSUER}/oidc/authorize`);
        authorize.search = new URLSearchParams({
            client_id: CLIENT_ID,
            code_challenge: challenge,
            code_challenge_method: "S256",
            nonce: "test-nonce",
            redirect_uri: redirectUri,
            response_type: "code",
            state: "test-state",
        }).toString();
        const authorization = await fetch(authorize, { redirect: "manual" });
        const callback = new URL(authorization.headers.get("location")!);
        const code = callback.searchParams.get("code")!;
        const tokenRequest = (codeVerifier: string) =>
            fetch(`${ISSUER}/oidc/token`, {
                method: "POST",
                headers: {
                    "content-type": "application/x-www-form-urlencoded",
                    origin: DEV_ORIGIN,
                },
                body: new URLSearchParams({
                    client_id: CLIENT_ID,
                    code,
                    code_verifier: codeVerifier,
                    grant_type: "authorization_code",
                    redirect_uri: redirectUri,
                }),
            });
        expect((await tokenRequest(`${verifier}x`)).status).to.equal(400);
        expect((await tokenRequest(verifier)).status).to.equal(400);

        const authorization2 = await fetch(authorize, { redirect: "manual" });
        const code2 = new URL(
            authorization2.headers.get("location")!
        ).searchParams.get("code")!;
        const validBody = new URLSearchParams({
            client_id: CLIENT_ID,
            code: code2,
            code_verifier: verifier,
            grant_type: "authorization_code",
            redirect_uri: redirectUri,
        });
        expect(
            (
                await fetch(`${ISSUER}/oidc/token`, {
                    method: "POST",
                    headers: {
                        "content-type": "application/x-www-form-urlencoded",
                        origin: DEV_ORIGIN,
                    },
                    body: validBody,
                })
            ).status
        ).to.equal(200);
        expect(
            (
                await fetch(`${ISSUER}/oidc/token`, {
                    method: "POST",
                    headers: {
                        "content-type": "application/x-www-form-urlencoded",
                        origin: DEV_ORIGIN,
                    },
                    body: validBody,
                })
            ).status
        ).to.equal(400);
    });

    it("permits credentialed preflight only from the exact dev origin", async () => {
        const allowed = await fetch(`${ISSUER}/oidc/token`, {
            method: "OPTIONS",
            headers: { origin: DEV_ORIGIN },
        });
        expect(allowed.status).to.equal(204);
        expect(allowed.headers.get("access-control-allow-origin")).to.equal(
            DEV_ORIGIN
        );
        expect(
            allowed.headers.get("access-control-allow-credentials")
        ).to.equal("true");

        const denied = await fetch(`${ISSUER}/oidc/token`, {
            method: "OPTIONS",
            headers: { origin: "http://localhost:5173" },
        });
        expect(denied.status).to.equal(403);
        expect(denied.headers.get("access-control-allow-origin")).to.equal(
            null
        );
    });
});
