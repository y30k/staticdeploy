import { expect } from "chai";
import { Knex } from "knex";
import {
    createHash,
    generateKeyPairSync,
    randomBytes,
    randomUUID,
    sign,
} from "node:crypto";
import { createServer } from "node:http";
import { join } from "node:path";

import {
    isGlobalOidcAddress,
    V2OidcSessionOptions,
    V2OidcSessions,
    V2_SESSION_COOKIE,
} from "../src/V2Sessions";
import { createPostgresKnex } from "../src/postgres";

const postgresUrl =
    process.env.POSTGRES_TEST_URL ??
    "postgres://postgres:password@127.0.0.1:5432/postgres";
const issuer = "https://idp.example/realm";
const configurationUrl = `${issuer}/.well-known/openid-configuration`;
const clientId = "staticdeploy-control";
const redirectUri = "https://portal.example/api/v2/auth/callback";
const portalOrigin = "https://portal.example";
const accessCanary = "access-token-must-never-leak";
const refreshCanary = "refresh-token-must-never-leak";

interface Flow {
    challenge?: string;
    nonce?: string;
    codeUsed: boolean;
    tokenMutation?: (
        payload: Record<string, unknown>
    ) => Record<string, unknown>;
    headerMutation?: (
        header: Record<string, unknown>
    ) => Record<string, unknown>;
    signingKey?: "trusted" | "attacker" | "weak";
    jwksKid?: string;
    jwksRequests: number;
    discoveryRequests?: number;
    discoveryMutation?: (
        value: Record<string, unknown>
    ) => Record<string, unknown>;
    jwkMutation?: (value: Record<string, unknown>) => Record<string, unknown>;
}

const b64 = (value: unknown): string =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
const digestForTest = (value: string): string =>
    createHash("sha256").update(value).digest("hex");

const expectRejected = async (operation: Promise<unknown>): Promise<void> => {
    let failed = false;
    try {
        await operation;
    } catch {
        failed = true;
    }
    expect(failed).to.equal(true);
};

describe("M3-06 server-side OIDC sessions", () => {
    let admin: Knex;
    let database: Knex;
    let databaseName: string;
    const trusted = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const attacker = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const weak = generateKeyPairSync("rsa", { modulusLength: 1024 });
    const trustedJwk = trusted.publicKey.export({ format: "jwk" });
    const weakJwk = weak.publicKey.export({ format: "jwk" });
    const flow: Flow = { codeUsed: false, jwksRequests: 0 };
    const keyOne = randomBytes(32);
    const keyTwo = randomBytes(32);

    before(async () => {
        admin = createPostgresKnex(postgresUrl);
        databaseName = `v2_auth_${process.pid}_${Date.now()}`;
        await admin.raw(`CREATE DATABASE ??`, [databaseName]);
        const parsed = new URL(postgresUrl);
        parsed.pathname = `/${databaseName}`;
        database = createPostgresKnex(parsed.toString());
        await database.migrate.latest({
            directory: join(__dirname, "../lib/migrations"),
            loadExtensions: [".js"],
        });
    });

    after(async () => {
        if (database !== undefined) await database.destroy();
        if (admin !== undefined) {
            await admin.raw(`DROP DATABASE IF EXISTS ?? WITH (FORCE)`, [
                databaseName,
            ]);
            await admin.destroy();
        }
    });

    beforeEach(() => {
        flow.challenge = undefined;
        flow.nonce = undefined;
        flow.codeUsed = false;
        flow.tokenMutation = undefined;
        flow.headerMutation = undefined;
        flow.signingKey = "trusted";
        flow.jwksKid = "trusted-key";
        flow.jwksRequests = 0;
        flow.discoveryRequests = 0;
        flow.discoveryMutation = undefined;
        flow.jwkMutation = undefined;
    });

    const mockFetch: typeof fetch = async (input, init) => {
        const url = String(input);
        if (url === configurationUrl) {
            flow.discoveryRequests = (flow.discoveryRequests ?? 0) + 1;
            const value = {
                issuer,
                authorization_endpoint: `${issuer}/authorize`,
                token_endpoint: `${issuer}/token`,
                jwks_uri: `${issuer}/jwks`,
                code_challenge_methods_supported: ["S256"],
                id_token_signing_alg_values_supported: ["RS256"],
                response_types_supported: ["code"],
                token_endpoint_auth_methods_supported: ["none"],
            };
            return Response.json(flow.discoveryMutation?.(value) ?? value);
        }
        if (url === `${issuer}/jwks`) {
            flow.jwksRequests++;
            const key = {
                ...trustedJwk,
                kid: flow.jwksKid,
                use: "sig",
                alg: "RS256",
            };
            return Response.json({
                keys: [flow.jwkMutation?.(key) ?? key],
            });
        }
        if (url === `${issuer}/token`) {
            const body = new URLSearchParams(String(init?.body));
            const verifier = body.get("code_verifier") ?? "";
            if (
                flow.codeUsed ||
                body.get("code") !== "single-use-code" ||
                createHash("sha256").update(verifier).digest("base64url") !==
                    flow.challenge
            )
                return Response.json(
                    { error: "invalid_grant" },
                    { status: 400 }
                );
            flow.codeUsed = true;
            const now = Math.floor(Date.now() / 1000);
            let payload: Record<string, unknown> = {
                iss: issuer,
                aud: clientId,
                sub: "user-123",
                exp: now + 300,
                iat: now,
                nonce: flow.nonce,
                groups: ["publishers"],
            };
            payload = flow.tokenMutation?.(payload) ?? payload;
            let header: Record<string, unknown> = {
                alg: "RS256",
                kid: "trusted-key",
                typ: "JWT",
            };
            header = flow.headerMutation?.(header) ?? header;
            const unsigned = `${b64(header)}.${b64(payload)}`;
            const privateKey =
                flow.signingKey === "attacker"
                    ? attacker.privateKey
                    : flow.signingKey === "weak"
                      ? weak.privateKey
                      : trusted.privateKey;
            const signature = sign(
                "RSA-SHA256",
                Buffer.from(unsigned),
                privateKey
            );
            return Response.json({
                token_type: "Bearer",
                id_token: `${unsigned}.${signature.toString("base64url")}`,
                access_token: accessCanary,
                refresh_token: refreshCanary,
            });
        }
        throw new Error(`unexpected mock request ${url}`);
    };

    const sessions = (
        primaryKeyId = "key-2",
        keys = [
            { id: "key-2", key: keyTwo },
            { id: "key-1", key: keyOne },
        ],
        idleLifetimeMs = 10_000,
        absoluteLifetimeMs = 60_000
    ) =>
        new V2OidcSessions(database, {
            clientId,
            configurationUrl,
            expectedIssuer: issuer,
            redirectUri,
            portalOrigin,
            primaryKeyId,
            encryptionKeys: keys,
            loginLifetimeMs: 10_000,
            idleLifetimeMs,
            absoluteLifetimeMs,
            resolveAddresses: async () => ["93.184.216.34"],
            fetch: mockFetch,
        });

    it("AUTH-01 classifies every special IP family fail-closed", () => {
        for (const address of [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.0.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::10.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::1",
            "100::1",
            "2001:db8::1",
            "2002::1",
            "3fff::1",
            "fc00::1",
            "fe80::1",
            "ff00::1",
        ])
            expect(isGlobalOidcAddress(address), address).to.equal(false);
        for (const address of [
            "8.8.8.8",
            "93.184.216.34",
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
        ])
            expect(isGlobalOidcAddress(address), address).to.equal(true);
    });

    it("AUTH-01 fails closed on unsafe origins, DNS, and transaction lifetimes", async () => {
        const base = {
            clientId,
            configurationUrl,
            expectedIssuer: issuer,
            redirectUri,
            portalOrigin,
            primaryKeyId: "key-2",
            encryptionKeys: [{ id: "key-2", key: keyTwo }],
            resolveAddresses: async () => ["93.184.216.34"],
            fetch: mockFetch,
        };
        expect(
            () =>
                new V2OidcSessions(database, {
                    ...base,
                    loginLifetimeMs: 300_001,
                })
        ).to.throw("invalid session lifetimes");
        expect(
            () =>
                new V2OidcSessions(database, {
                    ...base,
                    configurationUrl:
                        "https://127.0.0.1/.well-known/openid-configuration",
                    expectedIssuer: "https://127.0.0.1",
                })
        ).to.throw("invalid expected issuer");
        expect(
            () =>
                new V2OidcSessions(database, {
                    ...base,
                    configurationUrl: `${configurationUrl}#fragment`,
                })
        ).to.throw("invalid configuration URL");
        const mixedResolution = new V2OidcSessions(database, {
            ...base,
            resolveAddresses: async () => ["93.184.216.34", "169.254.169.254"],
        });
        await expectRejected(mixedResolution.beginLogin());
        await mixedResolution.destroy();
    });

    it("AUTH-01 pins the validated DNS answer through connection", async () => {
        let resolutions = 0;
        const connected: string[] = [];
        const options: V2OidcSessionOptions = {
            clientId,
            configurationUrl,
            expectedIssuer: issuer,
            redirectUri,
            portalOrigin,
            primaryKeyId: "key-2",
            encryptionKeys: [{ id: "key-2", key: keyTwo }],
            resolveAddresses: async () => {
                resolutions++;
                return resolutions === 1
                    ? ["93.184.216.34"]
                    : ["169.254.169.254"];
            },
        };
        const service = new V2OidcSessions(database, options);
        (service as any).pinnedRequest = async (
            url: URL,
            address: string,
            init: RequestInit
        ) => {
            connected.push(address);
            return mockFetch(url.toString(), init);
        };
        await service.beginLogin();
        expect(resolutions).to.equal(1);
        expect(connected).to.deep.equal(["93.184.216.34"]);
        await service.destroy();
    });

    it("AUTH-01 enforces an absolute pinned-response deadline", async () => {
        const server = createServer((_request, response) => {
            response.writeHead(200, { "content-type": "application/json" });
            const trickle = setInterval(() => response.write(" "), 10);
            response.on("close", () => clearInterval(trickle));
        });
        await new Promise<void>((resolve, reject) => {
            server.once("error", reject);
            server.listen(0, "127.0.0.1", () => resolve());
        });
        const address = server.address();
        if (address === null || typeof address === "string")
            throw new Error("test server did not bind TCP");
        const service = new V2OidcSessions(database, {
            clientId,
            configurationUrl,
            expectedIssuer: issuer,
            redirectUri,
            portalOrigin,
            primaryKeyId: "key-2",
            encryptionKeys: [{ id: "key-2", key: keyTwo }],
            allowHttpLoopbackForTests: true,
            httpTimeoutMs: 80,
        });
        const started = Date.now();
        try {
            await expectRejected(
                (service as any).fetchBounded(
                    `http://127.0.0.1:${address.port}/slow-trickle`
                )
            );
            expect(Date.now() - started).to.be.lessThan(1_000);
        } finally {
            await service.destroy();
            await new Promise<void>((resolve, reject) =>
                server.close((error) =>
                    error === undefined ? resolve() : reject(error)
                )
            );
        }
    });

    it("AUTH-01 revokes PUBLIC table and function access", async () => {
        const privileges = await database.raw(`
            select
                has_table_privilege('public', 'public.v2_login_transactions', 'SELECT') as table_select,
                has_table_privilege('public', 'public.v2_sessions', 'SELECT') as session_select,
                has_function_privilege(
                    'public',
                    'public.v2_begin_oidc_login(uuid,text,text,text,bytea,bytea,text,text,text,integer)',
                    'EXECUTE'
                ) as begin_execute,
                has_function_privilege(
                    'public',
                    'public.v2_use_session(uuid,integer)',
                    'EXECUTE'
                ) as use_execute
        `);
        expect(privileges.rows[0]).to.deep.equal({
            table_select: false,
            session_select: false,
            begin_execute: false,
            use_execute: false,
        });
        const functions = await database("pg_proc as p")
            .join("pg_namespace as n", "n.oid", "p.pronamespace")
            .where("n.nspname", "public")
            .whereIn("p.proname", [
                "v2_begin_oidc_login",
                "v2_consume_oidc_login",
                "v2_create_or_replace_session",
                "v2_read_session",
                "v2_use_session",
                "v2_rotate_session_envelope",
                "v2_revoke_session",
                "v2_cleanup_auth_state",
            ])
            .select("p.proname", "p.prosecdef", "p.proconfig")
            .orderBy("p.proname");
        expect(functions).to.have.length(8);
        for (const fn of functions) {
            expect(fn.prosecdef).to.equal(true);
            expect(fn.proconfig).to.include("search_path=pg_catalog");
            expect(fn.proconfig).to.include("lock_timeout=5s");
            expect(fn.proconfig).to.include("statement_timeout=10s");
        }

        const runtimeRole = `v2_auth_runtime_${process.pid}_${Date.now()}`;
        await database.raw(`CREATE ROLE ${runtimeRole} NOLOGIN`);
        try {
            await database.raw(`
                GRANT USAGE ON SCHEMA public TO ${runtimeRole};
                GRANT EXECUTE ON FUNCTION
                    public.v2_begin_oidc_login(uuid,text,text,text,bytea,bytea,text,text,text,integer),
                    public.v2_consume_oidc_login(uuid,text),
                    public.v2_create_or_replace_session(uuid,uuid,text,text,jsonb,text,text,bytea,bytea,integer,integer),
                    public.v2_read_session(uuid),
                    public.v2_use_session(uuid,integer),
                    public.v2_rotate_session_envelope(uuid,text,text,bytea,bytea),
                    public.v2_revoke_session(uuid,text),
                    public.v2_cleanup_auth_state(bigint,integer)
                TO ${runtimeRole}
            `);
            await database.transaction(async (transaction) => {
                await transaction.raw(
                    "REVOKE CREATE ON SCHEMA public FROM PUBLIC"
                );
                await transaction.raw(`SET LOCAL ROLE ${runtimeRole}`);
                const service = sessions();
                (service as any).database = transaction;
                await service.verifyReady();
                await transaction.raw("RESET ROLE");
                await transaction.raw(
                    `GRANT SELECT ON public.v2_login_transactions TO ${runtimeRole}`
                );
                await transaction.raw(`SET LOCAL ROLE ${runtimeRole}`);
                await expectRejected(service.verifyReady());
                await transaction.raw("RESET ROLE");
                await transaction.raw(
                    `REVOKE SELECT ON public.v2_login_transactions FROM ${runtimeRole}`
                );
                for (const [grant, revoke] of [
                    [
                        `GRANT SELECT (csrf_token_digest) ON public.v2_sessions TO ${runtimeRole}`,
                        `REVOKE SELECT (csrf_token_digest) ON public.v2_sessions FROM ${runtimeRole}`,
                    ],
                    [
                        `GRANT REFERENCES ON public.v2_sessions TO ${runtimeRole}`,
                        `REVOKE REFERENCES ON public.v2_sessions FROM ${runtimeRole}`,
                    ],
                    [
                        `GRANT SELECT ON public.knex_migrations TO ${runtimeRole}`,
                        `REVOKE SELECT ON public.knex_migrations FROM ${runtimeRole}`,
                    ],
                ]) {
                    await transaction.raw(grant);
                    await transaction.raw(`SET LOCAL ROLE ${runtimeRole}`);
                    await expectRejected(service.verifyReady());
                    await transaction.raw("RESET ROLE");
                    await transaction.raw(revoke);
                }
                const ownedSchema = `v2_auth_owned_${process.pid}`;
                await transaction.raw(
                    `CREATE SCHEMA ${ownedSchema} AUTHORIZATION ${runtimeRole}`
                );
                await transaction.raw(`SET LOCAL ROLE ${runtimeRole}`);
                await expectRejected(service.verifyReady());
                await transaction.raw("RESET ROLE");
                await transaction.raw(`DROP SCHEMA ${ownedSchema}`);
                await transaction.raw(
                    `GRANT EXECUTE ON FUNCTION public.v2_claim_release_jobs(text,integer,integer) TO ${runtimeRole}`
                );
                await transaction.raw(`SET LOCAL ROLE ${runtimeRole}`);
                await expectRejected(service.verifyReady());
                await transaction.raw("RESET ROLE");
                await transaction.raw(
                    `REVOKE EXECUTE ON FUNCTION public.v2_claim_release_jobs(text,integer,integer) FROM ${runtimeRole}`
                );
                await transaction.raw(`SET LOCAL ROLE ${runtimeRole}`);
                await service.verifyReady();
                await transaction.raw("RESET ROLE");

                const signature = "public.v2_read_session(uuid)";
                const owner = (
                    await transaction.raw(
                        "SELECT pg_get_userbyid(proowner) AS owner FROM pg_proc WHERE oid = to_regprocedure(?)",
                        [signature]
                    )
                ).rows[0].owner as string;
                try {
                    await transaction.raw(
                        `ALTER FUNCTION ${signature} OWNER TO ??`,
                        [runtimeRole]
                    );
                    await transaction.raw(`SET LOCAL ROLE ${runtimeRole}`);
                    await expectRejected(service.verifyReady());
                    await transaction.raw("RESET ROLE");
                } finally {
                    await transaction.raw("RESET ROLE");
                    await transaction.raw(
                        `ALTER FUNCTION ${signature} OWNER TO ??`,
                        [owner]
                    );
                }
                await service.destroy();
            });
        } finally {
            await database.raw(`DROP OWNED BY ${runtimeRole}`);
            await database.raw(`DROP ROLE ${runtimeRole}`);
        }
    });

    const begin = async (service = sessions()) => {
        const start = await service.beginLogin();
        const authorize = new URL(start.authorizationUrl);
        flow.challenge =
            authorize.searchParams.get("code_challenge") ?? undefined;
        flow.nonce = authorize.searchParams.get("nonce") ?? undefined;
        expect(authorize.searchParams.get("code_challenge_method")).to.equal(
            "S256"
        );
        expect(authorize.searchParams.get("response_type")).to.equal("code");
        return { service, start };
    };
    const finish = (
        candidate: Awaited<ReturnType<typeof begin>>,
        code = "single-use-code",
        existingSessionId?: string
    ) =>
        candidate.service.finishLogin(
            candidate.start.state,
            code,
            candidate.start.loginCookie,
            existingSessionId
        );

    it("AUTH-01 exchanges Code+S256 and stores only opaque encrypted session state", async () => {
        const candidate = await begin();
        const { service } = candidate;
        expect(candidate.start.loginCookie).not.to.include(
            candidate.start.state
        );
        expect(candidate.start.loginCookie).to.match(
            /__Host-staticdeploy-oidc-tx=[0-9a-f-]{36}; Path=\/; HttpOnly; Secure; SameSite=Lax/
        );
        const result = await finish(candidate);
        flow.codeUsed = false;
        await candidate.service.beginLogin();
        expect(flow.discoveryRequests).to.equal(1);
        expect(result.cookie).to.equal(
            `${V2_SESSION_COOKIE}=${result.sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax`
        );
        expect(result.cookie).not.to.include(accessCanary);
        const authenticated = await service.authenticate(result.cookie);
        expect(authenticated?.subjectId).to.equal("user-123");
        expect(
            await service.authenticate(`${result.cookie}; ${result.cookie}`)
        ).to.equal(null);
        expect(authenticated?.claims).to.deep.equal({
            sub: "user-123",
            groups: ["publishers"],
        });
        const row = await database("v2_sessions")
            .where({ id: result.sessionId })
            .first();
        expect(row.token_key_id).to.equal("key-2");
        const retained = Buffer.from(row.encrypted_token_material).toString(
            "utf8"
        );
        expect(retained).not.to.include(accessCanary);
        expect(retained).not.to.include(refreshCanary);
        expect(JSON.stringify(row.claims)).not.to.include(accessCanary);
    });

    it("AUTH-02 binds the pre-login cookie, consumes state atomically, and rejects invalid trust", async () => {
        const bound = await begin();
        await expectRejected(
            bound.service.finishLogin(
                bound.start.state,
                "single-use-code",
                `__Host-staticdeploy-oidc-tx=00000000-0000-4000-8000-000000000000`
            )
        );
        await expectRejected(
            bound.service.finishLogin(
                bound.start.state,
                "single-use-code",
                `${bound.start.loginCookie}; ${bound.start.loginCookie}`
            )
        );
        await finish(bound);

        flow.codeUsed = false;
        const malformedTerminal = await begin();
        await malformedTerminal.service.consumeFailedLogin(
            malformedTerminal.start.state,
            malformedTerminal.start.loginCookie
        );
        await expectRejected(finish(malformedTerminal));

        flow.codeUsed = false;
        const replay = await begin();
        const race = await Promise.allSettled([finish(replay), finish(replay)]);
        expect(
            race.filter((result) => result.status === "fulfilled")
        ).to.have.length(1);
        expect(
            race.filter((result) => result.status === "rejected")
        ).to.have.length(1);
        let rejected = 0;
        try {
            await finish(replay);
        } catch {
            rejected++;
        }
        expect(rejected).to.equal(1);

        flow.codeUsed = false;
        const expiredCode = await begin();
        let expiredCodeRejected = false;
        try {
            await finish(expiredCode, "expired-code");
        } catch {
            expiredCodeRejected = true;
        }
        expect(expiredCodeRejected).to.equal(true);
        flow.codeUsed = false;
        await expectRejected(finish(expiredCode));
        await expectRejected(
            expiredCode.service.finishLogin(
                "a".repeat(43),
                "single-use-code",
                expiredCode.start.loginCookie
            )
        );

        const mutations: Array<() => void> = [
            () => {
                flow.tokenMutation = (payload) => ({
                    ...payload,
                    iss: "https://evil.example",
                });
            },
            () => {
                flow.tokenMutation = (payload) => ({
                    ...payload,
                    aud: "wrong-client",
                });
            },
            () => {
                flow.tokenMutation = (payload) => ({
                    ...payload,
                    nonce: "wrong-nonce",
                });
            },
            () => {
                flow.tokenMutation = (payload) => ({ ...payload, exp: 1 });
            },
            () => {
                flow.tokenMutation = (payload) => ({ ...payload, iat: -1 });
            },
            () => {
                flow.tokenMutation = (payload) => ({
                    ...payload,
                    aud: [clientId, "other"],
                });
            },
            () => {
                flow.tokenMutation = (payload) => ({
                    ...payload,
                    nbf: Math.floor(Date.now() / 1000) + 600,
                });
            },
            () => {
                flow.tokenMutation = (payload) => ({ ...payload, sub: "" });
            },
            () => {
                flow.headerMutation = (header) => ({ ...header, alg: "HS256" });
            },
            () => {
                flow.signingKey = "attacker";
            },
        ];
        flow.codeUsed = false;
        flow.jwksRequests = 0;
        const unknownKid = await begin();
        flow.headerMutation = (header) => ({ ...header, kid: "unknown" });
        let unknownKidFailed = false;
        try {
            await finish(unknownKid);
        } catch {
            unknownKidFailed = true;
        }
        expect(unknownKidFailed).to.equal(true);
        expect(flow.jwksRequests).to.equal(1);

        flow.codeUsed = false;
        flow.headerMutation = undefined;
        const incompatibleJwk = await begin(sessions());
        flow.jwkMutation = (key) => ({ ...key, alg: "RS512" });
        await expectRejected(finish(incompatibleJwk));
        flow.jwkMutation = undefined;

        flow.codeUsed = false;
        const paddedWeakJwk = await begin(sessions());
        const weakModulus = Buffer.from(weakJwk.n!, "base64url");
        flow.jwkMutation = (key) => ({
            ...key,
            n: Buffer.concat([
                Buffer.alloc(256 - weakModulus.length),
                weakModulus,
            ]).toString("base64url"),
            e: weakJwk.e,
        });
        flow.signingKey = "weak";
        await expectRejected(finish(paddedWeakJwk));
        flow.jwkMutation = undefined;
        flow.signingKey = "trusted";

        flow.discoveryMutation = (value) => {
            const { response_types_supported: _removed, ...rest } = value;
            return rest;
        };
        await expectRejected(begin());
        flow.discoveryMutation = undefined;

        for (const mutate of mutations) {
            flow.codeUsed = false;
            flow.tokenMutation = undefined;
            flow.headerMutation = undefined;
            flow.signingKey = "trusted";
            const candidate = await begin();
            mutate();
            let failed = false;
            try {
                await finish(candidate);
            } catch {
                failed = true;
            }
            expect(failed).to.equal(true);
        }
    });

    it("AUTH-03 rotates fixation candidates, supports signing/envelope key rotation, logout and expiry", async () => {
        const signingRotationService = sessions();
        const signingFirst = await begin(signingRotationService);
        await finish(signingFirst);
        flow.codeUsed = false;
        const signingSecond = await begin(signingRotationService);
        flow.jwksKid = "rotated-key";
        flow.headerMutation = (header) => ({
            ...header,
            kid: "rotated-key",
        });
        await finish(signingSecond);
        expect(flow.jwksRequests).to.equal(2);

        flow.codeUsed = false;
        flow.headerMutation = undefined;
        flow.jwksKid = "trusted-key";
        const overlapFlow = await begin(sessions("key-1"));
        const overlap = await finish(overlapFlow);
        const oldEnvelope = await database("v2_sessions")
            .where({ id: overlap.sessionId })
            .first("token_nonce");
        expect(
            await sessions("key-2").authenticate(overlap.cookie)
        ).not.to.equal(null);
        const rotatedEnvelope = await database("v2_sessions")
            .where({ id: overlap.sessionId })
            .first("token_key_id", "token_nonce");
        expect(rotatedEnvelope.token_key_id).to.equal("key-2");
        expect(Buffer.from(rotatedEnvelope.token_nonce)).not.to.deep.equal(
            Buffer.from(oldEnvelope.token_nonce)
        );

        flow.codeUsed = false;
        const oldFlow = await begin(sessions("key-1"));
        const old = await finish(oldFlow);
        flow.codeUsed = false;
        const newFlow = await begin(sessions("key-2"));
        const rotated = await finish(newFlow, "single-use-code", old.sessionId);
        expect(await oldFlow.service.authenticate(old.cookie)).to.equal(null);
        expect(await newFlow.service.authenticate(rotated.cookie)).not.to.equal(
            null
        );
        const cleared = await newFlow.service.logout(rotated.cookie);
        expect(cleared).to.include("Max-Age=0");
        expect(await newFlow.service.authenticate(rotated.cookie)).to.equal(
            null
        );

        flow.codeUsed = false;
        const expiringFlow = await begin(
            sessions(
                "key-2",
                [
                    { id: "key-2", key: keyTwo },
                    { id: "key-1", key: keyOne },
                ],
                1_000,
                2_000
            )
        );
        const expiring = await finish(expiringFlow);
        await new Promise((resolve) => setTimeout(resolve, 1_100));
        expect(
            await expiringFlow.service.authenticate(expiring.cookie)
        ).to.equal(null);

        flow.codeUsed = false;
        const keyOneFlow = await begin(sessions("key-1"));
        const keyOneSession = await finish(keyOneFlow);
        const unknownKeyService = sessions("key-2", [
            { id: "key-2", key: keyTwo },
        ]);
        expect(() =>
            sessions("missing", [{ id: "key-2", key: keyTwo }])
        ).to.throw("primary encryption key is missing");
        expect(
            await unknownKeyService.authenticate(keyOneSession.cookie)
        ).to.equal(null);
        expect(
            (
                await database("v2_sessions")
                    .where({ id: keyOneSession.sessionId })
                    .first("revocation_reason")
            ).revocation_reason
        ).to.equal("TOKEN_KEY_REVOKED");
    });

    it("AUTH-03 keeps replacement atomic and bounds cleanup batches", async () => {
        const candidate = await begin();
        const active = await finish(candidate);
        const row = await database("v2_sessions")
            .where({ id: active.sessionId })
            .first();
        await expectRejected(
            database.raw(
                "select public.v2_create_or_replace_session(?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?, ?, ?)",
                [
                    active.sessionId,
                    randomUUID(),
                    "",
                    row.issuer,
                    JSON.stringify(row.claims),
                    row.csrf_token_digest,
                    row.token_key_id,
                    row.token_nonce,
                    row.encrypted_token_material,
                    10_000,
                    60_000,
                ]
            )
        );
        expect(
            await candidate.service.authenticate(active.cookie)
        ).not.to.equal(null);

        for (let index = 0; index < 3; index++)
            await database("v2_login_transactions").insert({
                id: randomUUID(),
                state_digest: digestForTest(`cleanup-state-${index}`),
                nonce_digest: digestForTest(`cleanup-nonce-${index}`),
                verifier_key_id: "key-2",
                verifier_nonce: randomBytes(12),
                encrypted_code_verifier: randomBytes(32),
                expected_issuer: issuer,
                client_id: clientId,
                redirect_uri: redirectUri,
                created_at: database.raw(
                    "clock_timestamp() - interval '2 hours'"
                ),
                expires_at: database.raw(
                    "clock_timestamp() - interval '1 hour'"
                ),
            });
        const cleaned = await database.raw(
            "select * from public.v2_cleanup_auth_state(0, 2)"
        );
        expect(Number(cleaned.rows[0].login_transactions_deleted)).to.equal(2);
        expect(
            Number(
                (
                    await database("v2_login_transactions")
                        .whereNull("consumed_at")
                        .where("expires_at", "<", database.fn.now())
                        .count("* as count")
                        .first()
                )?.count
            )
        ).to.be.greaterThan(0);
        await database.raw("set enable_seqscan = off");
        const plan = await database.raw(`
            explain (format text)
            select id from public.v2_login_transactions
             where consumed_at is null and expires_at > clock_timestamp()
             order by expires_at, id limit 1
        `);
        expect(JSON.stringify(plan.rows)).to.match(
            /v2_login_transactions_(?:live|expiry)_idx/
        );
        const admissionPlan = await database.raw(`
            explain (format text)
            select count(*) from public.v2_login_transactions
             where created_at > clock_timestamp() - interval '1 hour'
        `);
        expect(JSON.stringify(admissionPlan.rows)).to.include(
            "v2_login_transactions_admission_idx"
        );
        await database.raw("reset enable_seqscan");

        await database.raw(
            `
            insert into public.v2_login_transactions (
                id, state_digest, nonce_digest, verifier_key_id,
                verifier_nonce, encrypted_code_verifier, expected_issuer,
                client_id, redirect_uri, created_at, expires_at, consumed_at
            )
            select gen_random_uuid(), md5(i::text) || md5('state-' || i::text),
                md5('nonce-' || i::text) || md5(i::text), 'key-2',
                decode(repeat('ab', 12), 'hex'),
                decode(repeat('cd', 32), 'hex'), ?, 'admission-test', ?,
                clock_timestamp(), clock_timestamp() + interval '5 minutes',
                clock_timestamp()
              from generate_series(1, 10000) i
        `,
            [issuer, redirectUri]
        );
        const admissionService = sessions();
        await expectRejected(admissionService.beginLogin());
        await admissionService.destroy();
        await database("v2_login_transactions")
            .where({ client_id: "admission-test" })
            .delete();
    });

    it("AUTH-01 bounds pre-database login admission by source, process, and concurrency", async () => {
        const service = new V2OidcSessions(database, {
            clientId,
            configurationUrl,
            expectedIssuer: issuer,
            redirectUri,
            portalOrigin,
            primaryKeyId: "key-2",
            encryptionKeys: [{ id: "key-2", key: keyTwo }],
            resolveAddresses: async () => ["93.184.216.34"],
            fetch: mockFetch,
            loginAdmissionWindowMs: 60_000,
            loginAdmissionPerSource: 2,
            loginAdmissionGlobal: 4,
            loginAdmissionConcurrency: 1,
            loginAdmissionMaxSources: 4,
        });
        const before = Number(
            (
                await database("v2_login_transactions")
                    .count("* as count")
                    .first()
            )?.count
        );
        const first = service.beginLogin("peer-concurrent-a");
        await expectRejected(service.beginLogin("peer-concurrent-b"));
        await first;
        await service.beginLogin("peer-limited");
        await service.beginLogin("peer-limited");
        const beforeRejectedFlood = Number(
            (
                await database("v2_login_transactions")
                    .count("* as count")
                    .first()
            )?.count
        );
        for (let index = 0; index < 20; index++)
            await expectRejected(service.beginLogin("peer-limited"));
        expect(
            Number(
                (
                    await database("v2_login_transactions")
                        .count("* as count")
                        .first()
                )?.count
            )
        ).to.equal(beforeRejectedFlood);
        await service.beginLogin("peer-final-global-slot");
        await expectRejected(service.beginLogin("peer-global-rejected"));
        const after = Number(
            (
                await database("v2_login_transactions")
                    .count("* as count")
                    .first()
            )?.count
        );
        expect(after - before).to.equal(4);
        expect(flow.discoveryRequests).to.equal(1);
        await service.destroy();
    });

    it("AUTH-04 requires exact Origin, synchronizer CSRF, and approved media type", async () => {
        const candidate = await begin();
        const result = await finish(candidate);
        const session = await candidate.service.authenticate(result.cookie);
        expect(session).not.to.equal(null);
        expect(
            await candidate.service.acceptMutation(
                session!,
                portalOrigin,
                session!.csrfToken,
                "application/json; charset=utf-8",
                "application/json"
            )
        ).not.to.equal(null);
        for (const values of [
            ["https://evil.example", session!.csrfToken, "application/json"],
            [portalOrigin, "forged", "application/json"],
            [portalOrigin, session!.csrfToken, "text/plain"],
        ])
            await expectRejected(
                candidate.service.acceptMutation(
                    session!,
                    values[0],
                    values[1],
                    values[2],
                    "application/json"
                )
            );
    });

    it("AUTH-05 retained rows and browser artifacts contain no raw OIDC tokens", async () => {
        const candidate = await begin();
        const result = await finish(candidate);
        const rows = await database.raw(
            "select row_to_json(s)::text as value from v2_sessions s"
        );
        const retained = rows.rows
            .map((row: { value: string }) => row.value)
            .join("\n");
        expect(retained).not.to.include(accessCanary);
        expect(retained).not.to.include(refreshCanary);
        expect(JSON.stringify(result)).not.to.include(accessCanary);
        expect(JSON.stringify(result)).not.to.include(refreshCanary);
    });
});
