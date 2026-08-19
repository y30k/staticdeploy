import { Knex } from "knex";
import {
    createCipheriv,
    createDecipheriv,
    createHash,
    createPublicKey,
    randomBytes,
    randomUUID,
    timingSafeEqual,
    verify,
} from "node:crypto";
import type { JsonWebKey as NodeJsonWebKey } from "node:crypto";
import { lookup } from "node:dns/promises";
import { request as requestHttp } from "node:http";
import { request as requestHttps } from "node:https";
import { isIP } from "node:net";

import { createPostgresKnex } from "./postgres";

export const V2_SESSION_COOKIE = "__Host-staticdeploy-session";
export const V2_LOGIN_COOKIE = "__Host-staticdeploy-oidc-tx";
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const UUID =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HTTP_TIMEOUT_MS = 5_000;
const HTTP_MAX_BYTES = 1024 * 1024;
const JWT_MAX_BYTES = 64 * 1024;
const JWKS_MAX_KEYS = 32;
const ENVELOPE_VERSION = "v1";

export interface V2SessionEncryptionKey {
    id: string;
    key: Buffer;
}

export interface V2OidcSessionOptions {
    clientId: string;
    configurationUrl: string;
    expectedIssuer: string;
    redirectUri: string;
    portalOrigin: string;
    primaryKeyId: string;
    encryptionKeys: V2SessionEncryptionKey[];
    loginLifetimeMs?: number;
    idleLifetimeMs?: number;
    absoluteLifetimeMs?: number;
    cleanupIntervalMs?: number;
    cleanupRetentionMs?: number;
    cleanupBatchSize?: number;
    allowHttpLoopbackForTests?: boolean;
    resolveAddresses?: (hostname: string) => Promise<string[]>;
    onCleanupFailure?: () => void;
    loginAdmissionWindowMs?: number;
    loginAdmissionPerSource?: number;
    loginAdmissionGlobal?: number;
    loginAdmissionConcurrency?: number;
    loginAdmissionMaxSources?: number;
    /** Test seam may shorten, but never extend, the fixed production deadline. */
    httpTimeoutMs?: number;
    /** Test-only HTTP mock. Production requests use the pinned HTTPS client. */
    fetch?: typeof fetch;
}

export interface V2LoginStart {
    authorizationUrl: string;
    state: string;
    loginCookie: string;
}

export interface V2LoginResult {
    cookie: string;
    clearLoginCookie: string;
    sessionId: string;
}

export interface V2AuthenticatedSession {
    id: string;
    subjectId: string;
    issuer: string;
    claims: Record<string, unknown>;
    claimsVersion: number;
    csrfToken: string;
    csrfTokenDigest: string;
}

interface Discovery {
    issuer: string;
    authorization_endpoint: string;
    token_endpoint: string;
    jwks_uri: string;
    code_challenge_methods_supported: string[];
    id_token_signing_alg_values_supported: string[];
    response_types_supported: string[];
    token_endpoint_auth_methods_supported: string[];
}

interface LoginRow {
    id: string;
    verifier_key_id: string;
    verifier_nonce: Buffer;
    encrypted_code_verifier: Buffer;
    nonce_digest: string;
    expected_issuer: string;
    client_id: string;
    redirect_uri: string;
}

interface SessionRow {
    id: string;
    subject_id: string;
    issuer: string;
    claims: Record<string, unknown>;
    claims_version: string | number;
    csrf_token_digest: string;
    token_key_id: string;
    token_nonce: Buffer;
    encrypted_token_material: Buffer;
}

interface JwtPayload {
    iss?: unknown;
    aud?: unknown;
    azp?: unknown;
    sub?: unknown;
    exp?: unknown;
    iat?: unknown;
    nbf?: unknown;
    nonce?: unknown;
    groups?: unknown;
}

const digest = (value: string): string =>
    createHash("sha256").update(value, "utf8").digest("hex");
const randomOpaque = (): string => randomBytes(32).toString("base64url");
const record = (value: unknown): value is Record<string, unknown> =>
    value !== null && typeof value === "object" && !Array.isArray(value);
const hasControlCharacter = (value: string): boolean =>
    [...value].some((character) => {
        const code = character.codePointAt(0)!;
        return code <= 31 || code === 127;
    });

const globalIpv4 = (address: string): boolean => {
    const octets = address.split(".").map(Number);
    if (octets.length !== 4 || octets.some((value) => value < 0 || value > 255))
        return false;
    const [a, b, c] = octets;
    return !(
        a === 0 ||
        a === 10 ||
        a === 127 ||
        (a === 100 && b >= 64 && b <= 127) ||
        (a === 169 && b === 254) ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 0 && c === 0) ||
        (a === 192 && b === 0 && c === 2) ||
        (a === 192 && b === 88 && c === 99) ||
        (a === 192 && b === 168) ||
        (a === 198 && (b === 18 || b === 19)) ||
        (a === 198 && b === 51 && c === 100) ||
        (a === 203 && b === 0 && c === 113) ||
        a >= 224
    );
};

const ipv6Groups = (address: string): number[] | null => {
    if (address.includes("%")) return null;
    const halves = address.toLowerCase().split("::");
    if (halves.length > 2) return null;
    const parse = (part: string): number[] | null => {
        if (part === "") return [];
        const groups: number[] = [];
        for (const value of part.split(":")) {
            if (value.includes(".")) {
                if (isIP(value) !== 4) return null;
                const octets = value.split(".").map(Number);
                groups.push((octets[0] << 8) | octets[1]);
                groups.push((octets[2] << 8) | octets[3]);
            } else {
                if (!/^[0-9a-f]{1,4}$/.test(value)) return null;
                groups.push(Number.parseInt(value, 16));
            }
        }
        return groups;
    };
    const left = parse(halves[0]);
    const right = parse(halves[1] ?? "");
    if (left === null || right === null) return null;
    const missing = 8 - left.length - right.length;
    if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
    return [...left, ...Array(missing).fill(0), ...right];
};

export const isGlobalOidcAddress = (address: string): boolean => {
    if (isIP(address) === 4) return globalIpv4(address);
    if (isIP(address) !== 6) return false;
    const groups = ipv6Groups(address);
    if (groups === null) return false;
    // Permit only globally routable IPv6 unicast (2000::/3), then remove all
    // IANA special-purpose blocks. IPv4-compatible/mapped forms are outside
    // 2000::/3 and are deliberately rejected rather than reinterpreted.
    if (groups[0] < 0x2000 || groups[0] > 0x3fff) return false;
    return !(
        (groups[0] === 0x2001 && groups[1] <= 0x01ff) || // IETF protocol space
        (groups[0] === 0x2001 && groups[1] === 0x0db8) || // documentation
        groups[0] === 0x2002 || // deprecated 6to4
        (groups[0] === 0x3fff && (groups[1] & 0xf000) === 0) // documentation
    );
};

interface AdmissionWindow {
    startedAt: number;
    count: number;
}

const processLoginAdmission: {
    global: AdmissionWindow;
    sources: Map<string, AdmissionWindow>;
    active: number;
} = {
    global: { startedAt: 0, count: 0 },
    sources: new Map(),
    active: 0,
};

/** Parse JSON while rejecting duplicate members at every object depth. */
const parseStrictJson = (text: string): unknown => {
    let offset = 0;
    const whitespace = () => {
        while (/\s/.test(text[offset] ?? "")) offset++;
    };
    const string = (): string => {
        const start = offset;
        if (text[offset++] !== '"') throw new Error("invalid JSON");
        let escaped = false;
        while (offset < text.length) {
            const character = text[offset++];
            if (!escaped && character === '"')
                return JSON.parse(text.slice(start, offset)) as string;
            if (!escaped && character === "\\") escaped = true;
            else escaped = false;
        }
        throw new Error("invalid JSON");
    };
    const value = (): void => {
        whitespace();
        if (text[offset] === "{") {
            offset++;
            whitespace();
            const keys = new Set<string>();
            if (text[offset] === "}") {
                offset++;
                return;
            }
            for (;;) {
                whitespace();
                const key = string();
                if (keys.has(key)) throw new Error("duplicate JSON member");
                keys.add(key);
                whitespace();
                if (text[offset++] !== ":") throw new Error("invalid JSON");
                value();
                whitespace();
                const separator = text[offset++];
                if (separator === "}") return;
                if (separator !== ",") throw new Error("invalid JSON");
            }
        }
        if (text[offset] === "[") {
            offset++;
            whitespace();
            if (text[offset] === "]") {
                offset++;
                return;
            }
            for (;;) {
                value();
                whitespace();
                const separator = text[offset++];
                if (separator === "]") return;
                if (separator !== ",") throw new Error("invalid JSON");
            }
        }
        if (text[offset] === '"') {
            string();
            return;
        }
        const start = offset;
        while (offset < text.length && !/[\s,\]}]/.test(text[offset])) offset++;
        if (start === offset) throw new Error("invalid JSON");
        JSON.parse(text.slice(start, offset));
    };
    value();
    whitespace();
    if (offset !== text.length) throw new Error("invalid JSON");
    return JSON.parse(text) as unknown;
};

export class V2OidcSessions {
    private readonly keys = new Map<string, Buffer>();
    private readonly primaryKey: Buffer;
    private readonly request?: typeof fetch;
    private readonly resolveAddresses: (hostname: string) => Promise<string[]>;
    private readonly loginLifetimeMs: number;
    private readonly admissionWindowMs: number;
    private readonly admissionPerSource: number;
    private readonly admissionGlobal: number;
    private readonly admissionConcurrency: number;
    private readonly admissionMaxSources: number;
    private readonly idleLifetimeMs: number;
    private readonly absoluteLifetimeMs: number;
    private readonly cleanupRetentionMs: number;
    private readonly cleanupBatchSize: number;
    private readonly httpTimeoutMs: number;
    private readonly cleanupTimer?: NodeJS.Timeout;
    private jwksCache?: {
        url: string;
        keys: unknown[];
        expiresAt: number;
        generation: number;
    };
    private jwksRefresh?: Promise<unknown[]>;
    private discoveryCache?: { value: Discovery; expiresAt: number };
    private discoveryRefresh?: Promise<Discovery>;

    constructor(
        private readonly database: Knex,
        private readonly options: V2OidcSessionOptions,
        private readonly destroyDatabase?: () => Promise<void>
    ) {
        const issuer = this.trustedUrl(
            options.expectedIssuer,
            "expected issuer"
        );
        const configuration = this.trustedUrl(
            options.configurationUrl,
            "configuration URL"
        );
        const redirect = this.trustedUrl(options.redirectUri, "redirect URI");
        const portal = new URL(options.portalOrigin);
        if (
            portal.origin !== options.portalOrigin ||
            portal.protocol !== "https:" ||
            configuration.origin !== issuer.origin ||
            redirect.origin !== portal.origin
        )
            throw new Error("OIDC origins are not exactly trusted");
        if (
            options.encryptionKeys.length < 1 ||
            options.encryptionKeys.length > 8
        )
            throw new Error("one to eight encryption keys are required");
        for (const candidate of options.encryptionKeys) {
            if (!/^[A-Za-z0-9._-]{1,200}$/.test(candidate.id))
                throw new Error("invalid encryption key id");
            if (candidate.key.length !== 32 || this.keys.has(candidate.id))
                throw new Error("encryption keys must be unique 32-byte keys");
            this.keys.set(candidate.id, Buffer.from(candidate.key));
        }
        const primary = this.keys.get(options.primaryKeyId);
        if (primary === undefined)
            throw new Error("primary encryption key is missing");
        this.primaryKey = primary;
        this.request = options.fetch;
        this.resolveAddresses =
            options.resolveAddresses ??
            (async (hostname) =>
                (await lookup(hostname, { all: true, verbatim: true })).map(
                    (answer) => answer.address
                ));
        this.loginLifetimeMs = options.loginLifetimeMs ?? 5 * 60_000;
        this.admissionWindowMs = options.loginAdmissionWindowMs ?? 60_000;
        this.admissionPerSource = options.loginAdmissionPerSource ?? 20;
        this.admissionGlobal = options.loginAdmissionGlobal ?? 1_000;
        this.admissionConcurrency = options.loginAdmissionConcurrency ?? 32;
        this.admissionMaxSources = options.loginAdmissionMaxSources ?? 10_000;
        this.idleLifetimeMs = options.idleLifetimeMs ?? 30 * 60_000;
        this.absoluteLifetimeMs = options.absoluteLifetimeMs ?? 8 * 60 * 60_000;
        this.cleanupRetentionMs = options.cleanupRetentionMs ?? 86_400_000;
        this.cleanupBatchSize = options.cleanupBatchSize ?? 1_000;
        this.httpTimeoutMs = options.httpTimeoutMs ?? HTTP_TIMEOUT_MS;
        if (
            this.loginLifetimeMs < 1_000 ||
            this.loginLifetimeMs > 300_000 ||
            this.admissionWindowMs < 1_000 ||
            this.admissionWindowMs > 3_600_000 ||
            this.admissionPerSource < 1 ||
            this.admissionPerSource > 10_000 ||
            this.admissionGlobal < this.admissionPerSource ||
            this.admissionGlobal > 100_000 ||
            this.admissionConcurrency < 1 ||
            this.admissionConcurrency > 1_000 ||
            this.admissionMaxSources < 1 ||
            this.admissionMaxSources > 100_000 ||
            this.idleLifetimeMs < 1_000 ||
            this.idleLifetimeMs > 86_400_000 ||
            this.absoluteLifetimeMs < this.idleLifetimeMs ||
            this.absoluteLifetimeMs > 604_800_000 ||
            this.cleanupRetentionMs < 0 ||
            this.cleanupRetentionMs > 2_592_000_000 ||
            this.cleanupBatchSize < 1 ||
            this.cleanupBatchSize > 1_000 ||
            this.httpTimeoutMs < 10 ||
            this.httpTimeoutMs > HTTP_TIMEOUT_MS
        )
            throw new Error("invalid session lifetimes or cleanup bounds");
        const cleanupIntervalMs = options.cleanupIntervalMs ?? 60_000;
        if (cleanupIntervalMs < 1_000 || cleanupIntervalMs > 86_400_000)
            throw new Error("invalid cleanup interval");
        this.cleanupTimer = setInterval(() => {
            void this.cleanup().catch(() => {
                // Surface only a bounded category; never expose raw DB errors.
                this.options.onCleanupFailure?.();
            });
        }, cleanupIntervalMs);
        this.cleanupTimer.unref();
    }

    get portalRedirectUrl(): string {
        return `${this.options.portalOrigin}/`;
    }

    get clearLoginCookie(): string {
        return `${V2_LOGIN_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
    }

    get clearSessionCookie(): string {
        return `${V2_SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
    }

    async verifyReady(): Promise<void> {
        const result = await this.database.raw(`
            select current_user as identity,
                r.rolsuper, r.rolbypassrls, r.rolcreaterole,
                r.rolcreatedb, r.rolreplication,
                EXISTS (
                    SELECT 1 FROM pg_namespace n
                     WHERE n.nspname <> 'information_schema'
                       AND n.nspname !~ '^pg_(catalog|toast|temp_|toasted_temp_)'
                       AND (
                           n.nspowner = r.oid OR
                           has_schema_privilege(current_user, n.oid, 'CREATE')
                       )
                ) as unsafe_schema,
                has_database_privilege(current_user, current_database(), 'CREATE') as database_create,
                EXISTS (
                    SELECT 1 FROM pg_auth_members m WHERE m.member = r.oid
                ) as has_memberships,
                EXISTS (
                    SELECT 1 FROM pg_class c
                     JOIN pg_namespace n ON n.oid = c.relnamespace
                     WHERE n.nspname <> 'information_schema'
                       AND n.nspname !~ '^pg_(catalog|toast|temp_|toasted_temp_)'
                       AND c.relowner = r.oid
                ) OR EXISTS (
                    SELECT 1 FROM pg_proc p
                     JOIN pg_namespace n ON n.oid = p.pronamespace
                     WHERE n.nspname <> 'information_schema'
                       AND n.nspname !~ '^pg_(catalog|toast|temp_|toasted_temp_)'
                       AND p.proowner = r.oid
                ) OR EXISTS (
                    SELECT 1 FROM pg_database d
                     WHERE d.datname = current_database() AND d.datdba = r.oid
                ) as owns_runtime_objects,
                EXISTS (
                    SELECT 1 FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname <> 'information_schema'
                      AND n.nspname !~ '^pg_(catalog|toast|temp_|toasted_temp_)'
                      AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
                      AND (
                          has_table_privilege(
                              current_user, c.oid,
                              'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
                          ) OR
                          has_any_column_privilege(
                              current_user, c.oid,
                              'SELECT,INSERT,UPDATE,REFERENCES'
                          )
                      )
                ) as direct_table_privilege,
                EXISTS (
                    SELECT 1 FROM pg_proc p
                    JOIN pg_namespace n ON n.oid = p.pronamespace
                    WHERE n.nspname <> 'information_schema'
                      AND n.nspname !~ '^pg_(catalog|toast|temp_|toasted_temp_)'
                      AND p.prosecdef
                      AND p.prorettype NOT IN (
                        'trigger'::regtype, 'event_trigger'::regtype
                      )
                      AND has_function_privilege(current_user, p.oid, 'EXECUTE')
                      AND p.oid <> ALL (ARRAY[
                        to_regprocedure('public.v2_begin_oidc_login(uuid,text,text,text,bytea,bytea,text,text,text,integer)'),
                        to_regprocedure('public.v2_consume_oidc_login(uuid,text)'),
                        to_regprocedure('public.v2_create_or_replace_session(uuid,uuid,text,text,jsonb,text,text,bytea,bytea,integer,integer)'),
                        to_regprocedure('public.v2_read_session(uuid)'),
                        to_regprocedure('public.v2_use_session(uuid,integer)'),
                        to_regprocedure('public.v2_rotate_session_envelope(uuid,text,text,bytea,bytea)'),
                        to_regprocedure('public.v2_revoke_session(uuid,text)'),
                        to_regprocedure('public.v2_cleanup_auth_state(bigint,integer)'),
                        to_regprocedure('public.v2_initialize_authorization_policy(text[],bigint,text)'),
                        to_regprocedure('public.v2_authorization_policy_identity()'),
                        to_regprocedure('public.v2_authorize_operation(uuid,uuid,text[],bigint,uuid,text)'),
                        to_regprocedure('public.v2_replace_bindings(uuid,uuid,text[],bigint,uuid,bigint,text,text,jsonb)')
                      ]::oid[])
                ) as unrelated_definer_execute,
                has_function_privilege(current_user, 'public.v2_begin_oidc_login(uuid,text,text,text,bytea,bytea,text,text,text,integer)', 'EXECUTE') as begin_ok,
                has_function_privilege(current_user, 'public.v2_consume_oidc_login(uuid,text)', 'EXECUTE') as consume_ok,
                has_function_privilege(current_user, 'public.v2_create_or_replace_session(uuid,uuid,text,text,jsonb,text,text,bytea,bytea,integer,integer)', 'EXECUTE') as create_ok,
                has_function_privilege(current_user, 'public.v2_read_session(uuid)', 'EXECUTE') as read_ok,
                has_function_privilege(current_user, 'public.v2_use_session(uuid,integer)', 'EXECUTE') as use_ok,
                has_function_privilege(current_user, 'public.v2_rotate_session_envelope(uuid,text,text,bytea,bytea)', 'EXECUTE') as rotate_ok,
                has_function_privilege(current_user, 'public.v2_revoke_session(uuid,text)', 'EXECUTE') as revoke_ok,
                has_function_privilege(current_user, 'public.v2_cleanup_auth_state(bigint,integer)', 'EXECUTE') as cleanup_ok
              from pg_roles r where r.rolname = current_user
        `);
        const row = result.rows[0];
        if (
            row === undefined ||
            row.rolsuper ||
            row.rolbypassrls ||
            row.rolcreaterole ||
            row.rolcreatedb ||
            row.rolreplication ||
            row.unsafe_schema ||
            row.database_create ||
            row.has_memberships ||
            row.owns_runtime_objects ||
            row.direct_table_privilege ||
            row.unrelated_definer_execute ||
            !row.begin_ok ||
            !row.consume_ok ||
            !row.create_ok ||
            !row.read_ok ||
            !row.use_ok ||
            !row.rotate_ok ||
            !row.revoke_ok ||
            !row.cleanup_ok
        )
            throw new Error(
                "OIDC PostgreSQL runtime identity is not least privilege"
            );
    }

    async destroy(): Promise<void> {
        if (this.cleanupTimer !== undefined) clearInterval(this.cleanupTimer);
        await this.destroyDatabase?.();
    }

    async cleanup(): Promise<{ logins: number; sessions: number }> {
        const result = await this.database.raw(
            "select * from public.v2_cleanup_auth_state(?, ?)",
            [this.cleanupRetentionMs, this.cleanupBatchSize]
        );
        const row = result.rows[0] ?? {};
        return {
            logins: Number(row.login_transactions_deleted ?? 0),
            sessions: Number(row.sessions_deleted ?? 0),
        };
    }

    async beginLogin(source?: string): Promise<V2LoginStart> {
        const releaseAdmission = this.admitLogin(source);
        try {
            const loginId = randomUUID();
            const state = randomOpaque();
            const nonce = randomOpaque();
            const verifier = randomOpaque();
            const challenge = createHash("sha256")
                .update(verifier, "ascii")
                .digest("base64url");
            const envelope = this.encrypt(
                this.loginAad(
                    loginId,
                    this.options.expectedIssuer,
                    this.options.clientId
                ),
                verifier
            );
            await this.database.raw(
                "select public.v2_begin_oidc_login(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    loginId,
                    digest(state),
                    digest(nonce),
                    this.options.primaryKeyId,
                    envelope.nonce,
                    envelope.ciphertext,
                    this.options.expectedIssuer,
                    this.options.clientId,
                    this.options.redirectUri,
                    this.loginLifetimeMs,
                ]
            );
            // Cross-instance DB admission is sealed before provider work.
            const discovery = await this.discovery();
            const url = new URL(discovery.authorization_endpoint);
            url.search = new URLSearchParams({
                client_id: this.options.clientId,
                response_type: "code",
                scope: "openid",
                redirect_uri: this.options.redirectUri,
                code_challenge: challenge,
                code_challenge_method: "S256",
                state,
                nonce,
            }).toString();
            return {
                authorizationUrl: url.toString(),
                state,
                loginCookie: `${V2_LOGIN_COOKIE}=${loginId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${Math.ceil(
                    this.loginLifetimeMs / 1000
                )}`,
            };
        } finally {
            releaseAdmission();
        }
    }

    async consumeFailedLogin(
        state: string,
        loginCookieHeader: string | undefined
    ): Promise<void> {
        await this.consumeLogin(state, loginCookieHeader);
    }

    async finishLogin(
        state: string,
        code: string,
        loginCookieHeader: string | undefined,
        existingSessionId?: string
    ): Promise<V2LoginResult> {
        if (code.length < 1 || code.length > 4096)
            throw new Error("invalid login callback");
        const login = await this.consumeLogin(state, loginCookieHeader);
        if (
            login.expected_issuer !== this.options.expectedIssuer ||
            login.client_id !== this.options.clientId ||
            login.redirect_uri !== this.options.redirectUri
        )
            throw new Error("login transaction configuration changed");
        const verifier = this.decrypt(
            this.loginAad(login.id, login.expected_issuer, login.client_id),
            login.verifier_key_id,
            login.verifier_nonce,
            login.encrypted_code_verifier
        );
        const discovery = await this.discovery();
        const response = await this.fetchBounded(discovery.token_endpoint, {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
                grant_type: "authorization_code",
                client_id: this.options.clientId,
                code,
                code_verifier: verifier,
                redirect_uri: login.redirect_uri,
            }),
        });
        if (!response.ok) throw new Error("OIDC token exchange failed");
        const tokens = await this.responseJson(response);
        if (!record(tokens) || typeof tokens.id_token !== "string")
            throw new Error("invalid OIDC token response");
        const payload = await this.verifyIdToken(
            tokens.id_token,
            login.nonce_digest,
            discovery
        );
        const csrfToken = randomOpaque();
        const sessionId = randomUUID();
        const envelope = this.encrypt(
            this.sessionAad(
                sessionId,
                this.options.expectedIssuer,
                payload.sub
            ),
            csrfToken
        );
        const claims: Record<string, unknown> = { sub: payload.sub };
        if (
            Array.isArray(payload.groups) &&
            payload.groups.length <= 256 &&
            payload.groups.every(
                (group) =>
                    typeof group === "string" &&
                    group.length >= 1 &&
                    group.length <= 512 &&
                    group.trim() === group &&
                    !hasControlCharacter(group)
            )
        )
            claims.groups = [...new Set(payload.groups)].sort();
        await this.database.raw(
            "select public.v2_create_or_replace_session(?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?, ?, ?)",
            [
                existingSessionId ?? null,
                sessionId,
                payload.sub,
                this.options.expectedIssuer,
                JSON.stringify(claims),
                digest(csrfToken),
                this.options.primaryKeyId,
                envelope.nonce,
                envelope.ciphertext,
                this.idleLifetimeMs,
                this.absoluteLifetimeMs,
            ]
        );
        return {
            sessionId,
            cookie: `${V2_SESSION_COOKIE}=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax`,
            clearLoginCookie: this.clearLoginCookie,
        };
    }

    async inspect(
        cookieHeader: string | undefined
    ): Promise<V2AuthenticatedSession | null> {
        const sessionId = this.sessionId(cookieHeader);
        if (sessionId === undefined) return null;
        const result = await this.database.raw(
            "select * from public.v2_read_session(?)",
            [sessionId]
        );
        return this.decryptSession(
            result.rows[0] as SessionRow | undefined,
            false
        );
    }

    async authenticate(
        cookieHeader: string | undefined
    ): Promise<V2AuthenticatedSession | null> {
        const sessionId = this.sessionId(cookieHeader);
        return sessionId === undefined ? null : this.touch(sessionId);
    }

    validateMutation(
        inspected: V2AuthenticatedSession,
        origin: string | undefined,
        csrfToken: string | undefined,
        contentType: string | undefined,
        expectedContentType: "application/json" | "application/octet-stream"
    ): void {
        this.assertRequestShape(origin, contentType, expectedContentType);
        this.assertCsrf(inspected, csrfToken);
    }

    async acceptInspected(
        inspected: V2AuthenticatedSession
    ): Promise<V2AuthenticatedSession | null> {
        return this.touch(inspected.id);
    }

    async acceptMutation(
        inspected: V2AuthenticatedSession,
        origin: string | undefined,
        csrfToken: string | undefined,
        contentType: string | undefined,
        expectedContentType: "application/json" | "application/octet-stream"
    ): Promise<V2AuthenticatedSession | null> {
        this.validateMutation(
            inspected,
            origin,
            csrfToken,
            contentType,
            expectedContentType
        );
        return this.acceptInspected(inspected);
    }

    assertRequestShape(
        origin: string | undefined,
        contentType: string | undefined,
        expectedContentType: "application/json" | "application/octet-stream"
    ): void {
        if (origin !== this.options.portalOrigin)
            throw new Error("request origin rejected");
        if (contentType === undefined || contentType.includes(","))
            throw new Error("request content type rejected");
        const parts = contentType.split(";").map((part) => part.trim());
        if (parts[0].toLowerCase() !== expectedContentType)
            throw new Error("request content type rejected");
        if (
            expectedContentType === "application/octet-stream" &&
            parts.length !== 1
        )
            throw new Error("request content type rejected");
        if (
            expectedContentType === "application/json" &&
            (parts.length > 2 ||
                (parts.length === 2 &&
                    parts[1].toLowerCase() !== "charset=utf-8"))
        )
            throw new Error("request content type rejected");
    }

    async logout(cookieHeader: string | undefined): Promise<string> {
        const sessionId = this.sessionId(cookieHeader);
        if (sessionId !== undefined)
            await this.database.raw(
                "select public.v2_revoke_session(?, 'USER_LOGOUT')",
                [sessionId]
            );
        return this.clearSessionCookie;
    }

    private async consumeLogin(
        state: string,
        loginCookieHeader: string | undefined
    ): Promise<LoginRow> {
        if (!BASE64URL.test(state) || state.length < 43 || state.length > 128)
            throw new Error("invalid login callback");
        const loginId = this.cookieValue(
            loginCookieHeader,
            V2_LOGIN_COOKIE,
            (value) => UUID.test(value)
        );
        if (loginId === undefined) throw new Error("invalid login callback");
        const consumed = await this.database.raw(
            "select * from public.v2_consume_oidc_login(?, ?)",
            [loginId, digest(state)]
        );
        const login = consumed.rows[0] as LoginRow | undefined;
        if (login === undefined) throw new Error("invalid login callback");
        return login;
    }

    private async touch(
        sessionId: string
    ): Promise<V2AuthenticatedSession | null> {
        const result = await this.database.raw(
            "select * from public.v2_use_session(?, ?)",
            [sessionId, this.idleLifetimeMs]
        );
        return this.decryptSession(
            result.rows[0] as SessionRow | undefined,
            true
        );
    }

    private async decryptSession(
        row: SessionRow | undefined,
        mutate: boolean
    ): Promise<V2AuthenticatedSession | null> {
        if (row === undefined) return null;
        let csrfToken: string;
        try {
            csrfToken = this.decrypt(
                this.sessionAad(row.id, row.issuer, row.subject_id),
                row.token_key_id,
                row.token_nonce,
                row.encrypted_token_material
            );
            if (digest(csrfToken) !== row.csrf_token_digest)
                throw new Error("invalid session envelope");
        } catch {
            if (mutate)
                await this.database.raw(
                    "select public.v2_revoke_session(?, 'TOKEN_KEY_REVOKED')",
                    [row.id]
                );
            return null;
        }
        if (mutate && row.token_key_id !== this.options.primaryKeyId) {
            const envelope = this.encrypt(
                this.sessionAad(row.id, row.issuer, row.subject_id),
                csrfToken
            );
            await this.database.raw(
                "select public.v2_rotate_session_envelope(?, ?, ?, ?, ?)",
                [
                    row.id,
                    row.token_key_id,
                    this.options.primaryKeyId,
                    envelope.nonce,
                    envelope.ciphertext,
                ]
            );
        }
        return {
            id: row.id,
            subjectId: row.subject_id,
            issuer: row.issuer,
            claims: row.claims,
            claimsVersion: Number(row.claims_version),
            csrfToken,
            csrfTokenDigest: row.csrf_token_digest,
        };
    }

    private assertCsrf(
        session: V2AuthenticatedSession,
        csrfToken: string | undefined
    ): void {
        if (csrfToken === undefined || !BASE64URL.test(csrfToken))
            throw new Error("CSRF token rejected");
        const actual = Buffer.from(digest(csrfToken), "hex");
        const expected = Buffer.from(session.csrfTokenDigest, "hex");
        if (
            actual.length !== expected.length ||
            !timingSafeEqual(actual, expected)
        )
            throw new Error("CSRF token rejected");
    }

    private sessionId(cookieHeader: string | undefined): string | undefined {
        return this.cookieValue(cookieHeader, V2_SESSION_COOKIE, (value) =>
            UUID.test(value)
        );
    }

    private cookieValue(
        cookieHeader: string | undefined,
        name: string,
        validate: (value: string) => boolean
    ): string | undefined {
        const values = (cookieHeader ?? "")
            .split(";")
            .map((part) => part.trim());
        const matches = values.filter((part) => part.startsWith(`${name}=`));
        if (matches.length !== 1) return undefined;
        const value = matches[0].slice(name.length + 1);
        return validate(value) ? value : undefined;
    }

    private loginAad(id: string, issuer: string, clientId: string): string {
        return `${ENVELOPE_VERSION}:oidc-login:${id}:${issuer}:${clientId}`;
    }

    private sessionAad(id: string, issuer: string, subject: string): string {
        return `${ENVELOPE_VERSION}:oidc-session:${id}:${issuer}:${subject}`;
    }

    private encrypt(
        aad: string,
        plaintext: string
    ): { nonce: Buffer; ciphertext: Buffer } {
        const nonce = randomBytes(12);
        const cipher = createCipheriv("aes-256-gcm", this.primaryKey, nonce);
        cipher.setAAD(
            Buffer.from(`${aad}:${this.options.primaryKeyId}`, "utf8")
        );
        const ciphertext = Buffer.concat([
            cipher.update(plaintext, "utf8"),
            cipher.final(),
            cipher.getAuthTag(),
        ]);
        return { nonce, ciphertext };
    }

    private decrypt(
        aad: string,
        keyId: string,
        nonce: Buffer,
        value: Buffer
    ): string {
        const key = this.keys.get(keyId);
        if (
            key === undefined ||
            nonce.length !== 12 ||
            value.length < 16 ||
            value.length > 1_048_576
        )
            throw new Error("encryption key unavailable");
        const ciphertext = value.subarray(0, value.length - 16);
        const tag = value.subarray(value.length - 16);
        const decipher = createDecipheriv("aes-256-gcm", key, nonce);
        decipher.setAAD(Buffer.from(`${aad}:${keyId}`, "utf8"));
        decipher.setAuthTag(tag);
        return Buffer.concat([
            decipher.update(ciphertext),
            decipher.final(),
        ]).toString("utf8");
    }

    private admitLogin(source: string | undefined): () => void {
        // Direct library tests may omit a source. HTTP callers always supply
        // the peer socket address; forwarded headers are intentionally ignored.
        if (source === undefined) return () => undefined;
        if (source.length < 1 || source.length > 128)
            throw new Error("login admission rejected");
        const now = Date.now();
        const reset = (window: AdmissionWindow): void => {
            if (now - window.startedAt >= this.admissionWindowMs) {
                window.startedAt = now;
                window.count = 0;
            }
        };
        reset(processLoginAdmission.global);
        for (const [key, window] of processLoginAdmission.sources)
            if (now - window.startedAt >= this.admissionWindowMs)
                processLoginAdmission.sources.delete(key);
        let sourceWindow = processLoginAdmission.sources.get(source);
        if (sourceWindow === undefined) {
            if (processLoginAdmission.sources.size >= this.admissionMaxSources)
                throw new Error("login admission rejected");
            sourceWindow = { startedAt: now, count: 0 };
            processLoginAdmission.sources.set(source, sourceWindow);
        }
        reset(sourceWindow);
        if (
            processLoginAdmission.active >= this.admissionConcurrency ||
            processLoginAdmission.global.count >= this.admissionGlobal ||
            sourceWindow.count >= this.admissionPerSource
        )
            throw new Error("login admission rejected");
        processLoginAdmission.active++;
        processLoginAdmission.global.count++;
        sourceWindow.count++;
        let released = false;
        return () => {
            if (!released) {
                released = true;
                processLoginAdmission.active--;
            }
        };
    }

    private trustedUrl(value: unknown, name: string): URL {
        if (typeof value !== "string") throw new Error(`invalid ${name}`);
        const parsed = new URL(value);
        const loopback =
            parsed.hostname === "127.0.0.1" ||
            parsed.hostname === "[::1]" ||
            parsed.hostname === "localhost";
        const literal = parsed.hostname.replace(/^\[|\]$/g, "");
        const unsafeLiteral =
            isIP(literal) !== 0 && !isGlobalOidcAddress(literal);
        if (
            (parsed.protocol !== "https:" &&
                !(
                    this.options.allowHttpLoopbackForTests === true &&
                    parsed.protocol === "http:" &&
                    loopback
                )) ||
            parsed.username !== "" ||
            parsed.password !== "" ||
            parsed.hash !== "" ||
            (unsafeLiteral &&
                !(loopback && this.options.allowHttpLoopbackForTests === true))
        )
            throw new Error(`invalid ${name}`);
        return parsed;
    }

    private async resolvePinnedAddress(url: URL): Promise<string> {
        const hostname = url.hostname.replace(/^\[|\]$/g, "");
        const loopback =
            hostname === "127.0.0.1" ||
            hostname === "::1" ||
            hostname === "localhost";
        if (loopback && this.options.allowHttpLoopbackForTests === true)
            return hostname === "localhost" ? "127.0.0.1" : hostname;
        const literalVersion = isIP(hostname);
        const addresses =
            literalVersion === 0
                ? await Promise.race([
                      this.resolveAddresses(hostname),
                      new Promise<string[]>((_, reject) =>
                          setTimeout(
                              () => reject(new Error("OIDC DNS timeout")),
                              2_000
                          )
                      ),
                  ])
                : [hostname];
        if (
            addresses.length < 1 ||
            addresses.length > 16 ||
            addresses.some((address) => !isGlobalOidcAddress(address))
        )
            throw new Error("OIDC endpoint resolution rejected");
        // Pin one validated answer. The production transport connects directly
        // to this address and never performs a second resolver lookup.
        return [...addresses].sort()[0];
    }

    private async discovery(): Promise<Discovery> {
        if (
            this.discoveryCache !== undefined &&
            Date.now() < this.discoveryCache.expiresAt
        )
            return this.discoveryCache.value;
        if (this.discoveryRefresh !== undefined) return this.discoveryRefresh;
        this.discoveryRefresh = this.loadDiscovery();
        try {
            return await this.discoveryRefresh;
        } finally {
            this.discoveryRefresh = undefined;
        }
    }

    private async loadDiscovery(): Promise<Discovery> {
        const response = await this.fetchBounded(this.options.configurationUrl);
        if (!response.ok) throw new Error("OIDC discovery failed");
        const value = await this.responseJson(response);
        if (!record(value) || value.issuer !== this.options.expectedIssuer)
            throw new Error("OIDC issuer mismatch");
        const discovery = value as unknown as Discovery;
        const issuerOrigin = new URL(this.options.expectedIssuer).origin;
        for (const [candidate, name] of [
            [discovery.authorization_endpoint, "authorization endpoint"],
            [discovery.token_endpoint, "token endpoint"],
            [discovery.jwks_uri, "JWKS URI"],
        ] as const) {
            if (this.trustedUrl(candidate, name).origin !== issuerOrigin)
                throw new Error("OIDC endpoint origin mismatch");
        }
        if (
            !Array.isArray(discovery.code_challenge_methods_supported) ||
            !discovery.code_challenge_methods_supported.includes("S256") ||
            !Array.isArray(discovery.id_token_signing_alg_values_supported) ||
            !discovery.id_token_signing_alg_values_supported.includes(
                "RS256"
            ) ||
            !Array.isArray(discovery.response_types_supported) ||
            !discovery.response_types_supported.includes("code") ||
            !Array.isArray(discovery.token_endpoint_auth_methods_supported) ||
            !discovery.token_endpoint_auth_methods_supported.includes("none")
        )
            throw new Error("OIDC provider lacks required algorithms or flow");
        this.discoveryCache = {
            value: discovery,
            expiresAt: Date.now() + 60_000,
        };
        return discovery;
    }

    private async verifyIdToken(
        token: string,
        nonceDigest: string,
        discovery: Discovery
    ): Promise<JwtPayload & { sub: string }> {
        if (Buffer.byteLength(token, "utf8") > JWT_MAX_BYTES)
            throw new Error("ID token too large");
        const parts = token.split(".");
        if (parts.length !== 3 || parts.some((part) => !BASE64URL.test(part)))
            throw new Error("invalid ID token");
        const header = parseStrictJson(
            Buffer.from(parts[0], "base64url").toString("utf8")
        );
        const payload = parseStrictJson(
            Buffer.from(parts[1], "base64url").toString("utf8")
        ) as JwtPayload;
        if (
            !record(header) ||
            header.alg !== "RS256" ||
            typeof header.kid !== "string" ||
            header.kid.length < 1 ||
            header.kid.length > 200
        )
            throw new Error("invalid ID token algorithm");
        // Refresh before each validation cohort so a provider-retired key is
        // rejected immediately; concurrent validations share one fetch.
        const generation = this.jwksCache?.generation ?? 0;
        const keys = await this.jwks(discovery.jwks_uri, true, generation);
        const matches = this.matchingKeys(keys, header.kid);
        if (matches.length !== 1) throw new Error("ID token key rejected");
        let validSignature = false;
        try {
            validSignature = verify(
                "RSA-SHA256",
                Buffer.from(`${parts[0]}.${parts[1]}`, "ascii"),
                createPublicKey({
                    key: matches[0] as NodeJsonWebKey,
                    format: "jwk",
                }),
                Buffer.from(parts[2], "base64url")
            );
        } catch {
            throw new Error("ID token key rejected");
        }
        const now = Math.floor(Date.now() / 1000);
        const finiteTime = (candidate: unknown): candidate is number =>
            typeof candidate === "number" &&
            Number.isSafeInteger(candidate) &&
            candidate >= 0;
        const audience = Array.isArray(payload.aud)
            ? payload.aud
            : [payload.aud];
        if (
            !validSignature ||
            payload.iss !== this.options.expectedIssuer ||
            audience.length < 1 ||
            !audience.every((entry) => typeof entry === "string") ||
            !audience.includes(this.options.clientId) ||
            (audience.length > 1 && payload.azp !== this.options.clientId) ||
            typeof payload.sub !== "string" ||
            payload.sub.length < 1 ||
            payload.sub.length > 512 ||
            !finiteTime(payload.exp) ||
            payload.exp <= now - 60 ||
            !finiteTime(payload.iat) ||
            payload.iat > now + 60 ||
            (payload.nbf !== undefined &&
                (!finiteTime(payload.nbf) || payload.nbf > now + 60)) ||
            typeof payload.nonce !== "string" ||
            digest(payload.nonce) !== nonceDigest
        )
            throw new Error("ID token claims rejected");
        return payload as JwtPayload & { sub: string };
    }

    private matchingKeys(
        keys: unknown[],
        kid: string
    ): Record<string, unknown>[] {
        return keys.filter((key): key is Record<string, unknown> => {
            if (
                !record(key) ||
                key.kid !== kid ||
                key.kty !== "RSA" ||
                key.use !== "sig" ||
                (key.alg !== undefined && key.alg !== "RS256") ||
                (key.key_ops !== undefined &&
                    (!Array.isArray(key.key_ops) ||
                        !key.key_ops.includes("verify"))) ||
                typeof key.n !== "string" ||
                !BASE64URL.test(key.n) ||
                typeof key.e !== "string" ||
                !BASE64URL.test(key.e)
            )
                return false;
            const modulus = Buffer.from(key.n, "base64url");
            const exponent = Buffer.from(key.e, "base64url");
            if (
                modulus.length < 256 ||
                modulus.length > 1024 ||
                modulus[0] === 0 ||
                modulus.toString("base64url") !== key.n ||
                exponent.length < 1 ||
                exponent.length > 4 ||
                exponent[0] === 0 ||
                exponent.toString("base64url") !== key.e
            )
                return false;
            const leadingBits = 32 - Math.clz32(modulus[0]);
            const modulusBits = (modulus.length - 1) * 8 + leadingBits;
            const exponentValue = exponent.readUIntBE(0, exponent.length);
            return (
                modulusBits >= 2048 &&
                modulusBits <= 8192 &&
                exponentValue >= 65_537 &&
                exponentValue % 2 === 1
            );
        });
    }

    private async jwks(
        url: string,
        refresh: boolean,
        observedGeneration = 0
    ): Promise<unknown[]> {
        if (
            this.jwksCache !== undefined &&
            this.jwksCache.url === url &&
            ((!refresh && Date.now() < this.jwksCache.expiresAt) ||
                (refresh && this.jwksCache.generation > observedGeneration))
        )
            return this.jwksCache.keys;
        if (this.jwksRefresh !== undefined) return this.jwksRefresh;
        this.jwksRefresh = (async () => {
            const response = await this.fetchBounded(url);
            if (!response.ok) throw new Error("JWKS fetch failed");
            const value = await this.responseJson(response);
            if (
                !record(value) ||
                !Array.isArray(value.keys) ||
                value.keys.length < 1 ||
                value.keys.length > JWKS_MAX_KEYS
            )
                throw new Error("invalid JWKS");
            this.jwksCache = {
                url,
                keys: value.keys,
                expiresAt: Date.now() + 5 * 60_000,
                generation: (this.jwksCache?.generation ?? 0) + 1,
            };
            return value.keys;
        })();
        try {
            return await this.jwksRefresh;
        } finally {
            this.jwksRefresh = undefined;
        }
    }

    private async responseJson(response: Response): Promise<unknown> {
        const mediaType = response.headers
            .get("content-type")
            ?.split(";", 1)[0]
            .trim()
            .toLowerCase();
        if (mediaType !== "application/json")
            throw new Error("OIDC response content type rejected");
        return parseStrictJson(await response.text());
    }

    private async fetchBounded(
        url: string,
        init: RequestInit = {}
    ): Promise<Response> {
        const trusted = this.trustedUrl(url, "OIDC request URL");
        const address = await this.resolvePinnedAddress(trusted);
        const response =
            this.request === undefined
                ? await this.pinnedRequest(trusted, address, init)
                : await this.request(url, {
                      ...init,
                      redirect: "error",
                      signal: AbortSignal.timeout(this.httpTimeoutMs),
                  });
        const encoding = response.headers.get("content-encoding");
        if (encoding !== null && encoding.toLowerCase() !== "identity")
            throw new Error("OIDC response compression rejected");
        const length = response.headers.get("content-length");
        if (
            length !== null &&
            (!/^\d+$/.test(length) || Number(length) > HTTP_MAX_BYTES)
        )
            throw new Error("OIDC response too large");
        const chunks: Uint8Array[] = [];
        let received = 0;
        const reader = response.body?.getReader();
        if (reader !== undefined) {
            for (;;) {
                const part = await reader.read();
                if (part.done) break;
                received += part.value.byteLength;
                if (received > HTTP_MAX_BYTES) {
                    await reader.cancel();
                    throw new Error("OIDC response too large");
                }
                chunks.push(part.value);
            }
        }
        const body = Buffer.concat(chunks, received);
        return new Response(body, {
            status: response.status,
            statusText: response.statusText,
            headers: response.headers,
        });
    }

    private async pinnedRequest(
        url: URL,
        address: string,
        init: RequestInit
    ): Promise<Response> {
        const headers = new Headers(init.headers);
        headers.set("host", url.host);
        headers.set("accept-encoding", "identity");
        let body: Buffer | undefined;
        if (init.body !== undefined && init.body !== null) {
            if (typeof init.body === "string") body = Buffer.from(init.body);
            else if (init.body instanceof URLSearchParams)
                body = Buffer.from(init.body.toString());
            else if (init.body instanceof ArrayBuffer)
                body = Buffer.from(init.body);
            else if (ArrayBuffer.isView(init.body))
                body = Buffer.from(
                    init.body.buffer,
                    init.body.byteOffset,
                    init.body.byteLength
                );
            else throw new Error("unsupported OIDC request body");
            headers.set("content-length", String(body.length));
        }
        const response = await new Promise<Response>((resolve, reject) => {
            const transport =
                url.protocol === "https:" ? requestHttps : requestHttp;
            const operation: {
                request?: ReturnType<typeof requestHttps>;
                deadline?: NodeJS.Timeout;
                settled: boolean;
            } = { settled: false };
            const finish = (error?: Error, value?: Response): void => {
                if (operation.settled) return;
                operation.settled = true;
                if (operation.deadline !== undefined)
                    clearTimeout(operation.deadline);
                operation.request?.setTimeout(0);
                if (error !== undefined) reject(error);
                else resolve(value!);
            };
            operation.deadline = setTimeout(() => {
                const error = new Error("OIDC request deadline exceeded");
                operation.request?.destroy(error);
                finish(error);
            }, this.httpTimeoutMs);
            try {
                operation.request = transport(
                    {
                        protocol: url.protocol,
                        hostname: address,
                        port: url.port === "" ? undefined : Number(url.port),
                        method: init.method ?? "GET",
                        path: `${url.pathname}${url.search}`,
                        headers: Object.fromEntries(headers.entries()),
                        servername:
                            url.protocol === "https:" &&
                            isIP(url.hostname.replace(/^\[|\]$/g, "")) === 0
                                ? url.hostname
                                : undefined,
                        rejectUnauthorized: true,
                    },
                    (incoming) => {
                        const responseHeaders = new Headers();
                        for (
                            let index = 0;
                            index < incoming.rawHeaders.length;
                            index += 2
                        )
                            responseHeaders.append(
                                incoming.rawHeaders[index],
                                incoming.rawHeaders[index + 1]
                            );
                        const encoding =
                            responseHeaders.get("content-encoding");
                        if (
                            encoding !== null &&
                            encoding.toLowerCase() !== "identity"
                        ) {
                            const error = new Error(
                                "OIDC response compression rejected"
                            );
                            incoming.destroy(error);
                            finish(error);
                            return;
                        }
                        const declared = responseHeaders.get("content-length");
                        if (
                            declared !== null &&
                            (!/^\d+$/.test(declared) ||
                                Number(declared) > HTTP_MAX_BYTES)
                        ) {
                            const error = new Error("OIDC response too large");
                            incoming.destroy(error);
                            finish(error);
                            return;
                        }
                        const chunks: Buffer[] = [];
                        let received = 0;
                        incoming.on("data", (chunk: Buffer) => {
                            received += chunk.length;
                            if (received > HTTP_MAX_BYTES) {
                                const error = new Error(
                                    "OIDC response too large"
                                );
                                incoming.destroy(error);
                                finish(error);
                            } else chunks.push(chunk);
                        });
                        incoming.on("aborted", () =>
                            finish(new Error("OIDC response aborted"))
                        );
                        incoming.on("error", (error) => finish(error));
                        incoming.on("end", () =>
                            finish(
                                undefined,
                                new Response(Buffer.concat(chunks, received), {
                                    status: incoming.statusCode ?? 500,
                                    statusText: incoming.statusMessage,
                                    headers: responseHeaders,
                                })
                            )
                        );
                    }
                );
                const request = operation.request;
                request.setTimeout(this.httpTimeoutMs, () => {
                    const error = new Error("OIDC request timeout");
                    request.destroy(error);
                    finish(error);
                });
                request.on("error", (error) => finish(error));
                request.end(body);
            } catch (cause) {
                finish(
                    cause instanceof Error
                        ? cause
                        : new Error("OIDC request failed")
                );
            }
        });
        return response;
    }
}

/** Construct the control-session capability from its dedicated PostgreSQL URL. */
export function createV2OidcSessions(
    postgresUrl: string,
    options: V2OidcSessionOptions
): V2OidcSessions {
    const database = createPostgresKnex(postgresUrl);
    return new V2OidcSessions(database, options, () => database.destroy());
}
