import {
    GetObjectCommand,
    PutObjectCommand,
    S3Client,
} from "@aws-sdk/client-s3";
import { IV2RequestPrincipal } from "@staticdeploy/core";
import { Knex } from "knex";
import {
    KeyObject,
    createHash,
    createPrivateKey,
    createPublicKey,
    randomUUID,
    sign,
    verify,
} from "node:crypto";

import { isS3NotFoundError } from "./common/s3Errors";
import { parseV2ReleaseManifest, V2_OBJECT_LIMITS } from "./V2ObjectStorage";

const UUID =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const OWNER = /^[A-Za-z0-9._:-]{1,200}$/;
const ERROR_CODE = /^[A-Z][A-Z0-9_]{0,127}$/;
const KID = /^[A-Za-z0-9._:-]{1,100}$/;
const ACTOR = /^oidc:[0-9a-f]{64}$/;
const HOST =
    /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/;
const MIN_LEASE_MS = 100;
const MAX_LEASE_MS = 15 * 60 * 1000;
const MAX_BATCH = 100;
const MAX_RETRY_MS = 15 * 60 * 1000;
const MAX_ROUTING_BYTES = 16 * 1024;
const S3_TIMEOUT_MS = 30_000;
const ROUTING_PURPOSE = "staticdeploy-routing-v1";
const ROUTING_CONTEXT = "v2/routing";
const ROUTING_TYP = "staticdeploy-routing+jws";

export type V2PublicationOperation = "PUBLISH" | "RESTORE" | "UNPUBLISH";
export type V2RoutingKeyStatus = "ACTIVE" | "OVERLAP" | "RETIRED" | "REVOKED";

export interface V2RoutingVerificationKey {
    kid: string;
    purpose: typeof ROUTING_PURPOSE;
    status: V2RoutingKeyStatus;
    publicKey: string | Buffer | KeyObject;
    notBefore: string;
    notAfter: string;
}

export interface V2RoutingSigningKey extends V2RoutingVerificationKey {
    privateKey: string | Buffer | KeyObject;
}

/** Compatibility alias for worker signing configuration. */
export type V2RoutingKey = V2RoutingSigningKey;

export interface V2RoutingPayload {
    version: 1;
    purpose: typeof ROUTING_PURPOSE;
    context: typeof ROUTING_CONTEXT;
    applicationId: string;
    routingId: string;
    host: string;
    audience: "staticdeploy-published-content";
    generation: number;
    issuedAt: string;
    operation: V2PublicationOperation;
    release: null | {
        id: string;
        manifestDigest: string;
        objectPrefix: string;
    };
}

export interface V2VerifiedRoutingDocument {
    payload: V2RoutingPayload;
    digest: string;
    body: Buffer;
    kid: string;
}

interface PublicationRow {
    id: string;
    application_id: string;
    routing_id: string;
    release_id: string | null;
    generation: string | number;
    operation: V2PublicationOperation;
    idempotency_id: string;
    payload_kind: "RELEASE" | "TOMBSTONE";
    manifest_digest: string | null;
    object_prefix: string | null;
    state: string;
    lease_owner: string | null;
    lease_expires_at: Date | string | null;
    attempt_count: number;
    lease_version: string | number;
    max_attempts: number;
    created_at: Date | string;
    routing_kid: string | null;
    routing_host: string;
    request_digest: string;
    request_actor_id: string;
    request_audit_id: string;
    acknowledged_etag: string | null;
    acknowledged_version_id: string | null;
}

export interface V2PublicationLease {
    id: string;
    applicationId: string;
    routingId: string;
    releaseId: string | null;
    generation: number;
    operation: V2PublicationOperation;
    idempotencyId: string;
    manifestDigest: string | null;
    objectPrefix: string | null;
    owner: string;
    leaseExpiresAt: Date;
    leaseVersion: number;
    attemptCount: number;
    maxAttempts: number;
    createdAt: Date;
    routingKid: string | null;
    routingHost: string;
    requestDigest: string;
    requestActorId: string;
    requestAuditId: string;
}

export class V2PublicationLeaseLostError extends Error {
    constructor() {
        super("publication lease fencing does not match an active lease");
        this.name = "V2PublicationLeaseLostError";
    }
}

export class V2ProjectionConflictError extends Error {
    constructor(message = "routing projection precondition failed") {
        super(message);
        this.name = "V2ProjectionConflictError";
    }
}

export class V2RoutingReplayError extends Error {
    constructor() {
        super("routing generation is below the verified watermark");
        this.name = "V2RoutingReplayError";
    }
}

function canonicalJson(value: unknown): string {
    if (value === null) return "null";
    if (typeof value === "string" || typeof value === "boolean")
        return JSON.stringify(value);
    if (typeof value === "number") {
        if (!Number.isSafeInteger(value))
            throw new Error("routing number is outside safe integer bounds");
        return String(value);
    }
    if (Array.isArray(value))
        return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
    if (typeof value === "object") {
        const record = value as Record<string, unknown>;
        const keys = Object.keys(record).sort();
        return `{${keys
            .map(
                (key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`
            )
            .join(",")}}`;
    }
    throw new Error("routing document contains unsupported JSON value");
}

function base64url(value: Buffer): string {
    return value.toString("base64url");
}

function decodeBase64url(value: unknown, label: string): Buffer {
    if (
        typeof value !== "string" ||
        value.length < 1 ||
        value.length > MAX_ROUTING_BYTES * 2 ||
        !/^[A-Za-z0-9_-]+$/.test(value)
    )
        throw new Error(`invalid routing ${label}`);
    const decoded = Buffer.from(value, "base64url");
    if (base64url(decoded) !== value)
        throw new Error(`non-canonical routing ${label}`);
    return decoded;
}

function assertUuid(value: string, label: string): void {
    if (!UUID.test(value)) throw new Error(`invalid routing ${label}`);
}

export function normalizeV2RoutingHost(value: string): string {
    if (
        typeof value !== "string" ||
        !HOST.test(value) ||
        value !== value.toLowerCase()
    )
        throw new Error(
            "routing host must be an explicit normalized ASCII hostname"
        );
    return value;
}

function exactKeys(
    value: object,
    expected: readonly string[],
    label: string
): void {
    if (Object.keys(value).sort().join(",") !== [...expected].sort().join(","))
        throw new Error(`${label} is not closed`);
}

function parseInstant(value: string, label: string): number {
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value))
        throw new Error(`invalid ${label}`);
    const parsed = Date.parse(value);
    if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value)
        throw new Error(`invalid ${label}`);
    return parsed;
}

function assertPayload(payload: V2RoutingPayload): void {
    if (
        payload === null ||
        typeof payload !== "object" ||
        Array.isArray(payload)
    )
        throw new Error("invalid routing payload contract");
    exactKeys(
        payload,
        [
            "applicationId",
            "audience",
            "context",
            "generation",
            "host",
            "issuedAt",
            "operation",
            "purpose",
            "release",
            "routingId",
            "version",
        ],
        "routing payload"
    );
    if (
        payload.version !== 1 ||
        payload.purpose !== ROUTING_PURPOSE ||
        payload.context !== ROUTING_CONTEXT ||
        payload.audience !== "staticdeploy-published-content" ||
        !Number.isSafeInteger(payload.generation) ||
        payload.generation < 1 ||
        !["PUBLISH", "RESTORE", "UNPUBLISH"].includes(payload.operation)
    )
        throw new Error("invalid routing payload contract");
    parseInstant(payload.issuedAt, "routing issue time");
    normalizeV2RoutingHost(payload.host);
    assertUuid(payload.applicationId, "application id");
    assertUuid(payload.routingId, "routing id");
    if (payload.operation === "UNPUBLISH") {
        if (payload.release !== null)
            throw new Error("routing tombstone must not contain a release");
        return;
    }
    if (
        payload.release === null ||
        typeof payload.release !== "object" ||
        Array.isArray(payload.release)
    )
        throw new Error("routing release payload is missing");
    exactKeys(
        payload.release,
        ["id", "manifestDigest", "objectPrefix"],
        "routing release payload"
    );
    assertUuid(payload.release.id, "release id");
    if (!SHA256.test(payload.release.manifestDigest))
        throw new Error("invalid routing manifest digest");
    const expected = `v2/releases/${payload.applicationId}/${payload.release.id}`;
    if (payload.release.objectPrefix !== expected)
        throw new Error(
            "routing release prefix is not bound to its identities"
        );
}

function asPrivateKey(value: V2RoutingSigningKey["privateKey"]): KeyObject {
    if (value === undefined)
        throw new Error("active routing key has no private key");
    return value instanceof KeyObject ? value : createPrivateKey(value);
}

function asPublicKey(value: V2RoutingVerificationKey["publicKey"]): KeyObject {
    return value instanceof KeyObject ? value : createPublicKey(value);
}

function validateVerificationKeys(
    keys: readonly V2RoutingVerificationKey[]
): Map<string, V2RoutingVerificationKey> {
    if (keys.length < 1 || keys.length > 16)
        throw new Error("routing keyring size is outside bounds");
    const result = new Map<string, V2RoutingVerificationKey>();
    for (const key of keys) {
        if (
            !KID.test(key.kid) ||
            key.purpose !== ROUTING_PURPOSE ||
            !["ACTIVE", "OVERLAP", "RETIRED", "REVOKED"].includes(key.status) ||
            result.has(key.kid)
        )
            throw new Error("invalid or duplicate routing key configuration");
        if (asPublicKey(key.publicKey).asymmetricKeyType !== "ed25519")
            throw new Error("routing public key must be Ed25519");
        if (
            parseInstant(key.notBefore, "routing key not-before") >=
            parseInstant(key.notAfter, "routing key not-after")
        )
            throw new Error("routing key validity window is invalid");
        result.set(key.kid, key);
    }
    return result;
}

/** Public-key-only verifier used by content and reconciliation. */
export class V2RoutingVerifier {
    private readonly keys: Map<string, V2RoutingVerificationKey>;
    constructor(keys: readonly V2RoutingVerificationKey[]) {
        if (keys.some((key) => "privateKey" in key))
            throw new Error(
                "routing verifier must not receive private key material"
            );
        this.keys = validateVerificationKeys(keys);
        if (![...this.keys.values()].some((key) => key.status === "ACTIVE"))
            throw new Error("routing verifier requires an active public key");
    }

    verify(
        body: Uint8Array,
        expected: { routingId: string; applicationId: string; host: string }
    ): V2VerifiedRoutingDocument {
        assertUuid(expected.routingId, "expected routing id");
        assertUuid(expected.applicationId, "expected application id");
        normalizeV2RoutingHost(expected.host);
        const bytes = Buffer.from(body);
        if (bytes.byteLength < 1 || bytes.byteLength > MAX_ROUTING_BYTES)
            throw new Error("routing document exceeds byte limit");
        let envelope: unknown;
        try {
            envelope = JSON.parse(bytes.toString("utf8"));
        } catch {
            throw new Error("routing document is not valid JSON");
        }
        if (
            envelope === null ||
            typeof envelope !== "object" ||
            Array.isArray(envelope) ||
            Object.keys(envelope).sort().join(",") !==
                "payload,protected,signature" ||
            canonicalJson(envelope) !== bytes.toString("utf8")
        )
            throw new Error("routing envelope is not canonical and closed");
        const record = envelope as Record<string, unknown>;
        const protectedBytes = decodeBase64url(
            record.protected,
            "protected header"
        );
        const payloadBytes = decodeBase64url(record.payload, "payload");
        const signature = decodeBase64url(record.signature, "signature");
        let header: unknown;
        let payload: unknown;
        try {
            header = JSON.parse(protectedBytes.toString("utf8"));
            payload = JSON.parse(payloadBytes.toString("utf8"));
        } catch {
            throw new Error("routing protected data is not valid JSON");
        }
        if (
            header === null ||
            typeof header !== "object" ||
            Array.isArray(header) ||
            Object.keys(header).sort().join(",") !== "alg,kid,typ" ||
            canonicalJson(header) !== protectedBytes.toString("utf8")
        )
            throw new Error(
                "routing protected header is not canonical and closed"
            );
        const protectedHeader = header as Record<string, unknown>;
        if (
            protectedHeader.alg !== "EdDSA" ||
            protectedHeader.typ !== ROUTING_TYP ||
            typeof protectedHeader.kid !== "string"
        )
            throw new Error(
                "routing protected header has wrong algorithm or purpose"
            );
        const key = this.keys.get(protectedHeader.kid);
        if (
            key === undefined ||
            key.status === "RETIRED" ||
            key.status === "REVOKED"
        )
            throw new Error("routing key is unknown, retired, or revoked");
        if (canonicalJson(payload) !== payloadBytes.toString("utf8"))
            throw new Error("routing payload is not canonical");
        assertPayload(payload as V2RoutingPayload);
        const typed = payload as V2RoutingPayload;
        const issuedAt = parseInstant(typed.issuedAt, "routing issue time");
        if (
            issuedAt < parseInstant(key.notBefore, "routing key not-before") ||
            issuedAt >= parseInstant(key.notAfter, "routing key not-after")
        )
            throw new Error("routing key was not valid at issue time");
        if (
            typed.routingId !== expected.routingId ||
            typed.applicationId !== expected.applicationId ||
            typed.host !== expected.host
        )
            throw new Error("routing document identity substitution rejected");
        const signingInput = Buffer.from(
            `${record.protected as string}.${record.payload as string}`,
            "ascii"
        );
        if (!verify(null, signingInput, asPublicKey(key.publicKey), signature))
            throw new Error("routing signature is invalid");
        return {
            payload: typed,
            digest: createHash("sha256").update(bytes).digest("hex"),
            body: bytes,
            kid: key.kid,
        };
    }
}

/** Worker-only signer; its verifier export contains no private material. */
export class V2RoutingSigner {
    private readonly keys: Map<string, V2RoutingSigningKey>;
    private readonly active: V2RoutingSigningKey;
    readonly verifier: V2RoutingVerifier;
    constructor(keys: readonly V2RoutingSigningKey[]) {
        this.keys = new Map();
        validateVerificationKeys(keys);
        for (const key of keys) {
            const privateKey = asPrivateKey(key.privateKey);
            if (privateKey.asymmetricKeyType !== "ed25519")
                throw new Error("routing private key must be Ed25519");
            const challenge = Buffer.from(
                `staticdeploy-routing-key-match:${key.kid}`,
                "utf8"
            );
            if (
                !verify(
                    null,
                    challenge,
                    asPublicKey(key.publicKey),
                    sign(null, challenge, privateKey)
                )
            )
                throw new Error(
                    "routing signing and verification keys do not match"
                );
            this.keys.set(key.kid, key);
        }
        const active = keys.filter((key) => key.status === "ACTIVE");
        if (active.length !== 1)
            throw new Error(
                "routing signer requires exactly one active signing key"
            );
        this.active = active[0];
        this.verifier = new V2RoutingVerifier(
            keys.map(({ privateKey: _privateKey, ...key }) => key)
        );
    }
    get activeKid(): string {
        return this.active.kid;
    }
    kidForIssueTime(issuedAt: Date): string {
        const instant = issuedAt.getTime();
        if (!Number.isFinite(instant))
            throw new Error("invalid routing issue time");
        const valid = [...this.keys.values()]
            .filter(
                (key) =>
                    (key.status === "ACTIVE" || key.status === "OVERLAP") &&
                    instant >=
                        parseInstant(key.notBefore, "routing key not-before") &&
                    instant <
                        parseInstant(key.notAfter, "routing key not-after")
            )
            .sort((left, right) => {
                if (left.status !== right.status)
                    return left.status === "ACTIVE" ? -1 : 1;
                const byNotBefore =
                    parseInstant(right.notBefore, "routing key not-before") -
                    parseInstant(left.notBefore, "routing key not-before");
                if (byNotBefore !== 0) return byNotBefore;
                return left.kid < right.kid ? -1 : left.kid > right.kid ? 1 : 0;
            });
        if (valid.length === 0)
            throw new Error("no routing signing key is valid at issue time");
        return valid[0].kid;
    }
    sign(payload: V2RoutingPayload, boundKid = this.active.kid): Buffer {
        assertPayload(payload);
        const key = this.keys.get(boundKid);
        if (
            key === undefined ||
            key.status === "RETIRED" ||
            key.status === "REVOKED"
        )
            throw new Error("bound routing signing key is unavailable");
        const issuedAt = parseInstant(payload.issuedAt, "routing issue time");
        if (
            issuedAt < parseInstant(key.notBefore, "routing key not-before") ||
            issuedAt >= parseInstant(key.notAfter, "routing key not-after")
        )
            throw new Error("routing signing key was not valid at issue time");
        const protectedValue = base64url(
            Buffer.from(
                canonicalJson({ alg: "EdDSA", kid: key.kid, typ: ROUTING_TYP }),
                "utf8"
            )
        );
        const payloadValue = base64url(
            Buffer.from(canonicalJson(payload), "utf8")
        );
        const signingInput = Buffer.from(
            `${protectedValue}.${payloadValue}`,
            "ascii"
        );
        const body = Buffer.from(
            canonicalJson({
                payload: payloadValue,
                protected: protectedValue,
                signature: base64url(
                    sign(null, signingInput, asPrivateKey(key.privateKey))
                ),
            }),
            "utf8"
        );
        if (body.byteLength > MAX_ROUTING_BYTES)
            throw new Error("routing document exceeds byte limit");
        return body;
    }
}

/** @deprecated use V2RoutingSigner. */
export class V2RoutingKeyring extends V2RoutingSigner {}

function toLease(row: PublicationRow): V2PublicationLease {
    const generation = Number(row.generation);
    const leaseVersion = Number(row.lease_version);
    if (
        row.lease_owner === null ||
        row.lease_expires_at === null ||
        !Number.isSafeInteger(generation) ||
        generation < 1 ||
        !Number.isSafeInteger(leaseVersion) ||
        leaseVersion < 1 ||
        !HOST.test(row.routing_host) ||
        !SHA256.test(row.request_digest) ||
        !ACTOR.test(row.request_actor_id)
    )
        throw new Error("claimed publication has invalid lease identity");
    return {
        id: row.id,
        applicationId: row.application_id,
        routingId: row.routing_id,
        releaseId: row.release_id,
        generation,
        operation: row.operation,
        idempotencyId: row.idempotency_id,
        manifestDigest: row.manifest_digest,
        objectPrefix: row.object_prefix,
        owner: row.lease_owner,
        leaseExpiresAt: new Date(row.lease_expires_at),
        leaseVersion,
        attemptCount: Number(row.attempt_count),
        maxAttempts: Number(row.max_attempts),
        createdAt: new Date(row.created_at),
        routingKid: row.routing_kid,
        routingHost: row.routing_host,
        requestDigest: row.request_digest,
        requestActorId: row.request_actor_id,
        requestAuditId: row.request_audit_id,
    };
}

function rows<T>(value: unknown): T[] {
    return (value as { rows: T[] }).rows;
}

function isFenceError(error: unknown): boolean {
    return (error as { code?: string }).code === "55000";
}

export class V2PublicationQueue {
    constructor(private readonly knex: Knex) {}

    async request(input: {
        actor: IV2RequestPrincipal;
        applicationId: string;
        routingHost: string;
        releaseId: string | null;
        operation: V2PublicationOperation;
        idempotencyId: string;
        requestDigest: string;
        outboxId?: string;
        auditId?: string;
        authorizationAuditId?: string;
    }): Promise<{ id: string; generation: number; state: string }> {
        for (const [value, label] of [
            [input.applicationId, "application id"],
            [input.idempotencyId, "idempotency id"],
            [input.actor.sessionId, "session id"],
            [input.outboxId ?? (input.outboxId = randomUUID()), "outbox id"],
            [input.auditId ?? (input.auditId = randomUUID()), "audit id"],
            [
                input.authorizationAuditId ??
                    (input.authorizationAuditId = randomUUID()),
                "authorization audit id",
            ],
        ] as const)
            assertUuid(value, label);
        if (input.releaseId !== null) assertUuid(input.releaseId, "release id");
        normalizeV2RoutingHost(input.routingHost);
        if (!SHA256.test(input.requestDigest))
            throw new Error("invalid publication request digest");
        if (
            !Number.isSafeInteger(input.actor.claimsVersion) ||
            input.actor.claimsVersion < 1 ||
            !Array.isArray(input.actor.groups) ||
            input.actor.groups.length > 256
        )
            throw new Error("invalid publication authorization principal");
        const result = rows<PublicationRow>(
            await this.knex.raw(
                "SELECT * FROM public.v2_request_publication(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    input.applicationId,
                    input.releaseId,
                    input.operation,
                    input.idempotencyId,
                    input.outboxId,
                    input.auditId,
                    input.authorizationAuditId,
                    input.actor.sessionId,
                    input.actor.groups,
                    input.actor.claimsVersion,
                    input.requestDigest,
                    input.routingHost,
                ]
            )
        )[0];
        if (result === undefined || result.id === null)
            throw new Error("publication is not authorized");
        return {
            id: result.id,
            generation: Number(result.generation),
            state: result.state,
        };
    }

    async operation(id: string): Promise<{
        id: string;
        state: string;
        generation: number;
        requestDigest: string;
    }> {
        assertUuid(id, "outbox id");
        const row = rows<{
            id: string;
            state: string;
            generation: string | number;
            request_digest: string;
        }>(
            await this.knex.raw(
                "SELECT * FROM public.v2_publication_operation(?)",
                [id]
            )
        )[0];
        if (row === undefined)
            throw new Error("publication operation not found");
        return {
            id: row.id,
            state: row.state,
            generation: Number(row.generation),
            requestDigest: row.request_digest,
        };
    }

    async assertProjectable(lease: V2PublicationLease): Promise<void> {
        assertLease(lease);
        try {
            await this.knex.raw(
                "SELECT public.v2_assert_publication_projectable(?, ?, ?)",
                [lease.id, lease.owner, lease.leaseVersion]
            );
        } catch (error) {
            if (isFenceError(error)) throw new V2PublicationLeaseLostError();
            throw error;
        }
    }

    /** Qualifies the exact externally provisioned combined control or worker role. */
    async verifyReady(kind: "CONTROL" | "WORKER"): Promise<void> {
        const control = [
            "public.v2_begin_oidc_login(uuid,text,text,text,bytea,bytea,text,text,text,integer)",
            "public.v2_consume_oidc_login(uuid,text)",
            "public.v2_create_or_replace_session(uuid,uuid,text,text,jsonb,text,text,bytea,bytea,integer,integer)",
            "public.v2_read_session(uuid)",
            "public.v2_use_session(uuid,integer)",
            "public.v2_rotate_session_envelope(uuid,text,text,bytea,bytea)",
            "public.v2_revoke_session(uuid,text)",
            "public.v2_cleanup_auth_state(bigint,integer)",
            "public.v2_initialize_authorization_policy(text[],bigint,text)",
            "public.v2_authorization_policy_identity()",
            "public.v2_authorize_operation(uuid,uuid,text[],bigint,uuid,text)",
            "public.v2_replace_bindings(uuid,uuid,text[],bigint,uuid,bigint,text,text,jsonb)",
            "public.v2_request_publication(uuid,uuid,text,uuid,uuid,uuid,uuid,uuid,text[],bigint,text,text)",
            "public.v2_publication_operation(uuid)",
        ];
        const worker = [
            "public.v2_claim_release_jobs(text,integer,integer)",
            "public.v2_renew_release_job(uuid,text,bigint,integer)",
            "public.v2_assert_release_job_lease(uuid,text,bigint)",
            "public.v2_bind_release_job_work(uuid,text,bigint,text)",
            "public.v2_prepare_quarantine_cleanup(uuid,text,bigint,bigint)",
            "public.v2_finish_release_job(uuid,uuid,text,text,bigint,text,text,text,integer,text)",
            "public.v2_claim_publications(text,integer,integer)",
            "public.v2_bind_publication_key(uuid,text,bigint,text)",
            "public.v2_renew_publication(uuid,text,bigint,integer)",
            "public.v2_assert_publication_projectable(uuid,text,bigint)",
            "public.v2_finish_projected_publication_attempt(uuid,text,bigint,text,text,integer,uuid)",
            "public.v2_acknowledge_projected_publication(uuid,text,bigint,text,text,text,uuid)",
        ];
        const expected = kind === "CONTROL" ? control : worker;
        const qualification = rows<{
            rolcanlogin: boolean;
            elevated: boolean;
            unsafe_schema: boolean;
            database_create: boolean;
            has_memberships: boolean;
            owns_runtime_objects: boolean;
            direct_relation: boolean;
            missing_expected: boolean;
            unrelated_definer: boolean;
        }>(
            await this.knex.raw(
                `
            SELECT r.rolcanlogin,
                   (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole
                    OR r.rolcreatedb OR r.rolreplication) AS elevated,
                   EXISTS (SELECT 1 FROM pg_namespace n
                     WHERE n.nspname <> 'information_schema'
                       AND n.nspname !~ '^pg_(catalog|toast|temp_|toasted_temp_)'
                       AND (n.nspowner = r.oid OR
                         has_schema_privilege(current_user, n.oid, 'CREATE'))) AS unsafe_schema,
                   has_database_privilege(current_user, current_database(), 'CREATE') AS database_create,
                   EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member = r.oid) AS has_memberships,
                   EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                     WHERE n.nspname <> 'information_schema'
                       AND n.nspname !~ '^pg_(catalog|toast|temp_|toasted_temp_)'
                       AND c.relowner = r.oid)
                     OR EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                       WHERE n.nspname <> 'information_schema'
                         AND n.nspname !~ '^pg_(catalog|toast|temp_|toasted_temp_)'
                         AND p.proowner = r.oid) AS owns_runtime_objects,
                   EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                     WHERE n.nspname <> 'information_schema'
                       AND n.nspname !~ '^pg_(catalog|toast|temp_|toasted_temp_)'
                       AND c.relkind IN ('r','p','v','m','f')
                       AND (has_table_privilege(current_user, c.oid,
                         'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                         OR has_any_column_privilege(current_user, c.oid,
                         'SELECT,INSERT,UPDATE,REFERENCES'))) AS direct_relation,
                   EXISTS (SELECT 1 FROM unnest(?::text[]) signature
                     WHERE NOT has_function_privilege(current_user, signature, 'EXECUTE')) AS missing_expected,
                   EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                     WHERE n.nspname <> 'information_schema'
                       AND n.nspname !~ '^pg_(catalog|toast|temp_|toasted_temp_)'
                       AND p.prosecdef
                       AND p.prorettype NOT IN ('trigger'::regtype, 'event_trigger'::regtype)
                       AND has_function_privilege(current_user, p.oid, 'EXECUTE')
                       AND p.oid <> ALL (ARRAY(SELECT to_regprocedure(signature)
                         FROM unnest(?::text[]) signature)::oid[])) AS unrelated_definer
              FROM pg_roles r WHERE r.rolname = current_user`,
                [expected, expected]
            )
        )[0];
        if (
            qualification === undefined ||
            !qualification.rolcanlogin ||
            qualification.elevated ||
            qualification.unsafe_schema ||
            qualification.database_create ||
            qualification.has_memberships ||
            qualification.owns_runtime_objects ||
            qualification.direct_relation ||
            qualification.missing_expected ||
            qualification.unrelated_definer
        )
            throw new Error(
                `publication ${kind.toLowerCase()} PostgreSQL identity is not least privilege`
            );
    }

    async assertKeyRetirable(kid: string): Promise<void> {
        if (!KID.test(kid)) throw new Error("invalid routing key identity");
        const count = await this.knex.transaction(async (transaction) => {
            await transaction.raw("SET LOCAL lock_timeout = '5s'");
            await transaction.raw("SET LOCAL statement_timeout = '30s'");
            return Number(
                rows<{ count: string }>(
                    await transaction.raw(
                        `
                SELECT count(*)::text AS count
                  FROM public.v2_publication_outbox outbox
                  JOIN public.v2_applications application
                    ON application.id = outbox.application_id
                 WHERE outbox.routing_kid = ?
                   AND (outbox.state IN ('PENDING', 'LEASED')
                     OR (outbox.state = 'ACKNOWLEDGED'
                       AND application.served_generation = outbox.generation))`,
                        [kid]
                    )
                )[0].count
            );
        });
        if (count !== 0)
            throw new Error(
                "routing key is still referenced by pending or current projection"
            );
    }

    async claimDue(input: {
        owner: string;
        leaseMs: number;
        limit?: number;
    }): Promise<V2PublicationLease[]> {
        assertOwnerAndLease(input.owner, input.leaseMs);
        const limit = input.limit ?? 1;
        if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_BATCH)
            throw new Error("publication claim batch is outside bounds");
        return rows<PublicationRow>(
            await this.knex.raw(
                "SELECT * FROM public.v2_claim_publications(?, ?, ?)",
                [input.owner, input.leaseMs, limit]
            )
        ).map(toLease);
    }

    async bindKey(
        lease: V2PublicationLease,
        kid: string
    ): Promise<V2PublicationLease> {
        assertLease(lease);
        if (!KID.test(kid)) throw new Error("invalid routing key identity");
        try {
            return toLease(
                rows<PublicationRow>(
                    await this.knex.raw(
                        "SELECT * FROM public.v2_bind_publication_key(?, ?, ?, ?)",
                        [lease.id, lease.owner, lease.leaseVersion, kid]
                    )
                )[0]
            );
        } catch (error) {
            if (isFenceError(error)) throw new V2PublicationLeaseLostError();
            throw error;
        }
    }

    async renew(
        lease: V2PublicationLease,
        leaseMs: number
    ): Promise<V2PublicationLease> {
        assertLease(lease);
        assertOwnerAndLease(lease.owner, leaseMs);
        try {
            return toLease(
                rows<PublicationRow>(
                    await this.knex.raw(
                        "SELECT * FROM public.v2_renew_publication(?, ?, ?, ?)",
                        [lease.id, lease.owner, lease.leaseVersion, leaseMs]
                    )
                )[0]
            );
        } catch (error) {
            if (isFenceError(error)) throw new V2PublicationLeaseLostError();
            throw error;
        }
    }

    async retry(
        lease: V2PublicationLease,
        errorCode: string,
        delayMs: number
    ): Promise<void> {
        assertLease(lease);
        assertErrorCode(errorCode);
        if (
            !Number.isSafeInteger(delayMs) ||
            delayMs < 1 ||
            delayMs > MAX_RETRY_MS
        )
            throw new Error("publication retry delay is outside bounds");
        await this.finish(lease, "RETRY", errorCode, delayMs);
    }

    async fail(lease: V2PublicationLease, errorCode: string): Promise<void> {
        assertLease(lease);
        assertErrorCode(errorCode);
        await this.finish(lease, "FAILED", errorCode, null);
    }

    async acknowledge(
        lease: V2PublicationLease,
        receipt: V2ProjectionReceipt,
        auditId = randomUUID()
    ): Promise<string | null> {
        assertLease(lease);
        assertUuid(auditId, "audit id");
        if (!SHA256.test(receipt.document.digest))
            throw new Error("invalid projection digest");
        if (
            receipt.etag.length < 1 ||
            Buffer.byteLength(receipt.etag, "utf8") > 1024
        )
            throw new Error("invalid projection ETag");
        if (
            receipt.versionId !== null &&
            (receipt.versionId.length < 1 ||
                Buffer.byteLength(receipt.versionId, "utf8") > 1024)
        )
            throw new Error("invalid projection version identity");
        try {
            const result = await this.knex.raw(
                "SELECT public.v2_acknowledge_projected_publication(?, ?, ?, ?, ?, ?, ?) AS label",
                [
                    lease.id,
                    lease.owner,
                    lease.leaseVersion,
                    receipt.document.digest,
                    receipt.etag,
                    receipt.versionId,
                    auditId,
                ]
            );
            return rows<{ label: string | null }>(result)[0].label;
        } catch (error) {
            if (isFenceError(error)) throw new V2PublicationLeaseLostError();
            throw error;
        }
    }

    private async finish(
        lease: V2PublicationLease,
        outcome: "RETRY" | "FAILED",
        errorCode: string,
        delayMs: number | null
    ): Promise<void> {
        try {
            await this.knex.raw(
                "SELECT public.v2_finish_projected_publication_attempt(?, ?, ?, ?, ?, ?, ?)",
                [
                    lease.id,
                    lease.owner,
                    lease.leaseVersion,
                    outcome,
                    errorCode,
                    delayMs,
                    randomUUID(),
                ]
            );
        } catch (error) {
            if (isFenceError(error)) throw new V2PublicationLeaseLostError();
            throw error;
        }
    }
}

function assertOwnerAndLease(owner: string, leaseMs: number): void {
    if (!OWNER.test(owner)) throw new Error("invalid publication lease owner");
    if (
        !Number.isSafeInteger(leaseMs) ||
        leaseMs < MIN_LEASE_MS ||
        leaseMs > MAX_LEASE_MS
    )
        throw new Error("publication lease duration is outside bounds");
}
function assertErrorCode(value: string): void {
    if (!ERROR_CODE.test(value))
        throw new Error("invalid publication error code");
}
function assertLease(lease: V2PublicationLease): void {
    assertUuid(lease.id, "outbox id");
    assertUuid(lease.applicationId, "application id");
    assertUuid(lease.routingId, "routing id");
    if (
        !OWNER.test(lease.owner) ||
        !Number.isSafeInteger(lease.leaseVersion) ||
        lease.leaseVersion < 1
    )
        throw new Error("invalid publication lease identity");
}

async function readObject(
    client: S3Client,
    bucket: string,
    key: string,
    maximumBytes = MAX_ROUTING_BYTES
): Promise<{
    body: Buffer;
    etag: string | null;
    versionId: string | null;
} | null> {
    try {
        const result = await client.send(
            new GetObjectCommand({ Bucket: bucket, Key: key }),
            { abortSignal: AbortSignal.timeout(S3_TIMEOUT_MS) }
        );
        if (result.Body === undefined)
            throw new Error("routing object has no body");
        if (
            result.ContentLength !== undefined &&
            result.ContentLength > maximumBytes
        )
            throw new Error("routing object exceeds byte limit");
        const chunks: Buffer[] = [];
        let length = 0;
        const stream = result.Body as AsyncIterable<Uint8Array>;
        if (typeof stream[Symbol.asyncIterator] !== "function")
            throw new Error("routing object body is not a bounded stream");
        for await (const chunk of stream) {
            length += chunk.byteLength;
            if (length > maximumBytes)
                throw new Error("routing object exceeds byte limit");
            chunks.push(Buffer.from(chunk));
        }
        const body = Buffer.concat(chunks, length);
        return {
            body,
            etag: result.ETag ?? null,
            versionId: result.VersionId ?? null,
        };
    } catch (error) {
        if (isS3NotFoundError(error)) return null;
        throw error;
    }
}
function preconditionFailed(error: unknown): boolean {
    const typed = error as {
        $metadata?: { httpStatusCode?: number };
        name?: string;
    };
    return (
        typed.$metadata?.httpStatusCode === 412 ||
        typed.name === "PreconditionFailed"
    );
}
function routeKeys(
    routingId: string,
    generation: number
): { generation: string; current: string } {
    assertUuid(routingId, "routing id");
    if (!Number.isSafeInteger(generation) || generation < 1)
        throw new Error("invalid routing generation");
    const prefix = `v2/routing/${routingId}`;
    return {
        generation: `${prefix}/generations/${generation}.json`,
        current: `${prefix}/current.json`,
    };
}

export interface V2ProjectionReceipt {
    document: V2VerifiedRoutingDocument;
    etag: string;
    versionId: string | null;
}

export class V2RoutingProjector {
    constructor(
        private readonly s3: S3Client,
        private readonly bucket: string,
        private readonly signer: V2RoutingSigner
    ) {
        if (bucket.length < 3 || bucket.length > 255)
            throw new Error("invalid routing bucket");
    }

    documentFor(lease: V2PublicationLease): Buffer {
        assertLease(lease);
        const payload: V2RoutingPayload = {
            version: 1,
            purpose: ROUTING_PURPOSE,
            context: ROUTING_CONTEXT,
            audience: "staticdeploy-published-content",
            applicationId: lease.applicationId,
            routingId: lease.routingId,
            host: lease.routingHost,
            generation: lease.generation,
            issuedAt: lease.createdAt.toISOString(),
            operation: lease.operation,
            release:
                lease.releaseId === null
                    ? null
                    : {
                          id: lease.releaseId,
                          manifestDigest: lease.manifestDigest!,
                          objectPrefix: lease.objectPrefix!,
                      },
        };
        if (lease.routingKid === null)
            throw new Error("publication routing key is not bound");
        return this.signer.sign(payload, lease.routingKid);
    }

    async project(
        lease: V2PublicationLease,
        checkpoint: () => Promise<void> = async () => undefined
    ): Promise<V2ProjectionReceipt> {
        const boundary = async <T>(operation: () => Promise<T>): Promise<T> => {
            await checkpoint();
            const result = await operation();
            await checkpoint();
            return result;
        };
        const body = this.documentFor(lease);
        const expected = {
            routingId: lease.routingId,
            applicationId: lease.applicationId,
            host: lease.routingHost,
        };
        const verified = this.signer.verifier.verify(body, expected);
        const keys = routeKeys(lease.routingId, lease.generation);
        if (lease.releaseId !== null) {
            const manifest = await boundary(() =>
                readObject(
                    this.s3,
                    this.bucket,
                    `${lease.objectPrefix}/manifest.json`,
                    V2_OBJECT_LIMITS.maxManifestBytes
                )
            );
            if (manifest === null)
                throw new Error(
                    "READY release manifest is missing before projection"
                );
            parseV2ReleaseManifest(
                manifest.body,
                {
                    sha256: lease.manifestDigest!,
                    size: manifest.body.byteLength,
                },
                lease.applicationId,
                lease.releaseId
            );
        }
        try {
            await boundary(() =>
                this.s3.send(
                    new PutObjectCommand({
                        Bucket: this.bucket,
                        Key: keys.generation,
                        Body: body,
                        ContentLength: body.byteLength,
                        ContentType: "application/json",
                        IfNoneMatch: "*",
                    }),
                    { abortSignal: AbortSignal.timeout(S3_TIMEOUT_MS) }
                )
            );
        } catch (error) {
            if (!preconditionFailed(error)) throw error;
        }
        const generationReadBack = await boundary(() =>
            readObject(this.s3, this.bucket, keys.generation)
        );
        if (
            generationReadBack === null ||
            !generationReadBack.body.equals(body)
        )
            throw new V2ProjectionConflictError(
                "immutable routing generation conflicts"
            );
        this.signer.verifier.verify(generationReadBack.body, expected);

        let readBack: Awaited<ReturnType<typeof readObject>> = null;
        for (let attempt = 0; attempt < 3; attempt += 1) {
            const current = await boundary(() =>
                readObject(this.s3, this.bucket, keys.current)
            );
            if (current !== null) {
                const prior = this.signer.verifier.verify(
                    current.body,
                    expected
                );
                if (prior.payload.generation > lease.generation)
                    throw new V2ProjectionConflictError(
                        "stale publication cannot regress current routing"
                    );
                if (prior.payload.generation === lease.generation) {
                    if (!current.body.equals(body))
                        throw new V2ProjectionConflictError(
                            "same routing generation has conflicting bytes"
                        );
                    if (current.etag === null)
                        throw new V2ProjectionConflictError(
                            "current routing has no opaque ETag"
                        );
                    return {
                        document: verified,
                        etag: current.etag,
                        versionId: current.versionId,
                    };
                }
                if (current.etag === null)
                    throw new V2ProjectionConflictError(
                        "current routing has no conditional identity"
                    );
            }
            try {
                await boundary(() =>
                    this.s3.send(
                        new PutObjectCommand({
                            Bucket: this.bucket,
                            Key: keys.current,
                            Body: body,
                            ContentLength: body.byteLength,
                            ContentType: "application/json",
                            ...(current === null
                                ? { IfNoneMatch: "*" }
                                : { IfMatch: current.etag! }),
                        }),
                        { abortSignal: AbortSignal.timeout(S3_TIMEOUT_MS) }
                    )
                );
                readBack = await boundary(() =>
                    readObject(this.s3, this.bucket, keys.current)
                );
                break;
            } catch (error) {
                if (!preconditionFailed(error) || attempt === 2) {
                    if (preconditionFailed(error))
                        throw new V2ProjectionConflictError();
                    throw error;
                }
            }
        }
        if (readBack === null || !readBack.body.equals(body))
            throw new Error("routing current read-back verification failed");
        const readBackVerified = this.signer.verifier.verify(
            readBack.body,
            expected
        );
        if (readBackVerified.digest !== verified.digest)
            throw new Error(
                "routing current digest read-back verification failed"
            );
        if (readBack.etag === null)
            throw new Error("routing current read-back has no opaque ETag");
        return {
            document: verified,
            etag: readBack.etag,
            versionId: readBack.versionId,
        };
    }
}

export class V2PublicationWorker {
    constructor(
        private readonly queue: V2PublicationQueue,
        private readonly projector: V2RoutingProjector,
        private readonly signer: V2RoutingSigner,
        private readonly leaseMs = 30_000
    ) {
        if (
            !Number.isSafeInteger(leaseMs) ||
            leaseMs < MIN_LEASE_MS ||
            leaseMs > MAX_LEASE_MS
        )
            throw new Error(
                "publication worker lease duration is outside bounds"
            );
    }

    async apply(input: V2PublicationLease): Promise<V2ProjectionReceipt> {
        let lease =
            input.routingKid === null
                ? await this.queue.bindKey(
                      input,
                      this.signer.kidForIssueTime(input.createdAt)
                  )
                : input;
        const checkpoint = async (): Promise<void> => {
            lease = await this.queue.renew(lease, this.leaseMs);
            await this.queue.assertProjectable(lease);
        };
        await checkpoint();
        const receipt = await this.projector.project(lease, checkpoint);
        await checkpoint();
        await this.queue.acknowledge(lease, receipt);
        return receipt;
    }
}

export interface V2ContentRoutingResult {
    document: V2VerifiedRoutingDocument;
    source: "OBJECT" | "LAST_KNOWN_GOOD";
    replayStatus: "ATTESTED" | "COLD_START_UNATTESTED";
}

export class V2ContentRoutingCache {
    private lastKnownGood: V2VerifiedRoutingDocument | null = null;
    private watermark: number | null;
    constructor(
        private readonly s3: S3Client,
        private readonly bucket: string,
        private readonly routingId: string,
        private readonly applicationId: string,
        private readonly host: string,
        private readonly verifier: V2RoutingVerifier,
        minimumGeneration?: number
    ) {
        assertUuid(routingId, "routing id");
        assertUuid(applicationId, "application id");
        normalizeV2RoutingHost(host);
        if (
            minimumGeneration !== undefined &&
            (!Number.isSafeInteger(minimumGeneration) || minimumGeneration < 1)
        )
            throw new Error("invalid routing generation checkpoint");
        this.watermark = minimumGeneration ?? null;
    }
    async refresh(): Promise<V2ContentRoutingResult> {
        try {
            const current = await readObject(
                this.s3,
                this.bucket,
                routeKeys(this.routingId, 1).current
            );
            if (current === null)
                throw new Error("routing current object is missing");
            const verified = this.verifier.verify(current.body, {
                routingId: this.routingId,
                applicationId: this.applicationId,
                host: this.host,
            });
            const immutable = await readObject(
                this.s3,
                this.bucket,
                routeKeys(this.routingId, verified.payload.generation)
                    .generation
            );
            if (immutable === null || !immutable.body.equals(current.body))
                throw new Error(
                    "routing current does not match immutable generation"
                );
            if (verified.payload.release !== null) {
                const manifest = await readObject(
                    this.s3,
                    this.bucket,
                    `${verified.payload.release.objectPrefix}/manifest.json`,
                    8 * 1024 * 1024
                );
                if (
                    manifest === null ||
                    createHash("sha256").update(manifest.body).digest("hex") !==
                        verified.payload.release.manifestDigest
                )
                    throw new Error("routing release manifest digest mismatch");
                parseV2ReleaseManifest(
                    manifest.body,
                    {
                        sha256: verified.payload.release.manifestDigest,
                        size: manifest.body.byteLength,
                    },
                    this.applicationId,
                    verified.payload.release.id
                );
            }
            if (
                this.watermark !== null &&
                verified.payload.generation < this.watermark
            )
                throw new V2RoutingReplayError();
            if (
                this.watermark !== null &&
                verified.payload.generation === this.watermark &&
                this.lastKnownGood !== null &&
                verified.digest !== this.lastKnownGood.digest
            )
                throw new V2ProjectionConflictError(
                    "same routing generation changed bytes"
                );
            const cold = this.watermark === null;
            this.watermark = Math.max(
                this.watermark ?? 0,
                verified.payload.generation
            );
            this.lastKnownGood = verified;
            return {
                document: verified,
                source: "OBJECT",
                replayStatus: cold ? "COLD_START_UNATTESTED" : "ATTESTED",
            };
        } catch (error) {
            if (this.lastKnownGood === null) throw error;
            return {
                document: this.lastKnownGood,
                source: "LAST_KNOWN_GOOD",
                replayStatus: "ATTESTED",
            };
        }
    }
}

export interface V2ProjectionDrift {
    applicationId: string;
    desiredGeneration: number;
    servedGeneration: number;
    objectGeneration: number | null;
    outboxState: string | null;
    repair: "NONE" | "CLAIM_PENDING" | "REPORT_AMBIGUITY";
    reasons: string[];
}

/**
 * One shared reconciliation query for the Knex runtime and raw-pg benchmark.
 * The placeholder is deliberately closed so it cannot become SQL input.
 */
export function v2ProjectionReconciliationSql(placeholder: "?" | "$1"): string {
    if (placeholder !== "?" && placeholder !== "$1")
        throw new Error("unsupported reconciliation SQL placeholder");
    return `
        SELECT application.id, application.routing_id,
               application.desired_generation, application.served_generation,
               application.desired_current_release_id,
               application.served_current_release_id, outbox.state,
               outbox.projection_digest, outbox.acknowledged_etag,
               outbox.acknowledged_version_id, outbox.generation,
               outbox.operation, outbox.routing_kid, outbox.routing_host,
               outbox.manifest_digest, outbox.object_prefix, outbox.release_id,
               outbox.id AS outbox_id,
               (SELECT count(*)::text FROM public.v2_publication_outbox stale
                 WHERE stale.application_id = application.id
                   AND stale.generation < application.desired_generation
                   AND stale.state IN ('PENDING','LEASED')) AS superseded_count
          FROM public.v2_applications application
          LEFT JOIN public.v2_publication_outbox outbox
            ON outbox.application_id = application.id
           AND outbox.generation = application.desired_generation
         WHERE application.id = ${placeholder}`;
}

export class V2ProjectionReconciler {
    constructor(
        private readonly knex: Knex,
        private readonly s3: S3Client,
        private readonly bucket: string,
        private readonly verifier: V2RoutingVerifier
    ) {}
    async inspect(
        applicationId: string,
        expectedHost: string
    ): Promise<V2ProjectionDrift> {
        assertUuid(applicationId, "application id");
        normalizeV2RoutingHost(expectedHost);
        const result = await this.knex.transaction(async (transaction) => {
            await transaction.raw("SET LOCAL lock_timeout = '5s'");
            await transaction.raw("SET LOCAL statement_timeout = '30s'");
            return rows<{
                id: string;
                routing_id: string;
                desired_generation: string | number;
                served_generation: string | number;
                desired_current_release_id: string | null;
                served_current_release_id: string | null;
                state: string | null;
                projection_digest: string | null;
                acknowledged_etag: string | null;
                acknowledged_version_id: string | null;
                generation: string | number | null;
                operation: V2PublicationOperation | null;
                routing_kid: string | null;
                routing_host: string | null;
                manifest_digest: string | null;
                object_prefix: string | null;
                release_id: string | null;
                superseded_count: string;
                outbox_id: string | null;
            }>(
                await transaction.raw(v2ProjectionReconciliationSql("?"), [
                    applicationId,
                ])
            )[0];
        });
        if (result === undefined) throw new Error("application not found");
        const current = await readObject(
            this.s3,
            this.bucket,
            routeKeys(result.routing_id, 1).current
        );
        let objectGeneration: number | null = null;
        const reasons: string[] = [];
        if (current !== null) {
            try {
                const document = this.verifier.verify(current.body, {
                    routingId: result.routing_id,
                    applicationId,
                    host: expectedHost,
                });
                objectGeneration = document.payload.generation;
                const immutable = await readObject(
                    this.s3,
                    this.bucket,
                    routeKeys(result.routing_id, objectGeneration).generation
                );
                if (immutable === null) reasons.push("GENERATION_MISSING");
                else if (!immutable.body.equals(current.body))
                    reasons.push("GENERATION_MISMATCH");
                if (document.payload.release !== null) {
                    const manifest = await readObject(
                        this.s3,
                        this.bucket,
                        `${document.payload.release.objectPrefix}/manifest.json`,
                        8 * 1024 * 1024
                    );
                    if (manifest === null) reasons.push("MANIFEST_MISSING");
                    else {
                        try {
                            parseV2ReleaseManifest(
                                manifest.body,
                                {
                                    sha256: document.payload.release
                                        .manifestDigest,
                                    size: manifest.body.byteLength,
                                },
                                applicationId,
                                document.payload.release.id
                            );
                        } catch {
                            reasons.push("MANIFEST_MISMATCH");
                        }
                    }
                }
                if (
                    document.payload.release?.id !==
                    result.desired_current_release_id
                )
                    reasons.push("DESIRED_RELEASE_DRIFT");
                if (
                    result.generation !== null &&
                    document.payload.generation !== Number(result.generation)
                )
                    reasons.push("OUTBOX_GENERATION_DRIFT");
                if (
                    result.operation !== null &&
                    document.payload.operation !== result.operation
                )
                    reasons.push("OUTBOX_OPERATION_DRIFT");
                if (
                    result.routing_kid !== null &&
                    document.kid !== result.routing_kid
                )
                    reasons.push("OUTBOX_KEY_DRIFT");
                if (
                    result.routing_host !== null &&
                    document.payload.host !== result.routing_host
                )
                    reasons.push("OUTBOX_HOST_DRIFT");
                if (
                    (document.payload.release?.manifestDigest ?? null) !==
                    result.manifest_digest
                )
                    reasons.push("OUTBOX_MANIFEST_DRIFT");
                if (
                    (document.payload.release?.objectPrefix ?? null) !==
                    result.object_prefix
                )
                    reasons.push("OUTBOX_PREFIX_DRIFT");
                if (
                    (document.payload.release?.id ?? null) !== result.release_id
                )
                    reasons.push("OUTBOX_RELEASE_DRIFT");
                if (
                    result.state === "ACKNOWLEDGED" &&
                    (current.etag !== result.acknowledged_etag ||
                        document.digest !== result.projection_digest)
                )
                    reasons.push("ACKNOWLEDGED_IDENTITY_DRIFT");
                if (
                    result.acknowledged_version_id === null ||
                    current.versionId === null
                ) {
                    reasons.push("VERSION_HISTORY_UNATTESTABLE");
                    reasons.push("ORPHAN_GENERATION_UNATTESTABLE");
                } else if (current.versionId !== result.acknowledged_version_id)
                    reasons.push("VERSION_ID_DRIFT");
            } catch {
                reasons.push("OBJECT_INVALID");
            }
        } else reasons.push("OBJECT_MISSING");
        if (Number(result.superseded_count) > 0)
            reasons.push("SUPERSEDED_OPERATION");
        const desired = Number(result.desired_generation);
        const served = Number(result.served_generation);
        if (desired !== served) reasons.push("DATABASE_PROJECTION_LAG");
        if (objectGeneration !== served) reasons.push("SERVED_OBJECT_DRIFT");
        if (
            result.desired_current_release_id !==
                result.served_current_release_id &&
            desired === served
        )
            reasons.push("SERVED_RELEASE_DRIFT");
        if (objectGeneration !== desired) reasons.push("DESIRED_OBJECT_DRIFT");
        const safelyClaimableReasons = new Set([
            "OBJECT_MISSING",
            "DATABASE_PROJECTION_LAG",
            "SERVED_OBJECT_DRIFT",
            "DESIRED_OBJECT_DRIFT",
        ]);
        const safelyClaimable =
            result.state === "PENDING" &&
            reasons.every((reason) => safelyClaimableReasons.has(reason));
        const repair = safelyClaimable
            ? "CLAIM_PENDING"
            : reasons.length === 0
              ? "NONE"
              : "REPORT_AMBIGUITY";
        return {
            applicationId,
            desiredGeneration: desired,
            servedGeneration: served,
            objectGeneration,
            outboxState: result.state,
            repair,
            reasons,
        };
    }
}
