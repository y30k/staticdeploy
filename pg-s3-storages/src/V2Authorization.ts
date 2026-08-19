import {
    IV2AuthorizationStorage,
    IV2RequestPrincipal,
    V2_CAPABILITIES,
    V2Capability,
    V2EffectiveRole,
    V2_ROLE_CAPABILITIES,
} from "@staticdeploy/core";
import { createHash, randomUUID } from "node:crypto";
import { Knex } from "knex";

import { createPostgresKnex } from "./postgres";
import { V2AuthenticatedSession } from "./V2Sessions";

export { V2_CAPABILITIES, V2_ROLE_CAPABILITIES };
export type { V2Capability, V2EffectiveRole };
export type V2BindingRole = "OWNER" | "PUBLISHER" | "VIEWER";

export interface V2AuthorizationOptions {
    administratorGroupIds: string[];
    requiredClaimsVersion: number;
}
export type V2Actor = IV2RequestPrincipal;
export interface V2AuthorizationDecision {
    allowed: boolean;
    effectiveRole: V2EffectiveRole;
    source:
        | "ADMINISTRATOR_GROUP"
        | "APPLICATION_BINDING"
        | "STALE_CLAIMS"
        | "NONE";
    bindingVersion: number | null;
}
export interface V2DesiredBinding {
    groupId: string;
    role: V2BindingRole;
}
export interface V2BindingReplacementResult {
    outcome: "APPLIED" | "DENIED" | "VERSION_CONFLICT";
    resultingVersion: number | null;
    resultDigest: string | null;
    effectiveRole: V2EffectiveRole;
    source: string;
}
const UUID =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const validGroupId = (value: string): boolean =>
    value.length >= 1 &&
    value.length <= 512 &&
    ![...value].some((character) => {
        const code = character.codePointAt(0)!;
        return code <= 31 || code === 127;
    });
const DIGEST = /^[0-9a-f]{64}$/;

const stableGroups = (groups: unknown): string[] => {
    if (
        !Array.isArray(groups) ||
        groups.length > 256 ||
        groups.some(
            (group) =>
                typeof group !== "string" ||
                !validGroupId(group) ||
                group.trim() !== group
        )
    )
        throw new Error("invalid stable group identifiers");
    const result = [...new Set(groups)].sort((left, right) =>
        Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"))
    );
    if (result.length !== groups.length)
        throw new Error("stable group identifiers must be unique");
    return result;
};

const bindingId = (applicationId: string, groupId: string): string => {
    const bytes = createHash("sha256")
        .update(`staticdeploy-v2-binding\0${applicationId}\0${groupId}`, "utf8")
        .digest()
        .subarray(0, 16);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = bytes.toString("hex");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(
        12,
        16
    )}-${hex.slice(16, 20)}-${hex.slice(20)}`;
};

export const actorFromSession = (session: V2AuthenticatedSession): V2Actor => ({
    sessionId: session.id,
    subjectId: session.subjectId,
    issuer: session.issuer,
    groups: stableGroups(session.claims.groups ?? []),
    claimsVersion: session.claimsVersion,
});

export class V2Authorization implements IV2AuthorizationStorage {
    private readonly administratorGroups: string[];
    private readonly requiredClaimsVersion: number;
    private readonly configurationDigest: string;

    constructor(
        private readonly database: Knex,
        options: V2AuthorizationOptions,
        private readonly destroyDatabase?: () => Promise<void>
    ) {
        this.administratorGroups = stableGroups(options.administratorGroupIds);
        if (
            this.administratorGroups.length > 32 ||
            options.requiredClaimsVersion !== 1
        )
            throw new Error("invalid authorization policy configuration");
        this.requiredClaimsVersion = options.requiredClaimsVersion;
        this.configurationDigest = createHash("sha256")
            .update(
                JSON.stringify({
                    administratorGroupIds: this.administratorGroups,
                    requiredClaimsVersion: this.requiredClaimsVersion,
                }),
                "utf8"
            )
            .digest("hex");
    }

    async destroy(): Promise<void> {
        await this.destroyDatabase?.();
    }

    async verifyReady(): Promise<void> {
        const result = await this.database.raw(`
            SELECT r.rolsuper, r.rolbypassrls, r.rolcreaterole,
                r.rolcreatedb, r.rolreplication,
                EXISTS (
                    SELECT 1 FROM pg_namespace n
                     WHERE n.nspname <> 'information_schema'
                       AND n.nspname !~ '^pg_(catalog|toast|temp_|toasted_temp_)'
                       AND (n.nspowner = r.oid OR
                            has_schema_privilege(current_user, n.oid, 'CREATE'))
                ) AS unsafe_schema,
                has_database_privilege(current_user, current_database(), 'CREATE') AS database_create,
                EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member = r.oid) AS has_memberships,
                EXISTS (
                    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                     WHERE n.nspname <> 'information_schema'
                       AND n.nspname !~ '^pg_(catalog|toast|temp_|toasted_temp_)'
                       AND c.relowner = r.oid
                ) OR EXISTS (
                    SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                     WHERE n.nspname <> 'information_schema'
                       AND n.nspname !~ '^pg_(catalog|toast|temp_|toasted_temp_)'
                       AND p.proowner = r.oid
                ) OR EXISTS (
                    SELECT 1 FROM pg_database d
                     WHERE d.datname = current_database() AND d.datdba = r.oid
                ) AS owns_runtime_objects,
                EXISTS (
                    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                     WHERE n.nspname <> 'information_schema'
                       AND n.nspname !~ '^pg_(catalog|toast|temp_|toasted_temp_)'
                       AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
                       AND (has_table_privilege(current_user, c.oid,
                            'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                         OR has_any_column_privilege(current_user, c.oid,
                            'SELECT,INSERT,UPDATE,REFERENCES'))
                ) AS direct_table,
                EXISTS (
                    SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                     WHERE n.nspname <> 'information_schema'
                       AND n.nspname !~ '^pg_(catalog|toast|temp_|toasted_temp_)'
                       AND p.prosecdef
                       AND p.prorettype NOT IN ('trigger'::regtype, 'event_trigger'::regtype)
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
                ) AS unrelated_definer_execute,
                has_function_privilege(current_user,
                    'public.v2_initialize_authorization_policy(text[],bigint,text)',
                    'EXECUTE') AS initialize_ok,
                has_function_privilege(current_user,
                    'public.v2_authorization_policy_identity()',
                    'EXECUTE') AS policy_ok,
                has_function_privilege(current_user,
                    'public.v2_authorize_operation(uuid,uuid,text[],bigint,uuid,text)',
                    'EXECUTE') AS authorize_ok,
                has_function_privilege(current_user,
                    'public.v2_replace_bindings(uuid,uuid,text[],bigint,uuid,bigint,text,text,jsonb)',
                    'EXECUTE') AS replace_ok
              FROM pg_roles r WHERE r.rolname = current_user
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
            row.direct_table ||
            row.unrelated_definer_execute ||
            !row.initialize_ok ||
            !row.policy_ok ||
            !row.authorize_ok ||
            !row.replace_ok
        )
            throw new Error(
                "authorization PostgreSQL runtime identity is not least privilege"
            );
        await this.database.raw(
            "select public.v2_initialize_authorization_policy(?, ?, ?)",
            [
                this.administratorGroups,
                this.requiredClaimsVersion,
                this.configurationDigest,
            ]
        );
        const identity = (
            await this.database.raw(
                "select (public.v2_authorization_policy_identity()).*"
            )
        ).rows[0];
        if (
            identity === undefined ||
            JSON.stringify(identity.administrator_groups) !==
                JSON.stringify(this.administratorGroups) ||
            Number(identity.required_claims_version) !==
                this.requiredClaimsVersion ||
            identity.configuration_digest !== this.configurationDigest
        )
            throw new Error("authorization policy configuration mismatch");
    }

    async authorize(
        actor: V2Actor,
        applicationId: string,
        capability: V2Capability
    ): Promise<V2AuthorizationDecision> {
        if (capability === "APPLICATION_CREATE")
            throw new Error("application creation is a platform operation");
        return this.authorizeWith(
            this.database,
            actor,
            applicationId,
            capability
        );
    }

    async authorizeApplicationCreate(
        actor: V2Actor
    ): Promise<V2AuthorizationDecision> {
        return this.authorizeWith(
            this.database,
            actor,
            null,
            "APPLICATION_CREATE"
        );
    }

    private async authorizeWith(
        database: Knex,
        actor: V2Actor,
        applicationId: string | null,
        capability: V2Capability
    ): Promise<V2AuthorizationDecision> {
        this.validateActor(actor);
        if (
            !V2_CAPABILITIES.includes(capability) ||
            (capability === "APPLICATION_CREATE"
                ? applicationId !== null
                : applicationId === null || !UUID.test(applicationId))
        )
            throw new Error("invalid authorization target");
        const result = await database.raw(
            "select * from public.v2_authorize_operation(?, ?, ?, ?, ?, ?)",
            [
                randomUUID(),
                actor.sessionId,
                actor.groups,
                actor.claimsVersion,
                applicationId,
                capability,
            ]
        );
        const row = result.rows[0];
        return {
            allowed: row.allowed,
            effectiveRole: row.effective_role,
            source: row.role_source,
            bindingVersion:
                row.binding_version === null
                    ? null
                    : Number(row.binding_version),
        };
    }

    async replaceBindings(input: {
        actor: V2Actor;
        applicationId: string;
        expectedVersion: number;
        idempotencyKey: string;
        bindings: V2DesiredBinding[];
    }): Promise<V2BindingReplacementResult> {
        this.validateActor(input.actor);
        if (
            !UUID.test(input.applicationId) ||
            !Number.isSafeInteger(input.expectedVersion) ||
            input.expectedVersion < 1 ||
            input.idempotencyKey.length < 1 ||
            input.idempotencyKey.length > 200 ||
            input.bindings.length > 256
        )
            throw new Error("invalid binding replacement");
        const bindings = input.bindings
            .map((binding) => {
                if (
                    !validGroupId(binding.groupId) ||
                    binding.groupId.trim() !== binding.groupId ||
                    !["OWNER", "PUBLISHER", "VIEWER"].includes(binding.role)
                )
                    throw new Error("invalid binding replacement");
                return { groupId: binding.groupId, role: binding.role };
            })
            .sort((left, right) =>
                Buffer.compare(
                    Buffer.from(left.groupId, "utf8"),
                    Buffer.from(right.groupId, "utf8")
                )
            );
        if (
            new Set(bindings.map(({ groupId }) => groupId)).size !==
            bindings.length
        )
            throw new Error("binding group identifiers must be unique");
        const canonical = JSON.stringify({
            applicationId: input.applicationId,
            expectedVersion: input.expectedVersion,
            bindings,
        });
        const requestDigest = createHash("sha256")
            .update(canonical, "utf8")
            .digest("hex");
        const desired = bindings.map((binding) => ({
            id: bindingId(input.applicationId, binding.groupId),
            ...binding,
        }));
        const result = await this.database.raw(
            "select * from public.v2_replace_bindings(?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb)",
            [
                randomUUID(),
                input.actor.sessionId,
                input.actor.groups,
                input.actor.claimsVersion,
                input.applicationId,
                input.expectedVersion,
                input.idempotencyKey,
                requestDigest,
                JSON.stringify(desired),
            ]
        );
        const row = result.rows[0];
        if (
            (row.outcome === "DENIED" && row.result_digest !== null) ||
            (row.outcome !== "DENIED" && !DIGEST.test(row.result_digest))
        )
            throw new Error("invalid binding replacement result");
        return {
            outcome: row.outcome,
            resultingVersion:
                row.resulting_version === null
                    ? null
                    : Number(row.resulting_version),
            resultDigest: row.result_digest,
            effectiveRole: row.effective_role,
            source: row.role_source,
        };
    }

    private validateActor(actor: V2Actor): void {
        if (
            !UUID.test(actor.sessionId) ||
            actor.subjectId.length < 1 ||
            actor.subjectId.length > 512 ||
            actor.issuer.length < 1 ||
            actor.issuer.length > 2048 ||
            !Number.isSafeInteger(actor.claimsVersion) ||
            actor.claimsVersion < 1
        )
            throw new Error("invalid authorization actor");
        stableGroups(actor.groups);
    }
}

export function createV2Authorization(
    postgresUrl: string,
    options: V2AuthorizationOptions
): V2Authorization {
    const database = createPostgresKnex(postgresUrl);
    return new V2Authorization(database, options, () => database.destroy());
}
