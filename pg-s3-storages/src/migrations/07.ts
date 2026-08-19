import { V2_CAPABILITIES, V2_ROLE_CAPABILITIES } from "@staticdeploy/core";
import { Knex } from "knex";

import tables from "../common/tables";

const sqlList = (values: readonly string[]): string =>
    values.map((value) => `'${value}'`).join(", ");
const capabilitySql = sqlList(V2_CAPABILITIES);
const ownerCapabilitySql = sqlList(V2_ROLE_CAPABILITIES.OWNER);
const publisherCapabilitySql = sqlList(V2_ROLE_CAPABILITIES.PUBLISHER);
const viewerCapabilitySql = sqlList(V2_ROLE_CAPABILITIES.VIEWER);

/* Add the fenced v2 authorization/binding policy without changing legacy data. */
export async function up(knex: Knex): Promise<void> {
    await knex.raw(`
        ALTER TABLE public.${tables.v2Applications}
            ADD COLUMN binding_version bigint NOT NULL DEFAULT 1,
            ADD CONSTRAINT v2_applications_binding_version_check
                CHECK (binding_version > 0);

        CREATE TABLE public.v2_binding_requests (
            application_id uuid NOT NULL,
            idempotency_key text NOT NULL,
            actor_id text NOT NULL,
            request_digest text NOT NULL,
            expected_version bigint NOT NULL,
            outcome text NOT NULL,
            resulting_version bigint NOT NULL,
            result_digest text NOT NULL,
            created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
            PRIMARY KEY (application_id, actor_id, idempotency_key),
            FOREIGN KEY (application_id)
                REFERENCES public.${tables.v2Applications}(id)
                ON DELETE RESTRICT,
            CHECK (char_length(idempotency_key) BETWEEN 1 AND 200),
            CHECK (char_length(actor_id) BETWEEN 1 AND 512),
            CHECK (request_digest ~ '^[0-9a-f]{64}$'),
            CHECK (expected_version > 0 AND resulting_version > 0),
            CHECK (outcome IN ('APPLIED', 'DENIED', 'VERSION_CONFLICT')),
            CHECK (result_digest ~ '^[0-9a-f]{64}$')
        );
        REVOKE ALL ON public.v2_binding_requests FROM PUBLIC;

        CREATE TABLE public.v2_authorization_policy (
            singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
            administrator_groups text[] NOT NULL,
            required_claims_version bigint NOT NULL CHECK (required_claims_version > 0),
            configuration_digest text NOT NULL CHECK (configuration_digest ~ '^[0-9a-f]{64}$'),
            CHECK (cardinality(administrator_groups) BETWEEN 1 AND 32),
            CHECK (array_position(administrator_groups, NULL) IS NULL)
        );
        REVOKE ALL ON public.v2_authorization_policy FROM PUBLIC;

        CREATE INDEX v2_binding_requests_actor_time_idx
            ON public.v2_binding_requests (actor_id, created_at DESC, application_id);
        CREATE INDEX v2_bindings_application_role_group_idx
            ON public.${tables.v2Bindings} (application_id, role, group_id);

        CREATE OR REPLACE FUNCTION public.v2_guard_audit_event()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $function$
        BEGIN
            IF TG_OP = 'INSERT' THEN
                IF octet_length(NEW.metadata::text) > 4096
                    OR NEW.action NOT IN (
                        'AUTH_LOGIN', 'AUTH_LOGOUT', 'AUTH_SESSION_REVOKED',
                        'AUTHENTICATION_SUCCEEDED', 'AUTHORIZATION_DECISION',
                        'APPLICATION_CREATED', 'APPLICATION_VIEWED',
                        'RELEASE_READY', 'RELEASE_LISTED', 'AUDIT_VIEWED',
                        'BINDINGS_REPLACE'
                    )
                    OR (SELECT count(*) FROM jsonb_object_keys(NEW.metadata)) > 12
                    OR EXISTS (
                        SELECT 1 FROM jsonb_each(NEW.metadata) entry
                         WHERE entry.key NOT IN (
                            'issuer', 'operation', 'result', 'reason', 'role',
                            'source', 'objectKind', 'bindingVersion',
                            'requestDigest', 'bindingCount', 'eventVersion',
                            'claimsVersion', 'policyVersion', 'objectId'
                         )
                            OR jsonb_typeof(entry.value) IN ('array', 'object', 'null')
                            OR (entry.key IN ('issuer', 'objectId') AND (
                                jsonb_typeof(entry.value) <> 'string'
                                OR char_length(entry.value #>> '{}') > 2048
                            ))
                            OR (entry.key = 'requestDigest' AND (
                                jsonb_typeof(entry.value) <> 'string'
                                OR entry.value #>> '{}' !~ '^[0-9a-f]{64}$'
                            ))
                            OR (entry.key IN (
                                'bindingVersion', 'eventVersion',
                                'claimsVersion', 'policyVersion'
                            ) AND (
                                jsonb_typeof(entry.value) <> 'number'
                                OR entry.value #>> '{}' !~ '^[1-9][0-9]{0,18}$'
                                OR (entry.value #>> '{}')::numeric > 9223372036854775807
                            ))
                            OR (entry.key = 'bindingCount' AND (
                                jsonb_typeof(entry.value) <> 'number'
                                OR entry.value #>> '{}' !~ '^(0|[1-9][0-9]{0,2})$'
                                OR (entry.value #>> '{}')::integer > 256
                            ))
                            OR (entry.key = 'result' AND entry.value #>> '{}' NOT IN
                                ('ALLOWED', 'DENIED', 'APPLIED', 'VERSION_CONFLICT', 'SUCCESS'))
                            OR (entry.key = 'role' AND entry.value #>> '{}' NOT IN
                                ('ADMINISTRATOR', 'OWNER', 'PUBLISHER', 'VIEWER', 'DENIED'))
                            OR (entry.key = 'source' AND entry.value #>> '{}' NOT IN
                                ('ADMINISTRATOR_GROUP', 'APPLICATION_BINDING', 'STALE_CLAIMS', 'NONE'))
                            OR (entry.key = 'objectKind' AND entry.value #>> '{}' NOT IN
                                ('APPLICATION', 'BINDINGS', 'SESSION'))
                            OR (entry.key = 'reason' AND entry.value #>> '{}' NOT IN
                                ('USER_LOGOUT', 'SESSION_ROTATED', 'TOKEN_KEY_REVOKED',
                                 'NOT_AUTHORIZED', 'STALE_CLAIMS'))
                            OR (entry.key = 'operation'
                                AND entry.value #>> '{}' NOT IN (${capabilitySql}))
                    )
                THEN
                    RAISE EXCEPTION 'audit metadata exceeds the safe allowlist'
                        USING ERRCODE = '22023';
                END IF;
                RETURN NEW;
            END IF;
            RAISE EXCEPTION 'audit events are append-only'
                USING ERRCODE = '55000';
        END;
        $function$;
        DROP TRIGGER v2_audit_events_append_only
            ON public.${tables.v2AuditEvents};
        CREATE TRIGGER v2_audit_events_append_only
            BEFORE INSERT OR UPDATE OR DELETE ON public.${tables.v2AuditEvents}
            FOR EACH ROW EXECUTE FUNCTION public.v2_guard_audit_event();
        ALTER TABLE public.${tables.v2AuditEvents}
            ADD CONSTRAINT v2_audit_events_closed_action_check CHECK (action IN (
                'AUTH_LOGIN', 'AUTH_LOGOUT', 'AUTH_SESSION_REVOKED',
                'AUTHENTICATION_SUCCEEDED', 'AUTHORIZATION_DECISION',
                'APPLICATION_CREATED', 'APPLICATION_VIEWED', 'RELEASE_READY',
                'RELEASE_LISTED', 'AUDIT_VIEWED', 'BINDINGS_REPLACE'
            ));

        CREATE OR REPLACE FUNCTION public.v2_create_or_replace_session(
            replaced_session_id uuid,
            session_id uuid,
            requested_subject_id text,
            requested_issuer text,
            requested_claims jsonb,
            requested_csrf_digest text,
            requested_token_key_id text,
            requested_token_nonce bytea,
            requested_encrypted_tokens bytea,
            idle_lifetime_ms integer,
            absolute_lifetime_ms integer
        ) RETURNS void
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        SET lock_timeout = '5s'
        SET statement_timeout = '10s'
        AS $function$
        DECLARE observed_at timestamptz;
        DECLARE replaced public.${tables.v2Sessions}%ROWTYPE;
        BEGIN
            IF session_id IS NULL OR requested_subject_id IS NULL
                OR requested_issuer IS NULL OR requested_claims IS NULL
                OR requested_csrf_digest IS NULL
                OR requested_token_key_id IS NULL
                OR requested_token_nonce IS NULL
                OR requested_encrypted_tokens IS NULL
                OR idle_lifetime_ms IS NULL OR absolute_lifetime_ms IS NULL
                OR idle_lifetime_ms < 1000 OR idle_lifetime_ms > 86400000
                OR absolute_lifetime_ms < idle_lifetime_ms
                OR absolute_lifetime_ms > 604800000
            THEN
                RAISE EXCEPTION 'invalid session bounds' USING ERRCODE = '22023';
            END IF;
            IF replaced_session_id IS NOT NULL THEN
                SELECT * INTO replaced FROM public.${tables.v2Sessions}
                 WHERE id = replaced_session_id FOR UPDATE;
                observed_at := clock_timestamp();
                IF NOT FOUND OR replaced.revoked_at IS NOT NULL
                    OR replaced.idle_expires_at <= observed_at
                    OR replaced.absolute_expires_at <= observed_at
                THEN
                    RAISE EXCEPTION 'replacement session is no longer active'
                        USING ERRCODE = '40001';
                END IF;
            ELSE
                observed_at := clock_timestamp();
            END IF;

            INSERT INTO public.${tables.v2Sessions} (
                id, subject_id, issuer, claims, csrf_token_digest,
                token_key_id, token_nonce, encrypted_token_material,
                created_at, last_seen_at, idle_expires_at, absolute_expires_at
            ) VALUES (
                session_id, requested_subject_id, requested_issuer,
                requested_claims, requested_csrf_digest,
                requested_token_key_id, requested_token_nonce,
                requested_encrypted_tokens, observed_at, observed_at,
                observed_at + make_interval(secs => idle_lifetime_ms / 1000.0),
                observed_at + make_interval(secs => absolute_lifetime_ms / 1000.0)
            );
            IF replaced_session_id IS NOT NULL THEN
                UPDATE public.${tables.v2Sessions}
                   SET revoked_at = observed_at,
                       revocation_reason = 'SESSION_ROTATED'
                 WHERE id = replaced_session_id;
            END IF;
            INSERT INTO public.${tables.v2AuditEvents} (
                id, actor_id, action, metadata, occurred_at
            ) VALUES (
                gen_random_uuid(), 'oidc:' || encode(sha256(convert_to(
                    char_length(requested_issuer)::text || ':' || requested_issuer ||
                    char_length(requested_subject_id)::text || ':' || requested_subject_id,
                    'UTF8'
                )), 'hex'), 'AUTH_LOGIN',
                jsonb_build_object('issuer', requested_issuer, 'objectKind', 'SESSION',
                    'result', 'SUCCESS'),
                observed_at
            );
        END;
        $function$;
        REVOKE ALL ON FUNCTION public.v2_create_or_replace_session(
            uuid, uuid, text, text, jsonb, text, text, bytea, bytea,
            integer, integer
        ) FROM PUBLIC;

        CREATE OR REPLACE FUNCTION public.v2_revoke_session(session_id uuid, reason text)
        RETURNS boolean
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        SET lock_timeout = '5s'
        SET statement_timeout = '10s'
        AS $function$
        DECLARE observed_at timestamptz;
        DECLARE actor text;
        DECLARE actor_issuer text;
        BEGIN
            IF session_id IS NULL OR reason IS NULL
                OR reason !~ '^[A-Z][A-Z0-9_]{0,127}$'
            THEN
                RAISE EXCEPTION 'invalid revocation request' USING ERRCODE = '22023';
            END IF;
            SELECT subject_id, issuer INTO actor, actor_issuer FROM public.${tables.v2Sessions}
             WHERE id = session_id FOR UPDATE;
            observed_at := clock_timestamp();
            UPDATE public.${tables.v2Sessions}
               SET revoked_at = observed_at, revocation_reason = reason
             WHERE id = session_id AND revoked_at IS NULL
               AND idle_expires_at > observed_at
               AND absolute_expires_at > observed_at;
            IF FOUND THEN
                INSERT INTO public.${tables.v2AuditEvents} (
                    id, actor_id, action, metadata, occurred_at
                ) VALUES (
                    gen_random_uuid(), 'oidc:' || encode(sha256(convert_to(
                        char_length(actor_issuer)::text || ':' || actor_issuer ||
                        char_length(actor)::text || ':' || actor, 'UTF8'
                    )), 'hex'),
                    CASE WHEN reason = 'USER_LOGOUT'
                        THEN 'AUTH_LOGOUT' ELSE 'AUTH_SESSION_REVOKED' END,
                    jsonb_build_object('objectKind', 'SESSION', 'reason', reason, 'result', 'SUCCESS'),
                    observed_at
                );
                RETURN true;
            END IF;
            RETURN false;
        END;
        $function$;
        REVOKE ALL ON FUNCTION public.v2_revoke_session(uuid, text) FROM PUBLIC;

        CREATE FUNCTION public.v2_initialize_authorization_policy(
            requested_administrator_groups text[],
            requested_claims_version bigint,
            requested_configuration_digest text
        ) RETURNS void
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        SET lock_timeout = '5s'
        SET statement_timeout = '10s'
        AS $function$
        DECLARE current_policy public.v2_authorization_policy%ROWTYPE;
        DECLARE canonical_groups text[];
        BEGIN
            SELECT array_agg(value ORDER BY value COLLATE "C") INTO canonical_groups
              FROM unnest(requested_administrator_groups) value;
            IF requested_claims_version IS DISTINCT FROM 1
                OR requested_configuration_digest IS NULL
                OR requested_configuration_digest !~ '^[0-9a-f]{64}$'
                OR cardinality(requested_administrator_groups) NOT BETWEEN 1 AND 32
                OR cardinality(requested_administrator_groups) IS DISTINCT FROM
                    (SELECT count(DISTINCT value) FROM unnest(requested_administrator_groups) value)
                OR EXISTS (
                    SELECT 1 FROM unnest(requested_administrator_groups) value
                     WHERE value IS NULL OR char_length(value) NOT BETWEEN 1 AND 512
                        OR value ~ '[[:cntrl:]]' OR btrim(value) <> value
                )
                OR canonical_groups IS DISTINCT FROM requested_administrator_groups
            THEN
                RAISE EXCEPTION 'invalid authorization policy'
                    USING ERRCODE = '22023';
            END IF;
            PERFORM pg_advisory_xact_lock(
                hashtextextended('staticdeploy-v2-authorization-policy', 0)
            );
            SELECT * INTO current_policy FROM public.v2_authorization_policy
             WHERE singleton = true FOR UPDATE;
            IF NOT FOUND THEN
                INSERT INTO public.v2_authorization_policy (
                    singleton, administrator_groups, required_claims_version,
                    configuration_digest
                ) VALUES (
                    true, requested_administrator_groups,
                    requested_claims_version, requested_configuration_digest
                );
            ELSIF current_policy.administrator_groups IS DISTINCT FROM requested_administrator_groups
                OR current_policy.required_claims_version IS DISTINCT FROM requested_claims_version
                OR current_policy.configuration_digest IS DISTINCT FROM requested_configuration_digest
            THEN
                RAISE EXCEPTION 'authorization policy conflicts with immutable configuration'
                    USING ERRCODE = '55000';
            END IF;
        END;
        $function$;
        REVOKE ALL ON FUNCTION public.v2_initialize_authorization_policy(
            text[], bigint, text
        ) FROM PUBLIC;

        CREATE FUNCTION public.v2_authorization_policy_identity()
        RETURNS public.v2_authorization_policy
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog
        AS $function$
            SELECT * FROM public.v2_authorization_policy WHERE singleton = true
        $function$;
        REVOKE ALL ON FUNCTION public.v2_authorization_policy_identity()
            FROM PUBLIC;

        CREATE FUNCTION public.v2_authorize_operation(
            audit_id uuid,
            actor_session_id uuid,
            actor_groups text[],
            actor_claims_version bigint,
            target_application_id uuid,
            requested_operation text
        ) RETURNS TABLE (
            allowed boolean,
            effective_role text,
            role_source text,
            binding_version bigint
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        SET lock_timeout = '5s'
        SET statement_timeout = '10s'
        AS $function$
        DECLARE application_exists boolean := false;
        DECLARE role_rank integer := 0;
        DECLARE observed_at timestamptz;
        DECLARE session_row public.${tables.v2Sessions}%ROWTYPE;
        DECLARE audit_actor_id text;
        DECLARE policy public.v2_authorization_policy%ROWTYPE;
        BEGIN
            SELECT * INTO policy FROM public.v2_authorization_policy
             WHERE singleton = true FOR SHARE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'authorization policy is not provisioned'
                    USING ERRCODE = '55000';
            END IF;
            IF audit_id IS NULL OR actor_session_id IS NULL
                OR actor_groups IS NULL OR cardinality(actor_groups) > 256
                OR actor_claims_version IS NULL OR actor_claims_version < 1
                OR requested_operation IS NULL
                OR requested_operation NOT IN (${capabilitySql})
                OR (requested_operation = 'APPLICATION_CREATE') IS DISTINCT FROM
                   (target_application_id IS NULL)
                OR EXISTS (
                    SELECT 1 FROM unnest(actor_groups || policy.administrator_groups) value
                     WHERE value IS NULL OR char_length(value) NOT BETWEEN 1 AND 512
                        OR value ~ '[[:cntrl:]]' OR btrim(value) <> value
                )
                OR cardinality(actor_groups) <> (
                    SELECT count(DISTINCT value) FROM unnest(actor_groups) value
                )
            THEN
                RAISE EXCEPTION 'invalid authorization request'
                    USING ERRCODE = '22023';
            END IF;

            observed_at := clock_timestamp();
            SELECT * INTO session_row FROM public.${tables.v2Sessions}
             WHERE id = actor_session_id FOR SHARE;
            IF NOT FOUND OR session_row.claims_version IS DISTINCT FROM actor_claims_version
                OR session_row.revoked_at IS NOT NULL
                OR session_row.idle_expires_at <= observed_at
                OR session_row.absolute_expires_at <= observed_at
                OR jsonb_array_length(COALESCE(session_row.claims->'groups', '[]'::jsonb))
                    IS DISTINCT FROM cardinality(actor_groups)
                OR EXISTS (
                    SELECT 1 FROM jsonb_array_elements_text(
                        COALESCE(session_row.claims->'groups', '[]'::jsonb)
                    ) value WHERE NOT (value = ANY(actor_groups))
                )
            THEN
                RAISE EXCEPTION 'session authorization principal is stale'
                    USING ERRCODE = '40001';
            END IF;
            audit_actor_id := 'oidc:' || encode(sha256(convert_to(
                char_length(session_row.issuer)::text || ':' || session_row.issuer ||
                char_length(session_row.subject_id)::text || ':' || session_row.subject_id,
                'UTF8'
            )), 'hex');
            IF target_application_id IS NOT NULL THEN
                SELECT true, application.binding_version
                  INTO application_exists, binding_version
                  FROM public.${tables.v2Applications} application
                 WHERE application.id = target_application_id
                 FOR SHARE;
                application_exists := FOUND;
            END IF;
            effective_role := 'DENIED';
            role_source := 'NONE';

            IF actor_claims_version = policy.required_claims_version
                AND EXISTS (
                    SELECT 1 FROM unnest(actor_groups) actor_group
                    JOIN unnest(policy.administrator_groups) administrator_group
                      ON administrator_group = actor_group
                )
            THEN
                effective_role := 'ADMINISTRATOR';
                role_source := 'ADMINISTRATOR_GROUP';
                role_rank := 4;
            ELSIF actor_claims_version = policy.required_claims_version
                AND application_exists
            THEN
                SELECT COALESCE(max(CASE binding.role
                    WHEN 'OWNER' THEN 3
                    WHEN 'PUBLISHER' THEN 2
                    WHEN 'VIEWER' THEN 1
                    ELSE 0 END), 0)
                  INTO role_rank
                  FROM public.${tables.v2Bindings} binding
                 WHERE binding.application_id = target_application_id
                   AND binding.group_id = ANY(actor_groups);
                effective_role := CASE role_rank
                    WHEN 3 THEN 'OWNER'
                    WHEN 2 THEN 'PUBLISHER'
                    WHEN 1 THEN 'VIEWER'
                    ELSE 'DENIED' END;
                IF role_rank > 0 THEN role_source := 'APPLICATION_BINDING'; END IF;
            ELSIF actor_claims_version <> policy.required_claims_version THEN
                role_source := 'STALE_CLAIMS';
            END IF;

            allowed := CASE
                WHEN requested_operation = 'APPLICATION_CREATE' THEN role_rank = 4
                ELSE application_exists AND CASE
                WHEN role_rank = 4 THEN true
                WHEN role_rank = 3 THEN requested_operation IN (${ownerCapabilitySql})
                WHEN role_rank = 2 THEN requested_operation IN (${publisherCapabilitySql})
                WHEN role_rank = 1 THEN requested_operation IN (${viewerCapabilitySql})
                ELSE false END END;
            IF NOT allowed THEN binding_version := NULL; END IF;

            INSERT INTO public.${tables.v2AuditEvents} (
                id, actor_id, action, application_id, occurred_at, metadata
            ) VALUES (
                audit_id, audit_actor_id, 'AUTHORIZATION_DECISION',
                CASE WHEN application_exists THEN target_application_id ELSE NULL END,
                observed_at,
                pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
                    'objectKind', 'APPLICATION',
                    'operation', requested_operation,
                    'result', CASE WHEN allowed THEN 'ALLOWED' ELSE 'DENIED' END,
                    'role', effective_role,
                    'source', role_source,
                    'bindingVersion', binding_version
                ))
            );
            RETURN NEXT;
        END;
        $function$;
        REVOKE ALL ON FUNCTION public.v2_authorize_operation(
            uuid, uuid, text[], bigint, uuid, text
        ) FROM PUBLIC;

        CREATE FUNCTION public.v2_replace_bindings(
            audit_id uuid,
            actor_session_id uuid,
            actor_groups text[],
            actor_claims_version bigint,
            target_application_id uuid,
            expected_binding_version bigint,
            requested_idempotency_key text,
            requested_digest text,
            desired_bindings jsonb
        ) RETURNS TABLE (
            outcome text,
            resulting_version bigint,
            result_digest text,
            effective_role text,
            role_source text
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        SET lock_timeout = '5s'
        SET statement_timeout = '10s'
        AS $function$
        DECLARE application public.${tables.v2Applications}%ROWTYPE;
        DECLARE prior public.v2_binding_requests%ROWTYPE;
        DECLARE role_rank integer := 0;
        DECLARE observed_at timestamptz;
        DECLARE session_row public.${tables.v2Sessions}%ROWTYPE;
        DECLARE audit_actor_id text;
        DECLARE policy public.v2_authorization_policy%ROWTYPE;
        DECLARE application_exists boolean := false;
        DECLARE desired_is_current boolean := false;
        BEGIN
            SELECT * INTO policy FROM public.v2_authorization_policy
             WHERE singleton = true FOR SHARE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'authorization policy is not provisioned'
                    USING ERRCODE = '55000';
            END IF;
            IF audit_id IS NULL OR actor_session_id IS NULL
                OR actor_groups IS NULL OR cardinality(actor_groups) > 256
                OR actor_claims_version IS NULL OR actor_claims_version < 1
                OR target_application_id IS NULL
                OR expected_binding_version IS NULL OR expected_binding_version < 1
                OR requested_idempotency_key IS NULL
                OR char_length(requested_idempotency_key) NOT BETWEEN 1 AND 200
                OR requested_digest IS NULL
                OR requested_digest !~ '^[0-9a-f]{64}$'
                OR desired_bindings IS NULL
                OR jsonb_typeof(desired_bindings) <> 'array'
                OR jsonb_array_length(desired_bindings) > 256
                OR EXISTS (
                    SELECT 1 FROM unnest(actor_groups || policy.administrator_groups) value
                     WHERE value IS NULL OR char_length(value) NOT BETWEEN 1 AND 512
                        OR value ~ '[[:cntrl:]]' OR btrim(value) <> value
                )
                OR EXISTS (
                    SELECT 1 FROM jsonb_array_elements(desired_bindings) item
                     WHERE jsonb_typeof(item) <> 'object'
                        OR (SELECT count(*) FROM jsonb_object_keys(item)) <> 3
                        OR NOT (jsonb_exists(item, 'id')
                            AND jsonb_exists(item, 'groupId')
                            AND jsonb_exists(item, 'role'))
                        OR (item->>'id') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
                        OR char_length(item->>'groupId') NOT BETWEEN 1 AND 512
                        OR (item->>'groupId') ~ '[[:cntrl:]]'
                        OR btrim(item->>'groupId') <> item->>'groupId'
                        OR item->>'role' NOT IN ('OWNER', 'PUBLISHER', 'VIEWER')
                )
                OR jsonb_array_length(desired_bindings) <> (
                    SELECT count(DISTINCT item->>'groupId')
                      FROM jsonb_array_elements(desired_bindings) item
                )
            THEN
                RAISE EXCEPTION 'invalid binding replacement request'
                    USING ERRCODE = '22023';
            END IF;

            observed_at := clock_timestamp();
            SELECT * INTO session_row FROM public.${tables.v2Sessions}
             WHERE id = actor_session_id FOR SHARE;
            IF NOT FOUND OR session_row.claims_version IS DISTINCT FROM actor_claims_version
                OR session_row.revoked_at IS NOT NULL
                OR session_row.idle_expires_at <= observed_at
                OR session_row.absolute_expires_at <= observed_at
                OR jsonb_array_length(COALESCE(session_row.claims->'groups', '[]'::jsonb))
                    IS DISTINCT FROM cardinality(actor_groups)
                OR EXISTS (
                    SELECT 1 FROM jsonb_array_elements_text(
                        COALESCE(session_row.claims->'groups', '[]'::jsonb)
                    ) value WHERE NOT (value = ANY(actor_groups))
                )
            THEN
                RAISE EXCEPTION 'session authorization principal is stale'
                    USING ERRCODE = '40001';
            END IF;

            audit_actor_id := 'oidc:' || encode(sha256(convert_to(
                char_length(session_row.issuer)::text || ':' || session_row.issuer ||
                char_length(session_row.subject_id)::text || ':' || session_row.subject_id,
                'UTF8'
            )), 'hex');
            SELECT * INTO application
              FROM public.${tables.v2Applications}
             WHERE id = target_application_id
             FOR UPDATE;
            application_exists := FOUND;

            effective_role := 'DENIED';
            role_source := CASE WHEN actor_claims_version <> policy.required_claims_version
                THEN 'STALE_CLAIMS' ELSE 'NONE' END;
            IF actor_claims_version = policy.required_claims_version
                AND EXISTS (
                    SELECT 1 FROM unnest(actor_groups) actor_group
                    JOIN unnest(policy.administrator_groups) administrator_group
                      ON administrator_group = actor_group
                )
            THEN
                role_rank := 4;
                effective_role := 'ADMINISTRATOR';
                role_source := 'ADMINISTRATOR_GROUP';
            ELSIF actor_claims_version = policy.required_claims_version THEN
                SELECT COALESCE(max(CASE binding.role
                    WHEN 'OWNER' THEN 3 WHEN 'PUBLISHER' THEN 2
                    WHEN 'VIEWER' THEN 1 ELSE 0 END), 0)
                  INTO role_rank
                  FROM public.${tables.v2Bindings} binding
                 WHERE binding.application_id = target_application_id
                   AND binding.group_id = ANY(actor_groups);
                effective_role := CASE role_rank WHEN 3 THEN 'OWNER'
                    WHEN 2 THEN 'PUBLISHER' WHEN 1 THEN 'VIEWER'
                    ELSE 'DENIED' END;
                IF role_rank > 0 THEN role_source := 'APPLICATION_BINDING'; END IF;
            END IF;

            IF NOT application_exists OR role_rank < 3 THEN
                outcome := 'DENIED';
                resulting_version := NULL;
                result_digest := NULL;
                INSERT INTO public.${tables.v2AuditEvents} (
                    id, actor_id, action, application_id, occurred_at, metadata
                ) VALUES (
                    audit_id, audit_actor_id, 'BINDINGS_REPLACE',
                    CASE WHEN application_exists THEN target_application_id ELSE NULL END,
                    observed_at, pg_catalog.jsonb_build_object(
                        'objectKind', 'BINDINGS',
                        'operation', 'BINDINGS_REPLACE', 'result', outcome,
                        'role', effective_role, 'source', role_source,
                        'reason', CASE WHEN role_source = 'STALE_CLAIMS'
                            THEN 'STALE_CLAIMS' ELSE 'NOT_AUTHORIZED' END
                    )
                );
                RETURN NEXT;
                RETURN;
            END IF;

            SELECT * INTO prior FROM public.v2_binding_requests request
             WHERE request.application_id = target_application_id
               AND request.actor_id = audit_actor_id
               AND request.idempotency_key = requested_idempotency_key;
            IF FOUND THEN
                IF prior.request_digest IS DISTINCT FROM requested_digest
                    OR prior.expected_version IS DISTINCT FROM expected_binding_version
                THEN
                    RAISE EXCEPTION 'idempotency key conflicts with immutable request'
                        USING ERRCODE = '23505';
                END IF;
                outcome := prior.outcome;
                resulting_version := prior.resulting_version;
                result_digest := prior.result_digest;
                RETURN NEXT;
                RETURN;
            END IF;

            IF application.binding_version <> expected_binding_version THEN
                outcome := 'VERSION_CONFLICT';
                resulting_version := application.binding_version;
            ELSE
                SELECT NOT EXISTS (
                    (SELECT group_id, role FROM public.${tables.v2Bindings}
                      WHERE application_id = target_application_id
                     EXCEPT
                     SELECT item->>'groupId', item->>'role'
                       FROM jsonb_array_elements(desired_bindings) item)
                    UNION ALL
                    (SELECT item->>'groupId', item->>'role'
                       FROM jsonb_array_elements(desired_bindings) item
                     EXCEPT
                     SELECT group_id, role FROM public.${tables.v2Bindings}
                      WHERE application_id = target_application_id)
                ) INTO desired_is_current;
                IF desired_is_current THEN
                    resulting_version := application.binding_version;
                ELSE
                    DELETE FROM public.${tables.v2Bindings}
                     WHERE application_id = target_application_id;
                    INSERT INTO public.${tables.v2Bindings} (
                        id, application_id, group_id, role, created_by, created_at
                    ) SELECT (item->>'id')::uuid, target_application_id,
                        item->>'groupId', item->>'role', audit_actor_id, observed_at
                      FROM jsonb_array_elements(desired_bindings) item;
                    UPDATE public.${tables.v2Applications}
                       SET binding_version = binding_version + 1,
                           updated_at = observed_at
                     WHERE id = target_application_id
                     RETURNING binding_version INTO resulting_version;
                END IF;
                outcome := 'APPLIED';
            END IF;
            result_digest := requested_digest;
            INSERT INTO public.v2_binding_requests (
                application_id, idempotency_key, actor_id, request_digest,
                expected_version, outcome, resulting_version, result_digest,
                created_at
            ) VALUES (
                target_application_id, requested_idempotency_key, audit_actor_id,
                requested_digest, expected_binding_version, outcome,
                resulting_version, result_digest, observed_at
            );
            INSERT INTO public.${tables.v2AuditEvents} (
                id, actor_id, action, application_id, occurred_at, metadata
            ) VALUES (
                audit_id, audit_actor_id, 'BINDINGS_REPLACE', target_application_id,
                observed_at, pg_catalog.jsonb_build_object(
                    'objectKind', 'BINDINGS',
                    'operation', 'BINDINGS_REPLACE', 'result', outcome,
                    'role', effective_role, 'source', role_source,
                    'bindingVersion', resulting_version,
                    'bindingCount', jsonb_array_length(desired_bindings),
                    'requestDigest', requested_digest
                )
            );
            RETURN NEXT;
        END;
        $function$;
        REVOKE ALL ON FUNCTION public.v2_replace_bindings(
            uuid, uuid, text[], bigint, uuid, bigint,
            text, text, jsonb
        ) FROM PUBLIC;


    `);
}

export async function down(knex: Knex): Promise<void> {
    await knex.raw(`
        LOCK TABLE public.v2_binding_requests,
            public.v2_authorization_policy,
            public.${tables.v2Applications},
            public.${tables.v2Bindings} IN ACCESS EXCLUSIVE MODE;
        DO $guard$
        BEGIN
            IF EXISTS (SELECT 1 FROM public.v2_binding_requests)
                OR EXISTS (SELECT 1 FROM public.v2_authorization_policy)
                OR EXISTS (SELECT 1 FROM public.${tables.v2Applications}
                    WHERE binding_version <> 1)
            THEN
                RAISE EXCEPTION 'migration 07 has retained authorization state; expand-only rollback refused'
                    USING ERRCODE = '55000';
            END IF;
        END;
        $guard$;
        DROP FUNCTION IF EXISTS public.v2_list_authorized_audit_events(
            uuid, uuid, text[], bigint, uuid, text, text,
            timestamptz, uuid, integer
        );
        DROP FUNCTION IF EXISTS public.v2_replace_bindings(
            uuid, uuid, text[], bigint, uuid, bigint,
            text, text, jsonb
        );
        DROP FUNCTION IF EXISTS public.v2_authorize_operation(
            uuid, uuid, text[], bigint, uuid, text
        );
        DROP FUNCTION IF EXISTS public.v2_authorization_policy_identity();
        DROP FUNCTION IF EXISTS public.v2_initialize_authorization_policy(
            text[], bigint, text
        );
        DROP TABLE public.v2_authorization_policy;
        DROP TABLE public.v2_binding_requests;
        DROP INDEX IF EXISTS public.v2_bindings_application_role_group_idx;
        ALTER TABLE public.${tables.v2AuditEvents}
            DROP CONSTRAINT v2_audit_events_closed_action_check;
        DROP TRIGGER v2_audit_events_append_only
            ON public.${tables.v2AuditEvents};
        CREATE OR REPLACE FUNCTION public.v2_guard_audit_event()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $function$
        BEGIN
            RAISE EXCEPTION 'audit events are append-only'
                USING ERRCODE = '55000';
        END;
        $function$;
        CREATE TRIGGER v2_audit_events_append_only
            BEFORE UPDATE OR DELETE ON public.${tables.v2AuditEvents}
            FOR EACH ROW EXECUTE FUNCTION public.v2_guard_audit_event();
        CREATE OR REPLACE FUNCTION public.v2_create_or_replace_session(
            replaced_session_id uuid,
            session_id uuid,
            requested_subject_id text,
            requested_issuer text,
            requested_claims jsonb,
            requested_csrf_digest text,
            requested_token_key_id text,
            requested_token_nonce bytea,
            requested_encrypted_tokens bytea,
            idle_lifetime_ms integer,
            absolute_lifetime_ms integer
        ) RETURNS void
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        SET lock_timeout = '5s'
        SET statement_timeout = '10s'
        AS $function$
        DECLARE observed_at timestamptz;
        DECLARE replaced public.${tables.v2Sessions}%ROWTYPE;
        BEGIN
            IF session_id IS NULL OR requested_subject_id IS NULL
                OR requested_issuer IS NULL OR requested_claims IS NULL
                OR requested_csrf_digest IS NULL
                OR requested_token_key_id IS NULL
                OR requested_token_nonce IS NULL
                OR requested_encrypted_tokens IS NULL
                OR idle_lifetime_ms IS NULL OR absolute_lifetime_ms IS NULL
                OR idle_lifetime_ms < 1000 OR idle_lifetime_ms > 86400000
                OR absolute_lifetime_ms < idle_lifetime_ms
                OR absolute_lifetime_ms > 604800000
            THEN
                RAISE EXCEPTION 'invalid session bounds' USING ERRCODE = '22023';
            END IF;
            IF replaced_session_id IS NOT NULL THEN
                SELECT * INTO replaced FROM public.${tables.v2Sessions}
                 WHERE id = replaced_session_id FOR UPDATE;
                observed_at := clock_timestamp();
                IF NOT FOUND OR replaced.revoked_at IS NOT NULL
                    OR replaced.idle_expires_at <= observed_at
                    OR replaced.absolute_expires_at <= observed_at
                THEN
                    RAISE EXCEPTION 'replacement session is no longer active'
                        USING ERRCODE = '40001';
                END IF;
            ELSE
                observed_at := clock_timestamp();
            END IF;

            INSERT INTO public.${tables.v2Sessions} (
                id, subject_id, issuer, claims, csrf_token_digest,
                token_key_id, token_nonce, encrypted_token_material,
                created_at, last_seen_at, idle_expires_at, absolute_expires_at
            ) VALUES (
                session_id, requested_subject_id, requested_issuer,
                requested_claims, requested_csrf_digest,
                requested_token_key_id, requested_token_nonce,
                requested_encrypted_tokens, observed_at, observed_at,
                observed_at + make_interval(secs => idle_lifetime_ms / 1000.0),
                observed_at + make_interval(secs => absolute_lifetime_ms / 1000.0)
            );
            IF replaced_session_id IS NOT NULL THEN
                UPDATE public.${tables.v2Sessions}
                   SET revoked_at = observed_at,
                       revocation_reason = 'SESSION_ROTATED'
                 WHERE id = replaced_session_id;
            END IF;
            INSERT INTO public.${tables.v2AuditEvents} (
                id, actor_id, action, metadata, occurred_at
            ) VALUES (
                gen_random_uuid(), requested_subject_id, 'AUTH_LOGIN',
                jsonb_build_object('issuer', requested_issuer, 'result', 'SUCCESS'),
                observed_at
            );
        END;
        $function$;
        REVOKE ALL ON FUNCTION public.v2_create_or_replace_session(
            uuid, uuid, text, text, jsonb, text, text, bytea, bytea,
            integer, integer
        ) FROM PUBLIC;

        CREATE OR REPLACE FUNCTION public.v2_revoke_session(session_id uuid, reason text)
        RETURNS boolean
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        SET lock_timeout = '5s'
        SET statement_timeout = '10s'
        AS $function$
        DECLARE observed_at timestamptz;
        DECLARE actor text;
        BEGIN
            IF session_id IS NULL OR reason IS NULL
                OR reason !~ '^[A-Z][A-Z0-9_]{0,127}$'
            THEN
                RAISE EXCEPTION 'invalid revocation request' USING ERRCODE = '22023';
            END IF;
            SELECT subject_id INTO actor FROM public.${tables.v2Sessions}
             WHERE id = session_id FOR UPDATE;
            observed_at := clock_timestamp();
            UPDATE public.${tables.v2Sessions}
               SET revoked_at = observed_at, revocation_reason = reason
             WHERE id = session_id AND revoked_at IS NULL
               AND idle_expires_at > observed_at
               AND absolute_expires_at > observed_at;
            IF FOUND THEN
                INSERT INTO public.${tables.v2AuditEvents} (
                    id, actor_id, action, metadata, occurred_at
                ) VALUES (
                    gen_random_uuid(), actor,
                    CASE WHEN reason = 'USER_LOGOUT'
                        THEN 'AUTH_LOGOUT' ELSE 'AUTH_SESSION_REVOKED' END,
                    jsonb_build_object('reason', reason, 'result', 'SUCCESS'),
                    observed_at
                );
                RETURN true;
            END IF;
            RETURN false;
        END;
        $function$;
        REVOKE ALL ON FUNCTION public.v2_revoke_session(uuid, text) FROM PUBLIC;

        ALTER TABLE public.${tables.v2Applications}
            DROP CONSTRAINT v2_applications_binding_version_check,
            DROP COLUMN binding_version;
    `);
}
