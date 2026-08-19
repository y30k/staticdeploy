import { V2_CAPABILITIES } from "@staticdeploy/core";
import { Knex } from "knex";

import tables from "../common/tables";

const sqlList = (values: readonly string[]): string =>
    values.map((value) => `'${value}'`).join(", ");
const capabilitySql = sqlList(V2_CAPABILITIES);

/** Add the executable publication projection protocol without changing old rows. */
export async function up(knex: Knex): Promise<void> {
    await knex.raw(`
        -- PostgreSQL 13 grants CREATE on public to PUBLIC by default. Runtime
        -- least-privilege qualification must be identical on supported and
        -- compatibility majors, so remove that ambient capability additively.
        REVOKE CREATE ON SCHEMA public FROM PUBLIC;

        ALTER TABLE public.${tables.v2Applications}
            ADD CONSTRAINT v2_applications_generation_safe_integer_check
                CHECK (desired_generation <= 9007199254740991
                    AND served_generation <= 9007199254740991);
        ALTER TABLE public.${tables.v2PublicationOutbox}
            ADD COLUMN routing_kid text,
            ADD COLUMN routing_host text,
            ADD COLUMN request_digest text,
            ADD COLUMN request_actor_id text,
            ADD COLUMN request_audit_id uuid,
            ADD COLUMN acknowledged_etag text,
            ADD COLUMN acknowledged_version_id text,
            ADD CONSTRAINT v2_outbox_generation_safe_integer_check
                CHECK (generation <= 9007199254740991),
            ADD CONSTRAINT v2_outbox_lease_version_safe_integer_check
                CHECK (lease_version <= 9007199254740991),
            ADD CONSTRAINT v2_outbox_routing_kid_check CHECK (
                routing_kid IS NULL OR routing_kid ~ '^[A-Za-z0-9._:-]{1,100}$'),
            ADD CONSTRAINT v2_outbox_routing_host_check CHECK (
                routing_host IS NULL OR (octet_length(routing_host) BETWEEN 1 AND 253
                    AND routing_host = lower(routing_host)
                    AND routing_host ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9]){0,1}(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9]){0,1})*$')),
            ADD CONSTRAINT v2_outbox_request_digest_check CHECK (
                request_digest IS NULL OR request_digest ~ '^[0-9a-f]{64}$'),
            ADD CONSTRAINT v2_outbox_request_actor_check CHECK (
                request_actor_id IS NULL OR request_actor_id ~ '^oidc:[0-9a-f]{64}$'),
            ADD CONSTRAINT v2_outbox_ack_etag_check CHECK (
                acknowledged_etag IS NULL OR octet_length(acknowledged_etag) BETWEEN 1 AND 1024),
            ADD CONSTRAINT v2_outbox_ack_version_check CHECK (
                acknowledged_version_id IS NULL OR octet_length(acknowledged_version_id) BETWEEN 1 AND 1024);
        ALTER TABLE public.${tables.v2Idempotency}
            DROP CONSTRAINT v2_idempotency_expiry_check;
        ALTER TABLE public.${tables.v2Idempotency}
            ADD CONSTRAINT v2_idempotency_expiry_check CHECK (
                expires_at > created_at AND (completed_at IS NULL OR completed_at >= created_at));

        CREATE UNIQUE INDEX v2_outbox_request_audit_unique
            ON public.${tables.v2PublicationOutbox}(request_audit_id)
            WHERE request_audit_id IS NOT NULL;
        CREATE INDEX v2_outbox_routing_kid_active_idx
            ON public.${tables.v2PublicationOutbox}
                (routing_kid, state, application_id, generation DESC)
            WHERE routing_kid IS NOT NULL;

        ALTER TABLE public.${tables.v2AuditEvents}
            DROP CONSTRAINT v2_audit_events_closed_action_check;
        ALTER TABLE public.${tables.v2AuditEvents}
            ADD CONSTRAINT v2_audit_events_closed_action_check CHECK (action IN (
                'AUTH_LOGIN', 'AUTH_LOGOUT', 'AUTH_SESSION_REVOKED',
                'AUTHENTICATION_SUCCEEDED', 'AUTHORIZATION_DECISION',
                'APPLICATION_CREATED', 'APPLICATION_VIEWED', 'RELEASE_READY',
                'RELEASE_LISTED', 'AUDIT_VIEWED', 'BINDINGS_REPLACE',
                'PUBLISH_REQUESTED', 'RESTORE_REQUESTED', 'UNPUBLISH_REQUESTED',
                'PUBLISHED', 'RESTORED', 'UNPUBLISHED', 'PUBLICATION_FAILED'
            ));

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
                        'BINDINGS_REPLACE', 'PUBLISH_REQUESTED',
                        'RESTORE_REQUESTED', 'UNPUBLISH_REQUESTED',
                        'PUBLISHED', 'RESTORED', 'UNPUBLISHED', 'PUBLICATION_FAILED'
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
                                ('ALLOWED', 'DENIED', 'APPLIED', 'VERSION_CONFLICT',
                                 'SUCCESS', 'PENDING', 'FAILED'))
                            OR (entry.key = 'role' AND entry.value #>> '{}' NOT IN
                                ('ADMINISTRATOR', 'OWNER', 'PUBLISHER', 'VIEWER', 'DENIED'))
                            OR (entry.key = 'source' AND entry.value #>> '{}' NOT IN
                                ('ADMINISTRATOR_GROUP', 'APPLICATION_BINDING',
                                 'STALE_CLAIMS', 'NONE'))
                            OR (entry.key = 'objectKind' AND entry.value #>> '{}' NOT IN
                                ('APPLICATION', 'BINDINGS', 'SESSION', 'PUBLICATION'))
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

        CREATE OR REPLACE FUNCTION public.v2_guard_idempotency()
        RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog
        AS $function$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                IF transaction_timestamp() < OLD.expires_at THEN
                    RAISE EXCEPTION 'unexpired idempotency record cannot be deleted'
                        USING ERRCODE = '55000';
                END IF;
                IF EXISTS (SELECT 1 FROM public.${tables.v2PublicationOutbox} outbox
                     WHERE outbox.idempotency_id = OLD.id AND outbox.routing_host IS NOT NULL
                       AND outbox.state IN ('PENDING', 'LEASED'))
                THEN RAISE EXCEPTION 'active publication idempotency record cannot be deleted'
                    USING ERRCODE = '55000'; END IF;
                RETURN OLD;
            END IF;
            IF OLD.state = 'COMPLETED' THEN RAISE EXCEPTION 'completed idempotency result is immutable'
                USING ERRCODE = '55000'; END IF;
            IF NEW.id IS DISTINCT FROM OLD.id OR NEW.actor_id IS DISTINCT FROM OLD.actor_id
                OR NEW.scope IS DISTINCT FROM OLD.scope
                OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
                OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
                OR NEW.created_at IS DISTINCT FROM OLD.created_at
                OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
                OR (NEW.state = 'IN_PROGRESS' AND OLD.state <> 'IN_PROGRESS')
            THEN RAISE EXCEPTION 'idempotency request identity is immutable' USING ERRCODE = '55000'; END IF;
            IF OLD.expires_at <= transaction_timestamp() AND NOT (
                NEW.state = 'COMPLETED' AND NEW.result_kind = 'PUBLICATION'
                AND EXISTS (SELECT 1 FROM public.${tables.v2OutboxTransitionGuards} guard
                    WHERE guard.outbox_id = NEW.result_id AND guard.transaction_id = txid_current()))
            THEN RAISE EXCEPTION 'expired idempotency record is immutable' USING ERRCODE = '55000'; END IF;
            RETURN NEW;
        END $function$;

        CREATE FUNCTION public.v2_request_publication(
            target_application_id uuid, target_release_id uuid, requested_operation text,
            requested_idempotency_id uuid, requested_outbox_id uuid,
            requested_audit_id uuid, authorization_audit_id uuid,
            actor_session_id uuid, actor_groups text[], actor_claims_version bigint,
            requested_digest text, requested_routing_host text
        ) RETURNS public.${tables.v2PublicationOutbox}
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
        SET lock_timeout = '5s' SET statement_timeout = '30s'
        AS $function$
        DECLARE application public.${tables.v2Applications}%ROWTYPE;
        DECLARE release public.${tables.v2Releases}%ROWTYPE;
        DECLARE existing public.${tables.v2PublicationOutbox}%ROWTYPE;
        DECLARE created public.${tables.v2PublicationOutbox}%ROWTYPE;
        DECLARE idempotency public.${tables.v2Idempotency}%ROWTYPE;
        DECLARE session_row public.${tables.v2Sessions}%ROWTYPE;
        DECLARE authz_decision record;
        DECLARE expected_scope text;
        DECLARE capability text;
        DECLARE audit_actor_id text;
        DECLARE observed_at timestamptz;
        BEGIN
            IF target_application_id IS NULL OR requested_idempotency_id IS NULL
                OR requested_outbox_id IS NULL OR requested_audit_id IS NULL
                OR authorization_audit_id IS NULL OR actor_session_id IS NULL
                OR requested_digest !~ '^[0-9a-f]{64}$'
                OR requested_routing_host IS NULL
                OR octet_length(requested_routing_host) NOT BETWEEN 1 AND 253
                OR requested_routing_host <> lower(requested_routing_host)
                OR requested_routing_host !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9]){0,1}(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9]){0,1})*$'
                OR requested_operation NOT IN ('PUBLISH', 'RESTORE', 'UNPUBLISH')
                OR (requested_operation = 'UNPUBLISH') <> (target_release_id IS NULL)
            THEN RAISE EXCEPTION 'publication request arguments are invalid' USING ERRCODE = '22023'; END IF;
            expected_scope := CASE requested_operation WHEN 'PUBLISH' THEN 'release.publish'
                WHEN 'RESTORE' THEN 'release.restore' ELSE 'application.unpublish' END;
            capability := CASE requested_operation WHEN 'PUBLISH' THEN 'PUBLISH'
                WHEN 'RESTORE' THEN 'RESTORE' ELSE 'UNPUBLISH' END;

            -- Serialize equal targets before v2_authorize_operation takes its
            -- application FOR SHARE lock. This transaction-scoped, target-only
            -- lock avoids concurrent SHARE-to-UPDATE upgrade deadlocks without
            -- looking up the target before session and authorization fencing.
            PERFORM pg_catalog.pg_advisory_xact_lock(
                pg_catalog.hashtextextended(target_application_id::text, 30808)
            );
            SELECT * INTO authz_decision FROM public.v2_authorize_operation(
                authorization_audit_id, actor_session_id, actor_groups,
                actor_claims_version, target_application_id, capability
            );
            IF NOT FOUND OR NOT authz_decision.allowed THEN RETURN NULL; END IF;
            SELECT * INTO session_row FROM public.${tables.v2Sessions}
             WHERE id = actor_session_id FOR SHARE;
            audit_actor_id := 'oidc:' || encode(sha256(convert_to(
                char_length(session_row.issuer)::text || ':' || session_row.issuer ||
                char_length(session_row.subject_id)::text || ':' || session_row.subject_id, 'UTF8'
            )), 'hex');

            SELECT * INTO idempotency FROM public.${tables.v2Idempotency}
             WHERE id = requested_idempotency_id FOR UPDATE;
            IF NOT FOUND OR idempotency.actor_id <> audit_actor_id
                OR idempotency.scope <> expected_scope
                OR idempotency.request_digest <> requested_digest
            THEN RAISE EXCEPTION 'publication idempotency identity is invalid' USING ERRCODE = '55000'; END IF;
            SELECT * INTO existing FROM public.${tables.v2PublicationOutbox}
             WHERE idempotency_id = requested_idempotency_id;
            IF FOUND THEN
                IF existing.application_id <> target_application_id
                    OR existing.release_id IS DISTINCT FROM target_release_id
                    OR existing.operation <> requested_operation
                    OR existing.request_digest <> requested_digest
                    OR existing.routing_host <> requested_routing_host
                    OR existing.request_actor_id <> audit_actor_id
                THEN RAISE EXCEPTION 'conflicting publication idempotency reuse' USING ERRCODE = '23505'; END IF;
                RETURN existing;
            END IF;
            IF idempotency.state <> 'IN_PROGRESS' OR idempotency.expires_at <= clock_timestamp()
            THEN RAISE EXCEPTION 'publication idempotency identity is no longer active' USING ERRCODE = '55000'; END IF;

            SELECT * INTO application FROM public.${tables.v2Applications}
             WHERE id = target_application_id FOR UPDATE;
            IF NOT FOUND OR application.status <> 'ACTIVE' THEN
                RAISE EXCEPTION 'active application not found' USING ERRCODE = 'P0002'; END IF;
            IF target_release_id IS NOT NULL THEN
                SELECT * INTO release FROM public.${tables.v2Releases}
                 WHERE id = target_release_id AND application_id = target_application_id FOR SHARE;
                IF NOT FOUND OR release.state <> 'READY' OR release.manifest_digest IS NULL
                    OR (requested_operation = 'PUBLISH' AND release.published_at IS NOT NULL)
                    OR (requested_operation = 'RESTORE' AND release.published_at IS NULL)
                THEN RAISE EXCEPTION 'matching READY release not found' USING ERRCODE = 'P0002'; END IF;
            END IF;
            observed_at := clock_timestamp();
            UPDATE public.${tables.v2Applications}
               SET desired_current_release_id = target_release_id,
                   desired_generation = desired_generation + 1, updated_at = observed_at
             WHERE id = target_application_id RETURNING * INTO application;
            INSERT INTO public.${tables.v2AuditEvents} (
                id, actor_id, action, application_id, release_id, occurred_at, metadata
            ) VALUES (requested_audit_id, audit_actor_id, requested_operation || '_REQUESTED',
                target_application_id, target_release_id, observed_at,
                jsonb_build_object('objectKind', 'PUBLICATION', 'operation', capability,
                    'result', 'PENDING', 'eventVersion', application.desired_generation,
                    'requestDigest', requested_digest));
            INSERT INTO public.${tables.v2PublicationOutbox} (
                id, application_id, routing_id, release_id, generation, operation,
                idempotency_id, payload_kind, manifest_digest, object_prefix,
                routing_host, request_digest, request_actor_id, request_audit_id,
                created_at, updated_at
            ) VALUES (requested_outbox_id, target_application_id, application.routing_id,
                target_release_id, application.desired_generation, requested_operation,
                requested_idempotency_id,
                CASE WHEN target_release_id IS NULL THEN 'TOMBSTONE' ELSE 'RELEASE' END,
                release.manifest_digest, CASE WHEN target_release_id IS NULL THEN NULL ELSE
                    'v2/releases/' || target_application_id::text || '/' || target_release_id::text END,
                requested_routing_host, requested_digest, audit_actor_id, requested_audit_id,
                observed_at, observed_at) RETURNING * INTO created;
            RETURN created;
        END $function$;
        REVOKE ALL ON FUNCTION public.v2_request_publication(
            uuid, uuid, text, uuid, uuid, uuid, uuid, uuid, text[], bigint, text, text
        ) FROM PUBLIC;

        CREATE FUNCTION public.v2_publication_operation(target_outbox_id uuid)
        RETURNS public.${tables.v2PublicationOutbox}
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog
        AS $function$ SELECT * FROM public.${tables.v2PublicationOutbox} WHERE id = target_outbox_id $function$;
        REVOKE ALL ON FUNCTION public.v2_publication_operation(uuid) FROM PUBLIC;

        CREATE FUNCTION public.v2_guard_projection_context()
        RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
        AS $function$
        BEGIN
            IF NEW.routing_host IS DISTINCT FROM OLD.routing_host
                OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
                OR NEW.request_actor_id IS DISTINCT FROM OLD.request_actor_id
                OR NEW.request_audit_id IS DISTINCT FROM OLD.request_audit_id
                OR (OLD.routing_kid IS NOT NULL AND NEW.routing_kid IS DISTINCT FROM OLD.routing_kid)
                OR (OLD.acknowledged_etag IS NOT NULL
                    AND NEW.acknowledged_etag IS DISTINCT FROM OLD.acknowledged_etag)
                OR (OLD.acknowledged_version_id IS NOT NULL
                    AND NEW.acknowledged_version_id IS DISTINCT FROM OLD.acknowledged_version_id)
                OR ((NEW.routing_kid IS DISTINCT FROM OLD.routing_kid
                        OR NEW.acknowledged_etag IS DISTINCT FROM OLD.acknowledged_etag
                        OR NEW.acknowledged_version_id IS DISTINCT FROM OLD.acknowledged_version_id)
                    AND NOT EXISTS (SELECT 1 FROM public.${tables.v2OutboxTransitionGuards}
                        WHERE outbox_id = NEW.id AND transaction_id = txid_current()))
            THEN RAISE EXCEPTION 'publication projection context is immutable and fenced'
                USING ERRCODE = '55000'; END IF;
            RETURN NEW;
        END $function$;
        CREATE TRIGGER v2_outbox_projection_context_guard
            BEFORE UPDATE ON public.${tables.v2PublicationOutbox}
            FOR EACH ROW EXECUTE FUNCTION public.v2_guard_projection_context();

        CREATE FUNCTION public.v2_bind_publication_key(
            target_outbox_id uuid, expected_lease_owner text,
            expected_lease_version bigint, requested_kid text
        ) RETURNS public.${tables.v2PublicationOutbox}
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
        SET lock_timeout = '5s' SET statement_timeout = '30s'
        AS $function$
        DECLARE target public.${tables.v2PublicationOutbox}%ROWTYPE;
        BEGIN
            IF requested_kid !~ '^[A-Za-z0-9._:-]{1,100}$' THEN
                RAISE EXCEPTION 'invalid routing key identity' USING ERRCODE = '22023'; END IF;
            SELECT * INTO target FROM public.${tables.v2PublicationOutbox}
             WHERE id = target_outbox_id FOR UPDATE;
            IF NOT FOUND OR target.state <> 'LEASED'
                OR target.lease_owner IS DISTINCT FROM expected_lease_owner
                OR target.lease_version IS DISTINCT FROM expected_lease_version
                OR target.lease_expires_at <= clock_timestamp()
            THEN RAISE EXCEPTION 'active outbox lease fencing does not match'
                USING ERRCODE = '55000'; END IF;
            IF target.routing_kid IS NOT NULL THEN
                IF target.routing_kid <> requested_kid THEN
                    RAISE EXCEPTION 'publication key is already bound' USING ERRCODE = '55000'; END IF;
                RETURN target;
            END IF;
            INSERT INTO public.${tables.v2OutboxTransitionGuards}(outbox_id, transaction_id)
                VALUES (target.id, txid_current());
            UPDATE public.${tables.v2PublicationOutbox} SET routing_kid = requested_kid
             WHERE id = target.id RETURNING * INTO target;
            DELETE FROM public.${tables.v2OutboxTransitionGuards}
             WHERE outbox_id = target.id AND transaction_id = txid_current();
            RETURN target;
        END $function$;
        REVOKE ALL ON FUNCTION public.v2_bind_publication_key(uuid, text, bigint, text)
            FROM PUBLIC;

        CREATE FUNCTION public.v2_claim_publications(
            requested_owner text, requested_lease_ms integer, requested_limit integer
        )
        RETURNS SETOF public.${tables.v2PublicationOutbox}
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        SET lock_timeout = '5s'
        SET statement_timeout = '30s'
        AS $function$
        DECLARE candidate public.${tables.v2PublicationOutbox}%ROWTYPE;
        DECLARE claimed_count integer := 0;
        DECLARE observed_at timestamptz;
        BEGIN
            IF requested_owner IS NULL
                OR requested_lease_ms IS NULL
                OR requested_limit IS NULL
                OR requested_owner !~ '^[A-Za-z0-9._:-]{1,200}$'
                OR requested_lease_ms NOT BETWEEN 100 AND 900000
                OR requested_limit NOT BETWEEN 1 AND 100
            THEN RAISE EXCEPTION 'publication claim arguments are invalid'
                USING ERRCODE = '22023'; END IF;
            observed_at := clock_timestamp();
            RETURN QUERY
            WITH candidates AS MATERIALIZED (
                SELECT outbox.id, outbox.next_attempt_at AS priority_time,
                       outbox.created_at AS priority_created_at
                  FROM public.${tables.v2PublicationOutbox} outbox
                  JOIN public.${tables.v2Applications} application
                    ON application.id = outbox.application_id
                 WHERE outbox.state = 'PENDING'
                   AND outbox.next_attempt_at <= observed_at
                   AND outbox.attempt_count < outbox.max_attempts
                   AND outbox.lease_version < 9007199254740991
                   AND outbox.routing_host IS NOT NULL
                   AND outbox.request_digest IS NOT NULL
                   AND outbox.request_actor_id IS NOT NULL
                   AND outbox.request_audit_id IS NOT NULL
                   AND application.desired_generation = outbox.generation
                   AND application.desired_current_release_id IS NOT DISTINCT FROM
                       outbox.release_id
                 ORDER BY outbox.next_attempt_at, outbox.created_at, outbox.id
                 FOR UPDATE OF outbox SKIP LOCKED
                 LIMIT requested_limit
            ), updated AS (
                UPDATE public.${tables.v2PublicationOutbox} outbox
                   SET state = 'LEASED', lease_owner = requested_owner,
                       lease_expires_at = clock_timestamp()
                           + make_interval(secs => requested_lease_ms / 1000.0),
                       attempt_count = outbox.attempt_count + 1,
                       lease_version = outbox.lease_version + 1,
                       next_attempt_at = NULL, last_error_code = NULL,
                       updated_at = clock_timestamp()
                  FROM candidates
                 WHERE outbox.id = candidates.id
                RETURNING outbox.*
            ) SELECT updated.* FROM updated
                JOIN candidates ON candidates.id = updated.id
                ORDER BY candidates.priority_time,
                         candidates.priority_created_at, candidates.id;
            GET DIAGNOSTICS claimed_count = ROW_COUNT;

            IF claimed_count < requested_limit THEN
                RETURN QUERY
                WITH candidates AS MATERIALIZED (
                    SELECT outbox.id,
                           outbox.lease_expires_at AS priority_time
                      FROM public.${tables.v2PublicationOutbox} outbox
                      JOIN public.${tables.v2Applications} application
                        ON application.id = outbox.application_id
                     WHERE outbox.state = 'LEASED'
                       AND outbox.lease_expires_at <= observed_at
                       AND outbox.attempt_count < outbox.max_attempts
                       AND outbox.lease_version < 9007199254740991
                       AND outbox.routing_host IS NOT NULL
                       AND outbox.request_digest IS NOT NULL
                       AND outbox.request_actor_id IS NOT NULL
                       AND outbox.request_audit_id IS NOT NULL
                       AND application.desired_generation = outbox.generation
                       AND application.desired_current_release_id IS NOT DISTINCT FROM
                           outbox.release_id
                     ORDER BY outbox.lease_expires_at, outbox.id
                     FOR UPDATE OF outbox SKIP LOCKED
                     LIMIT requested_limit - claimed_count
                ), updated AS (
                    UPDATE public.${tables.v2PublicationOutbox} outbox
                       SET lease_owner = requested_owner,
                           lease_expires_at = clock_timestamp()
                               + make_interval(secs => requested_lease_ms / 1000.0),
                           attempt_count = outbox.attempt_count + 1,
                           lease_version = outbox.lease_version + 1,
                           next_attempt_at = NULL, last_error_code = NULL,
                           updated_at = clock_timestamp()
                      FROM candidates
                     WHERE outbox.id = candidates.id
                    RETURNING outbox.*
                ) SELECT updated.* FROM updated
                    JOIN candidates ON candidates.id = updated.id
                    ORDER BY candidates.priority_time, candidates.id;
            END IF;
            FOR candidate IN SELECT * FROM public.${tables.v2PublicationOutbox}
                 WHERE state = 'LEASED' AND lease_expires_at <= clock_timestamp()
                   AND attempt_count >= max_attempts
                   AND routing_host IS NOT NULL
                   AND request_digest IS NOT NULL
                   AND request_actor_id IS NOT NULL
                   AND request_audit_id IS NOT NULL
                 ORDER BY lease_expires_at, id FOR UPDATE SKIP LOCKED LIMIT requested_limit
            LOOP
                PERFORM public.v2_finish_projected_publication_attempt(
                    candidate.id, candidate.lease_owner, candidate.lease_version,
                    'FAILED', 'FINAL_ATTEMPT_LEASE_EXPIRED', NULL,
                    gen_random_uuid()
                );
            END LOOP;
            FOR candidate IN SELECT outbox.* FROM public.${tables.v2PublicationOutbox} outbox
                 JOIN public.${tables.v2Applications} application
                   ON application.id = outbox.application_id
                 WHERE ((outbox.state = 'PENDING'
                          AND outbox.next_attempt_at <= clock_timestamp())
                     OR (outbox.state = 'LEASED'
                          AND outbox.lease_expires_at <= clock_timestamp()))
                   AND outbox.attempt_count < outbox.max_attempts
                   AND outbox.routing_host IS NOT NULL
                   AND outbox.request_digest IS NOT NULL
                   AND outbox.request_actor_id IS NOT NULL
                   AND outbox.request_audit_id IS NOT NULL
                   AND (outbox.generation <> application.desired_generation
                     OR outbox.release_id IS DISTINCT FROM application.desired_current_release_id)
                   AND outbox.lease_version < 9007199254740991
                 ORDER BY outbox.generation, outbox.id FOR UPDATE OF outbox SKIP LOCKED
                 LIMIT requested_limit
            LOOP
                observed_at := clock_timestamp();
                -- Reclaim an expired superseded lease (or claim a due pending
                -- row) with fresh fencing, then terminalize through the only
                -- guarded completion wrapper.
                UPDATE public.${tables.v2PublicationOutbox}
                   SET state = 'LEASED', lease_owner = requested_owner,
                       lease_expires_at = observed_at + interval '1 second',
                       attempt_count = attempt_count + 1, lease_version = lease_version + 1,
                       next_attempt_at = NULL, last_error_code = NULL, updated_at = observed_at
                 WHERE id = candidate.id RETURNING * INTO candidate;
                PERFORM public.v2_finish_projected_publication_attempt(
                    candidate.id, candidate.lease_owner, candidate.lease_version,
                    'FAILED', 'SUPERSEDED_GENERATION', NULL, gen_random_uuid());
            END LOOP;
        END;
        $function$;
        REVOKE ALL ON FUNCTION public.v2_claim_publications(text, integer, integer)
            FROM PUBLIC;

        CREATE FUNCTION public.v2_renew_publication(
            target_outbox_id uuid, expected_lease_owner text,
            expected_lease_version bigint, requested_lease_ms integer
        ) RETURNS public.${tables.v2PublicationOutbox}
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        SET lock_timeout = '5s'
        SET statement_timeout = '30s'
        AS $function$
        DECLARE renewed public.${tables.v2PublicationOutbox}%ROWTYPE;
        DECLARE observed_at timestamptz;
        DECLARE desired_generation bigint;
        DECLARE desired_release_id uuid;
        BEGIN
            IF expected_lease_owner !~ '^[A-Za-z0-9._:-]{1,200}$'
                OR expected_lease_version <= 0
                OR requested_lease_ms NOT BETWEEN 100 AND 900000
            THEN RAISE EXCEPTION 'publication renewal arguments are invalid'
                USING ERRCODE = '22023'; END IF;
            SELECT * INTO renewed FROM public.${tables.v2PublicationOutbox}
             WHERE id = target_outbox_id FOR UPDATE;
            SELECT application.desired_generation, application.desired_current_release_id
              INTO desired_generation, desired_release_id
              FROM public.${tables.v2Applications} application
             WHERE application.id = renewed.application_id FOR SHARE;
            observed_at := clock_timestamp();
            IF NOT FOUND OR renewed.state <> 'LEASED'
                OR renewed.lease_owner IS DISTINCT FROM expected_lease_owner
                OR renewed.lease_version IS DISTINCT FROM expected_lease_version
                OR renewed.lease_expires_at <= observed_at
                OR renewed.generation IS DISTINCT FROM desired_generation
                OR renewed.release_id IS DISTINCT FROM desired_release_id
            THEN RAISE EXCEPTION 'active outbox lease fencing does not match'
                USING ERRCODE = '55000'; END IF;
            UPDATE public.${tables.v2PublicationOutbox}
               SET lease_expires_at = GREATEST(lease_expires_at,
                    observed_at + make_interval(secs => requested_lease_ms / 1000.0)),
                   updated_at = observed_at
             WHERE id = target_outbox_id RETURNING * INTO renewed;
            RETURN renewed;
        END;
        $function$;
        REVOKE ALL ON FUNCTION public.v2_renew_publication(uuid, text, bigint, integer)
            FROM PUBLIC;

        CREATE FUNCTION public.v2_assert_publication_projectable(
            target_outbox_id uuid, expected_lease_owner text, expected_lease_version bigint
        ) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
        SET lock_timeout = '5s' SET statement_timeout = '30s'
        AS $function$
        DECLARE target public.${tables.v2PublicationOutbox}%ROWTYPE;
        DECLARE application public.${tables.v2Applications}%ROWTYPE;
        DECLARE release public.${tables.v2Releases}%ROWTYPE;
        DECLARE observed_at timestamptz;
        BEGIN
            SELECT * INTO target FROM public.${tables.v2PublicationOutbox}
             WHERE id = target_outbox_id FOR UPDATE;
            SELECT * INTO application FROM public.${tables.v2Applications}
             WHERE id = target.application_id FOR SHARE;
            observed_at := clock_timestamp();
            IF NOT FOUND OR target.state <> 'LEASED'
                OR target.lease_owner IS DISTINCT FROM expected_lease_owner
                OR target.lease_version IS DISTINCT FROM expected_lease_version
                OR target.lease_expires_at <= observed_at
                OR target.routing_host IS NULL OR target.request_digest IS NULL
                OR target.generation IS DISTINCT FROM application.desired_generation
                OR target.release_id IS DISTINCT FROM application.desired_current_release_id
            THEN RAISE EXCEPTION 'active outbox lease is no longer projectable' USING ERRCODE = '55000'; END IF;
            IF target.release_id IS NOT NULL THEN
                SELECT * INTO release FROM public.${tables.v2Releases}
                 WHERE id = target.release_id AND application_id = target.application_id FOR SHARE;
                IF NOT FOUND OR release.state <> 'READY'
                    OR release.manifest_digest IS DISTINCT FROM target.manifest_digest
                    OR target.object_prefix IS DISTINCT FROM
                       ('v2/releases/' || target.application_id::text || '/' || target.release_id::text)
                THEN RAISE EXCEPTION 'READY release snapshot changed before projection' USING ERRCODE = '55000'; END IF;
            END IF;
        END $function$;
        REVOKE ALL ON FUNCTION public.v2_assert_publication_projectable(uuid, text, bigint)
            FROM PUBLIC;

        CREATE FUNCTION public.v2_finish_projected_publication_attempt(
            target_outbox_id uuid, expected_lease_owner text,
            expected_lease_version bigint, outcome text, error_code text,
            requested_retry_delay_ms integer, requested_audit_id uuid
        ) RETURNS void
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
        SET lock_timeout = '5s' SET statement_timeout = '30s'
        AS $function$
        DECLARE target public.${tables.v2PublicationOutbox}%ROWTYPE;
        DECLARE observed_at timestamptz;
        DECLARE capability text;
        DECLARE requested_retry_at timestamptz;
        BEGIN
            IF (outcome = 'RETRY' AND requested_retry_delay_ms NOT BETWEEN 1 AND 900000)
                OR (outcome = 'FAILED' AND requested_retry_delay_ms IS NOT NULL)
            THEN RAISE EXCEPTION 'publication retry delay is invalid' USING ERRCODE = '22023'; END IF;
            observed_at := clock_timestamp();
            requested_retry_at := CASE WHEN requested_retry_delay_ms IS NULL THEN NULL ELSE
                observed_at + make_interval(secs => requested_retry_delay_ms / 1000.0) END;
            SELECT * INTO target FROM public.${tables.v2PublicationOutbox}
             WHERE id = target_outbox_id;
            IF NOT FOUND OR target.request_actor_id IS NULL THEN
                RAISE EXCEPTION 'leased outbox row not found' USING ERRCODE = 'P0002'; END IF;
            PERFORM public.v2_finish_publication_attempt(target_outbox_id,
                expected_lease_owner, expected_lease_version, outcome,
                error_code, requested_retry_at);
            IF outcome = 'FAILED' THEN
                capability := CASE target.operation WHEN 'PUBLISH' THEN 'PUBLISH'
                    WHEN 'RESTORE' THEN 'RESTORE' ELSE 'UNPUBLISH' END;
                INSERT INTO public.${tables.v2AuditEvents}(
                    id, actor_id, action, application_id, release_id, occurred_at, metadata
                ) VALUES (requested_audit_id, target.request_actor_id,
                    'PUBLICATION_FAILED', target.application_id, target.release_id,
                    observed_at, jsonb_build_object('objectKind', 'PUBLICATION',
                        'operation', capability, 'result', 'FAILED',
                        'eventVersion', target.generation));
                INSERT INTO public.${tables.v2OutboxTransitionGuards}(outbox_id, transaction_id)
                    VALUES (target.id, txid_current());
                UPDATE public.${tables.v2Idempotency}
                   SET state = 'COMPLETED', result_kind = 'PUBLICATION',
                       result_id = target.id, result_status = 'FAILED', completed_at = observed_at
                 WHERE id = target.idempotency_id AND state = 'IN_PROGRESS';
                IF NOT FOUND THEN RAISE EXCEPTION 'publication idempotency completion failed'
                    USING ERRCODE = '55000'; END IF;
                DELETE FROM public.${tables.v2OutboxTransitionGuards}
                 WHERE outbox_id = target.id AND transaction_id = txid_current();
            END IF;
        END $function$;
        REVOKE ALL ON FUNCTION public.v2_finish_projected_publication_attempt(
            uuid, text, bigint, text, text, integer, uuid
        ) FROM PUBLIC;

        CREATE FUNCTION public.v2_acknowledge_projected_publication(
            target_outbox_id uuid, expected_lease_owner text,
            expected_lease_version bigint, projection_digest_value text,
            acknowledged_etag_value text, acknowledged_version_value text,
            requested_audit_id uuid
        ) RETURNS text
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        SET lock_timeout = '5s'
        SET statement_timeout = '30s'
        AS $function$
        DECLARE target public.${tables.v2PublicationOutbox}%ROWTYPE;
        DECLARE actor text;
        DECLARE label text;
        DECLARE observed_at timestamptz;
        DECLARE capability text;
        DECLARE target_application_id uuid;
        BEGIN
            SELECT application_id INTO target_application_id
              FROM public.${tables.v2PublicationOutbox} WHERE id = target_outbox_id;
            PERFORM 1 FROM public.${tables.v2Applications}
             WHERE id = target_application_id FOR UPDATE;
            SELECT * INTO target FROM public.${tables.v2PublicationOutbox}
             WHERE id = target_outbox_id FOR UPDATE;
            IF NOT FOUND OR target.request_actor_id IS NULL OR target.routing_kid IS NULL
            THEN RAISE EXCEPTION 'leased outbox row not found or projection context is unbound'
                USING ERRCODE = 'P0002'; END IF;
            actor := target.request_actor_id;
            IF acknowledged_etag_value IS NULL
                OR octet_length(acknowledged_etag_value) NOT BETWEEN 1 AND 1024
                OR (acknowledged_version_value IS NOT NULL
                    AND octet_length(acknowledged_version_value) NOT BETWEEN 1 AND 1024)
            THEN RAISE EXCEPTION 'invalid acknowledged object identity'
                USING ERRCODE = '22023'; END IF;
            INSERT INTO public.${tables.v2OutboxTransitionGuards}(outbox_id, transaction_id)
                VALUES (target.id, txid_current());
            UPDATE public.${tables.v2PublicationOutbox}
               SET acknowledged_etag = acknowledged_etag_value,
                   acknowledged_version_id = acknowledged_version_value
             WHERE id = target.id;
            DELETE FROM public.${tables.v2OutboxTransitionGuards}
             WHERE outbox_id = target.id AND transaction_id = txid_current();
            label := public.v2_acknowledge_publication(target_outbox_id,
                expected_lease_owner, expected_lease_version, projection_digest_value);
            observed_at := clock_timestamp();
            capability := CASE target.operation WHEN 'PUBLISH' THEN 'PUBLISH'
                WHEN 'RESTORE' THEN 'RESTORE' ELSE 'UNPUBLISH' END;
            INSERT INTO public.${tables.v2AuditEvents} (
                id, actor_id, action, application_id, release_id, occurred_at, metadata
            ) VALUES (requested_audit_id, actor,
                CASE target.operation WHEN 'PUBLISH' THEN 'PUBLISHED'
                    WHEN 'RESTORE' THEN 'RESTORED' ELSE 'UNPUBLISHED' END,
                target.application_id, target.release_id, observed_at,
                jsonb_build_object('objectKind', 'PUBLICATION', 'operation', capability,
                    'result', 'SUCCESS', 'eventVersion', target.generation,
                    'requestDigest', target.request_digest));
            INSERT INTO public.${tables.v2OutboxTransitionGuards}(outbox_id, transaction_id)
                VALUES (target.id, txid_current());
            UPDATE public.${tables.v2Idempotency}
               SET state = 'COMPLETED', result_kind = 'PUBLICATION',
                   result_id = target.id, result_status = 'SUCCEEDED', completed_at = observed_at
             WHERE id = target.idempotency_id AND state = 'IN_PROGRESS';
            IF NOT FOUND THEN RAISE EXCEPTION 'publication idempotency completion failed'
                USING ERRCODE = '55000'; END IF;
            DELETE FROM public.${tables.v2OutboxTransitionGuards}
             WHERE outbox_id = target.id AND transaction_id = txid_current();
            RETURN label;
        END;
        $function$;
        REVOKE ALL ON FUNCTION public.v2_acknowledge_projected_publication(
            uuid, text, bigint, text, text, text, uuid
        ) FROM PUBLIC;
    `);
}

export async function down(knex: Knex): Promise<void> {
    // Deliberately do not restore PostgreSQL 13's ambient PUBLIC CREATE grant:
    // rollback must not reintroduce an unsafe cross-role schema capability.
    await knex.raw(`
        LOCK TABLE public.${tables.v2Applications}, public.${tables.v2PublicationOutbox},
            public.${tables.v2AuditEvents}, public.${tables.v2Idempotency}
            IN ACCESS EXCLUSIVE MODE;
        DO $guard$ BEGIN
            IF EXISTS (SELECT 1 FROM public.${tables.v2PublicationOutbox})
                OR EXISTS (SELECT 1 FROM public.${tables.v2AuditEvents}
                    WHERE action IN ('PUBLISH_REQUESTED', 'RESTORE_REQUESTED',
                        'UNPUBLISH_REQUESTED', 'PUBLISHED', 'RESTORED', 'UNPUBLISHED',
                        'PUBLICATION_FAILED'))
            THEN RAISE EXCEPTION 'migration 08 has retained projection state; expand-only rollback refused'
                USING ERRCODE = '55000'; END IF;
        END $guard$;
        DROP FUNCTION public.v2_acknowledge_projected_publication(uuid, text, bigint, text, text, text, uuid);
        DROP FUNCTION public.v2_finish_projected_publication_attempt(uuid, text, bigint, text, text, integer, uuid);
        DROP FUNCTION public.v2_assert_publication_projectable(uuid, text, bigint);
        DROP FUNCTION public.v2_renew_publication(uuid, text, bigint, integer);
        DROP FUNCTION public.v2_claim_publications(text, integer, integer);
        DROP FUNCTION public.v2_bind_publication_key(uuid, text, bigint, text);
        DROP TRIGGER v2_outbox_projection_context_guard ON public.${tables.v2PublicationOutbox};
        DROP FUNCTION public.v2_guard_projection_context();
        DROP FUNCTION public.v2_publication_operation(uuid);
        DROP FUNCTION public.v2_request_publication(uuid, uuid, text, uuid, uuid, uuid, uuid, uuid, text[], bigint, text, text);
        DROP INDEX public.v2_outbox_routing_kid_active_idx;
        DROP INDEX public.v2_outbox_request_audit_unique;
        ALTER TABLE public.${tables.v2PublicationOutbox}
            DROP CONSTRAINT v2_outbox_ack_version_check,
            DROP CONSTRAINT v2_outbox_ack_etag_check,
            DROP CONSTRAINT v2_outbox_request_actor_check,
            DROP CONSTRAINT v2_outbox_request_digest_check,
            DROP CONSTRAINT v2_outbox_routing_host_check,
            DROP CONSTRAINT v2_outbox_routing_kid_check,
            DROP CONSTRAINT v2_outbox_lease_version_safe_integer_check,
            DROP CONSTRAINT v2_outbox_generation_safe_integer_check,
            DROP COLUMN acknowledged_version_id,
            DROP COLUMN acknowledged_etag,
            DROP COLUMN request_audit_id,
            DROP COLUMN request_actor_id,
            DROP COLUMN request_digest,
            DROP COLUMN routing_host,
            DROP COLUMN routing_kid;
        ALTER TABLE public.${tables.v2Applications}
            DROP CONSTRAINT v2_applications_generation_safe_integer_check;
        ALTER TABLE public.${tables.v2Idempotency}
            DROP CONSTRAINT v2_idempotency_expiry_check;
        ALTER TABLE public.${tables.v2Idempotency}
            ADD CONSTRAINT v2_idempotency_expiry_check CHECK (
                expires_at > created_at AND (completed_at IS NULL
                    OR completed_at BETWEEN created_at AND expires_at));
        ALTER TABLE public.${tables.v2AuditEvents}
            DROP CONSTRAINT v2_audit_events_closed_action_check;
        ALTER TABLE public.${tables.v2AuditEvents}
            ADD CONSTRAINT v2_audit_events_closed_action_check CHECK (action IN (
                'AUTH_LOGIN', 'AUTH_LOGOUT', 'AUTH_SESSION_REVOKED',
                'AUTHENTICATION_SUCCEEDED', 'AUTHORIZATION_DECISION',
                'APPLICATION_CREATED', 'APPLICATION_VIEWED', 'RELEASE_READY',
                'RELEASE_LISTED', 'AUDIT_VIEWED', 'BINDINGS_REPLACE'
            ));
        CREATE OR REPLACE FUNCTION public.v2_guard_idempotency()
        RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog
        AS $function$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                IF transaction_timestamp() < OLD.expires_at THEN
                    RAISE EXCEPTION 'unexpired idempotency record cannot be deleted' USING ERRCODE = '55000';
                END IF;
                RETURN OLD;
            END IF;
            IF OLD.expires_at <= transaction_timestamp() THEN
                RAISE EXCEPTION 'expired idempotency record is immutable' USING ERRCODE = '55000';
            END IF;
            IF OLD.state = 'COMPLETED' THEN
                RAISE EXCEPTION 'completed idempotency result is immutable' USING ERRCODE = '55000';
            END IF;
            IF NEW.id IS DISTINCT FROM OLD.id OR NEW.actor_id IS DISTINCT FROM OLD.actor_id
                OR NEW.scope IS DISTINCT FROM OLD.scope OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
                OR NEW.request_digest IS DISTINCT FROM OLD.request_digest OR NEW.created_at IS DISTINCT FROM OLD.created_at
                OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
                OR NEW.state = 'IN_PROGRESS' AND OLD.state <> 'IN_PROGRESS'
            THEN RAISE EXCEPTION 'idempotency request identity is immutable' USING ERRCODE = '55000'; END IF;
            RETURN NEW;
        END $function$;
        CREATE OR REPLACE FUNCTION public.v2_guard_audit_event()
        RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog
        AS $function$
        BEGIN
            IF TG_OP = 'INSERT' THEN
                IF octet_length(NEW.metadata::text) > 4096
                    OR NEW.action NOT IN ('AUTH_LOGIN','AUTH_LOGOUT','AUTH_SESSION_REVOKED',
                        'AUTHENTICATION_SUCCEEDED','AUTHORIZATION_DECISION','APPLICATION_CREATED',
                        'APPLICATION_VIEWED','RELEASE_READY','RELEASE_LISTED','AUDIT_VIEWED','BINDINGS_REPLACE')
                    OR (SELECT count(*) FROM jsonb_object_keys(NEW.metadata)) > 12
                    OR EXISTS (SELECT 1 FROM jsonb_each(NEW.metadata) entry
                         WHERE entry.key NOT IN ('issuer','operation','result','reason','role','source','objectKind',
                            'bindingVersion','requestDigest','bindingCount','eventVersion','claimsVersion','policyVersion','objectId')
                            OR jsonb_typeof(entry.value) IN ('array','object','null')
                            OR (entry.key IN ('issuer','objectId') AND (jsonb_typeof(entry.value) <> 'string'
                                OR char_length(entry.value #>> '{}') > 2048))
                            OR (entry.key = 'requestDigest' AND (jsonb_typeof(entry.value) <> 'string'
                                OR entry.value #>> '{}' !~ '^[0-9a-f]{64}$'))
                            OR (entry.key IN ('bindingVersion','eventVersion','claimsVersion','policyVersion') AND (
                                jsonb_typeof(entry.value) <> 'number' OR entry.value #>> '{}' !~ '^[1-9][0-9]{0,18}$'
                                OR (entry.value #>> '{}')::numeric > 9223372036854775807))
                            OR (entry.key = 'bindingCount' AND (jsonb_typeof(entry.value) <> 'number'
                                OR entry.value #>> '{}' !~ '^(0|[1-9][0-9]{0,2})$'
                                OR (entry.value #>> '{}')::integer > 256))
                            OR (entry.key = 'result' AND entry.value #>> '{}' NOT IN
                                ('ALLOWED','DENIED','APPLIED','VERSION_CONFLICT','SUCCESS'))
                            OR (entry.key = 'role' AND entry.value #>> '{}' NOT IN
                                ('ADMINISTRATOR','OWNER','PUBLISHER','VIEWER','DENIED'))
                            OR (entry.key = 'source' AND entry.value #>> '{}' NOT IN
                                ('ADMINISTRATOR_GROUP','APPLICATION_BINDING','STALE_CLAIMS','NONE'))
                            OR (entry.key = 'objectKind' AND entry.value #>> '{}' NOT IN
                                ('APPLICATION','BINDINGS','SESSION'))
                            OR (entry.key = 'reason' AND entry.value #>> '{}' NOT IN
                                ('USER_LOGOUT','SESSION_ROTATED','TOKEN_KEY_REVOKED','NOT_AUTHORIZED','STALE_CLAIMS'))
                            OR (entry.key = 'operation' AND entry.value #>> '{}' NOT IN (${capabilitySql})))
                THEN RAISE EXCEPTION 'audit metadata exceeds the safe allowlist' USING ERRCODE = '22023'; END IF;
                RETURN NEW;
            END IF;
            RAISE EXCEPTION 'audit events are append-only' USING ERRCODE = '55000';
        END $function$;
    `);
}
