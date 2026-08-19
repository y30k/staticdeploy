import { Knex } from "knex";

import tables from "../common/tables";

/*
 * Add operational v2 session, idempotency, release-job, and publication-outbox
 * state. This migration is additive and leaves all legacy tables and rows
 * unchanged.
 */
export async function up(knex: Knex): Promise<void> {
    await knex.raw(`
        ALTER TABLE public.${tables.v2Applications}
            ADD CONSTRAINT v2_applications_routing_identity_unique
                UNIQUE (id, routing_id);

        CREATE TABLE public.${tables.v2Sessions} (
            id uuid PRIMARY KEY,
            subject_id text NOT NULL,
            issuer text NOT NULL,
            claims jsonb NOT NULL DEFAULT '{}'::jsonb,
            claims_version bigint NOT NULL DEFAULT 1,
            csrf_token_digest text NOT NULL,
            token_key_id text,
            token_nonce bytea,
            encrypted_token_material bytea,
            created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
            last_seen_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
            idle_expires_at timestamptz NOT NULL,
            absolute_expires_at timestamptz NOT NULL,
            revoked_at timestamptz,
            revocation_reason text,
            CONSTRAINT v2_sessions_subject_id_check
                CHECK (char_length(subject_id) BETWEEN 1 AND 512),
            CONSTRAINT v2_sessions_issuer_check
                CHECK (char_length(issuer) BETWEEN 1 AND 2048),
            CONSTRAINT v2_sessions_claims_object_check
                CHECK (jsonb_typeof(claims) = 'object'),
            CONSTRAINT v2_sessions_claims_version_check
                CHECK (claims_version > 0),
            CONSTRAINT v2_sessions_csrf_digest_check
                CHECK (csrf_token_digest ~ '^[0-9a-f]{64}$'),
            CONSTRAINT v2_sessions_token_envelope_check
                CHECK ((token_key_id IS NULL
                        AND token_nonce IS NULL
                        AND encrypted_token_material IS NULL)
                    OR (token_key_id IS NOT NULL
                        AND token_nonce IS NOT NULL
                        AND encrypted_token_material IS NOT NULL
                        AND char_length(token_key_id) BETWEEN 1 AND 200
                        AND octet_length(token_nonce) BETWEEN 12 AND 32
                        AND octet_length(encrypted_token_material)
                            BETWEEN 16 AND 1048576)),
            CONSTRAINT v2_sessions_expiry_check
                CHECK (created_at <= last_seen_at
                    AND last_seen_at < idle_expires_at
                    AND idle_expires_at <= absolute_expires_at),
            CONSTRAINT v2_sessions_revocation_check
                CHECK ((revoked_at IS NULL AND revocation_reason IS NULL)
                    OR (revoked_at IS NOT NULL
                        AND revoked_at BETWEEN created_at AND absolute_expires_at
                        AND revocation_reason IS NOT NULL
                        AND revocation_reason ~ '^[A-Z][A-Z0-9_]{0,127}$'))
        );
        REVOKE ALL ON public.${tables.v2Sessions} FROM PUBLIC;

        CREATE TABLE public.${tables.v2Idempotency} (
            id uuid PRIMARY KEY,
            actor_id text NOT NULL,
            scope text NOT NULL,
            idempotency_key text NOT NULL,
            request_digest text NOT NULL,
            state text NOT NULL DEFAULT 'IN_PROGRESS',
            result_kind text,
            result_id uuid,
            result_status text,
            created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
            completed_at timestamptz,
            expires_at timestamptz NOT NULL,
            CONSTRAINT v2_idempotency_actor_id_check
                CHECK (char_length(actor_id) BETWEEN 1 AND 512),
            CONSTRAINT v2_idempotency_scope_check
                CHECK (scope ~ '^[a-z][a-z0-9._-]{0,127}$'),
            CONSTRAINT v2_idempotency_key_check
                CHECK (char_length(idempotency_key) BETWEEN 16 AND 200),
            CONSTRAINT v2_idempotency_request_digest_check
                CHECK (request_digest ~ '^[0-9a-f]{64}$'),
            CONSTRAINT v2_idempotency_state_check
                CHECK (state IN ('IN_PROGRESS', 'COMPLETED')),
            CONSTRAINT v2_idempotency_result_kind_check
                CHECK (result_kind IS NULL
                    OR result_kind ~ '^[A-Z][A-Z0-9_]{0,127}$'),
            CONSTRAINT v2_idempotency_result_status_check
                CHECK (result_status IS NULL
                    OR result_status IN ('SUCCEEDED', 'FAILED')),
            CONSTRAINT v2_idempotency_result_check
                CHECK ((state = 'IN_PROGRESS'
                        AND result_kind IS NULL
                        AND result_id IS NULL
                        AND result_status IS NULL
                        AND completed_at IS NULL)
                    OR (state = 'COMPLETED'
                        AND result_kind IS NOT NULL
                        AND result_id IS NOT NULL
                        AND result_status IS NOT NULL
                        AND completed_at IS NOT NULL)),
            CONSTRAINT v2_idempotency_expiry_check
                CHECK (expires_at > created_at
                    AND (completed_at IS NULL
                        OR completed_at BETWEEN created_at AND expires_at)),
            CONSTRAINT v2_idempotency_actor_scope_key_unique
                UNIQUE (actor_id, scope, idempotency_key)
        );

        CREATE TABLE public.${tables.v2ReleaseJobs} (
            id uuid PRIMARY KEY,
            release_id uuid NOT NULL,
            kind text NOT NULL DEFAULT 'PROCESS_RELEASE',
            state text NOT NULL DEFAULT 'PENDING',
            lease_owner text,
            lease_expires_at timestamptz,
            attempt_count integer NOT NULL DEFAULT 0,
            lease_version bigint NOT NULL DEFAULT 0,
            max_attempts integer NOT NULL DEFAULT 5,
            next_attempt_at timestamptz DEFAULT transaction_timestamp(),
            last_error_code text,
            terminal_reason text,
            created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
            updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
            completed_at timestamptz,
            CONSTRAINT v2_release_jobs_release_fk
                FOREIGN KEY (release_id)
                REFERENCES public.${tables.v2Releases}(id)
                ON DELETE RESTRICT,
            CONSTRAINT v2_release_jobs_kind_check
                CHECK (kind IN ('PROCESS_RELEASE', 'CLEANUP_QUARANTINE')),
            CONSTRAINT v2_release_jobs_state_check
                CHECK (state IN (
                    'PENDING', 'LEASED', 'RETRY_WAIT', 'SUCCEEDED', 'FAILED'
                )),
            CONSTRAINT v2_release_jobs_lease_owner_check
                CHECK (lease_owner IS NULL
                    OR char_length(lease_owner) BETWEEN 1 AND 200),
            CONSTRAINT v2_release_jobs_attempt_check
                CHECK (attempt_count BETWEEN 0 AND max_attempts
                    AND lease_version >= 0
                    AND max_attempts BETWEEN 1 AND 100),
            CONSTRAINT v2_release_jobs_error_code_check
                CHECK (last_error_code IS NULL
                    OR last_error_code ~ '^[A-Z][A-Z0-9_]{0,127}$'),
            CONSTRAINT v2_release_jobs_terminal_reason_check
                CHECK (terminal_reason IS NULL
                    OR terminal_reason ~ '^[A-Z][A-Z0-9_]{0,127}$'),
            CONSTRAINT v2_release_jobs_lifecycle_check
                CHECK ((state = 'PENDING'
                        AND lease_owner IS NULL
                        AND lease_expires_at IS NULL
                        AND next_attempt_at IS NOT NULL
                        AND last_error_code IS NULL
                        AND completed_at IS NULL
                        AND terminal_reason IS NULL)
                    OR (state = 'RETRY_WAIT'
                        AND lease_owner IS NULL
                        AND lease_expires_at IS NULL
                        AND next_attempt_at IS NOT NULL
                        AND last_error_code IS NOT NULL
                        AND completed_at IS NULL
                        AND terminal_reason IS NULL)
                    OR (state = 'LEASED'
                        AND lease_owner IS NOT NULL
                        AND lease_expires_at IS NOT NULL
                        AND lease_expires_at > updated_at
                        AND attempt_count > 0
                        AND next_attempt_at IS NULL
                        AND last_error_code IS NULL
                        AND completed_at IS NULL
                        AND terminal_reason IS NULL)
                    OR (state = 'SUCCEEDED'
                        AND lease_owner IS NULL
                        AND lease_expires_at IS NULL
                        AND next_attempt_at IS NULL
                        AND last_error_code IS NULL
                        AND completed_at IS NOT NULL
                        AND terminal_reason IS NULL)
                    OR (state = 'FAILED'
                        AND lease_owner IS NULL
                        AND lease_expires_at IS NULL
                        AND next_attempt_at IS NULL
                        AND last_error_code IS NOT NULL
                        AND completed_at IS NOT NULL
                        AND terminal_reason IS NOT NULL)),
            CONSTRAINT v2_release_jobs_completed_check
                CHECK (completed_at IS NULL OR completed_at >= created_at),
            CONSTRAINT v2_release_jobs_release_kind_unique
                UNIQUE (release_id, kind)
        );

        CREATE TABLE public.${tables.v2ReleaseJobTransitionGuards} (
            job_id uuid PRIMARY KEY,
            transaction_id bigint NOT NULL,
            CONSTRAINT v2_release_job_transition_guards_job_fk
                FOREIGN KEY (job_id)
                REFERENCES public.${tables.v2ReleaseJobs}(id)
                ON DELETE CASCADE
        );
        REVOKE ALL ON public.${tables.v2ReleaseJobTransitionGuards} FROM PUBLIC;

        CREATE TABLE public.${tables.v2PublicationOutbox} (
            id uuid PRIMARY KEY,
            application_id uuid NOT NULL,
            routing_id uuid NOT NULL,
            release_id uuid,
            generation bigint NOT NULL,
            operation text NOT NULL,
            idempotency_id uuid NOT NULL,
            payload_kind text NOT NULL,
            manifest_digest text,
            object_prefix text,
            state text NOT NULL DEFAULT 'PENDING',
            lease_owner text,
            lease_expires_at timestamptz,
            attempt_count integer NOT NULL DEFAULT 0,
            lease_version bigint NOT NULL DEFAULT 0,
            max_attempts integer NOT NULL DEFAULT 10,
            next_attempt_at timestamptz DEFAULT transaction_timestamp(),
            acknowledged_at timestamptz,
            projection_digest text,
            last_error_code text,
            created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
            updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
            CONSTRAINT v2_publication_outbox_application_fk
                FOREIGN KEY (application_id, routing_id)
                REFERENCES public.${tables.v2Applications}(id, routing_id)
                ON DELETE RESTRICT,
            CONSTRAINT v2_publication_outbox_release_fk
                FOREIGN KEY (application_id, release_id)
                REFERENCES public.${tables.v2Releases}(application_id, id)
                ON DELETE RESTRICT,
            CONSTRAINT v2_publication_outbox_generation_check
                CHECK (generation > 0),
            CONSTRAINT v2_publication_outbox_operation_check
                CHECK (operation IN ('PUBLISH', 'RESTORE', 'UNPUBLISH')),
            CONSTRAINT v2_publication_outbox_payload_kind_check
                CHECK (payload_kind IN ('RELEASE', 'TOMBSTONE')),
            CONSTRAINT v2_publication_outbox_payload_check
                CHECK ((payload_kind = 'RELEASE'
                        AND operation IN ('PUBLISH', 'RESTORE')
                        AND release_id IS NOT NULL
                        AND manifest_digest IS NOT NULL
                        AND object_prefix IS NOT NULL
                        AND manifest_digest ~ '^[0-9a-f]{64}$'
                        AND char_length(object_prefix) BETWEEN 1 AND 1024
                        AND object_prefix !~ '^/'
                        AND object_prefix !~ '[\\\\]'
                        AND object_prefix !~ '(^|/)([.]|[.][.])(/|$)')
                    OR (payload_kind = 'TOMBSTONE'
                        AND operation = 'UNPUBLISH'
                        AND release_id IS NULL
                        AND manifest_digest IS NULL
                        AND object_prefix IS NULL)),
            CONSTRAINT v2_publication_outbox_state_check
                CHECK (state IN ('PENDING', 'LEASED', 'ACKNOWLEDGED', 'FAILED')),
            CONSTRAINT v2_publication_outbox_lease_owner_check
                CHECK (lease_owner IS NULL
                    OR char_length(lease_owner) BETWEEN 1 AND 200),
            CONSTRAINT v2_publication_outbox_attempt_check
                CHECK (attempt_count BETWEEN 0 AND max_attempts
                    AND lease_version >= 0
                    AND max_attempts BETWEEN 1 AND 100),
            CONSTRAINT v2_publication_outbox_projection_digest_check
                CHECK (projection_digest IS NULL
                    OR projection_digest ~ '^[0-9a-f]{64}$'),
            CONSTRAINT v2_publication_outbox_error_code_check
                CHECK (last_error_code IS NULL
                    OR last_error_code ~ '^[A-Z][A-Z0-9_]{0,127}$'),
            CONSTRAINT v2_publication_outbox_lifecycle_check
                CHECK ((state = 'PENDING'
                        AND lease_owner IS NULL
                        AND lease_expires_at IS NULL
                        AND next_attempt_at IS NOT NULL
                        AND acknowledged_at IS NULL
                        AND projection_digest IS NULL)
                    OR (state = 'LEASED'
                        AND lease_owner IS NOT NULL
                        AND lease_expires_at IS NOT NULL
                        AND lease_expires_at > updated_at
                        AND attempt_count > 0
                        AND next_attempt_at IS NULL
                        AND acknowledged_at IS NULL
                        AND projection_digest IS NULL)
                    OR (state = 'ACKNOWLEDGED'
                        AND lease_owner IS NULL
                        AND lease_expires_at IS NULL
                        AND next_attempt_at IS NULL
                        AND acknowledged_at IS NOT NULL
                        AND projection_digest IS NOT NULL
                        AND last_error_code IS NULL)
                    OR (state = 'FAILED'
                        AND lease_owner IS NULL
                        AND lease_expires_at IS NULL
                        AND next_attempt_at IS NULL
                        AND acknowledged_at IS NULL
                        AND projection_digest IS NULL
                        AND last_error_code IS NOT NULL)),
            CONSTRAINT v2_publication_outbox_ack_time_check
                CHECK (acknowledged_at IS NULL OR acknowledged_at >= created_at),
            CONSTRAINT v2_publication_outbox_application_generation_unique
                UNIQUE (application_id, generation),
            CONSTRAINT v2_publication_outbox_idempotency_unique
                UNIQUE (idempotency_id)
        );

        CREATE TABLE public.${tables.v2OutboxTransitionGuards} (
            outbox_id uuid PRIMARY KEY,
            transaction_id bigint NOT NULL,
            CONSTRAINT v2_outbox_transition_guards_outbox_fk
                FOREIGN KEY (outbox_id)
                REFERENCES public.${tables.v2PublicationOutbox}(id)
                ON DELETE CASCADE
        );
        REVOKE ALL ON public.${tables.v2OutboxTransitionGuards} FROM PUBLIC;

        CREATE FUNCTION public.v2_guard_served_projection()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        AS $function$
        BEGIN
            IF NEW.served_generation IS DISTINCT FROM OLD.served_generation
                OR NEW.served_current_release_id
                    IS DISTINCT FROM OLD.served_current_release_id
            THEN
                IF NOT EXISTS (
                    SELECT 1
                      FROM public.${tables.v2OutboxTransitionGuards} AS guard
                      JOIN public.${tables.v2PublicationOutbox} AS outbox
                        ON outbox.id = guard.outbox_id
                     WHERE guard.transaction_id = txid_current()
                       AND outbox.application_id = NEW.id
                       AND outbox.generation = NEW.served_generation
                       AND outbox.release_id
                           IS NOT DISTINCT FROM NEW.served_current_release_id
                ) THEN
                    RAISE EXCEPTION 'served projection must use v2_acknowledge_publication'
                        USING ERRCODE = '55000';
                END IF;
            END IF;
            RETURN NEW;
        END;
        $function$;

        CREATE TRIGGER v2_applications_served_projection_guard
            BEFORE UPDATE ON public.${tables.v2Applications}
            FOR EACH ROW EXECUTE FUNCTION public.v2_guard_served_projection();

        CREATE INDEX v2_sessions_subject_active_idx
            ON public.${tables.v2Sessions}
                (subject_id, absolute_expires_at, id)
            WHERE revoked_at IS NULL;
        CREATE INDEX v2_sessions_active_expiry_idx
            ON public.${tables.v2Sessions}
                (idle_expires_at, absolute_expires_at, id)
            WHERE revoked_at IS NULL;
        CREATE INDEX v2_sessions_revoked_cleanup_idx
            ON public.${tables.v2Sessions} (revoked_at, id)
            WHERE revoked_at IS NOT NULL;
        CREATE INDEX v2_idempotency_actor_scope_created_idx
            ON public.${tables.v2Idempotency}
                (actor_id, scope, created_at DESC, id DESC);
        CREATE INDEX v2_idempotency_expiry_idx
            ON public.${tables.v2Idempotency} (expires_at, id);
        CREATE INDEX v2_release_jobs_claim_idx
            ON public.${tables.v2ReleaseJobs}
                (state, next_attempt_at, created_at, id)
            WHERE state IN ('PENDING', 'RETRY_WAIT');
        CREATE INDEX v2_release_jobs_lease_expiry_idx
            ON public.${tables.v2ReleaseJobs} (lease_expires_at, id)
            WHERE state = 'LEASED';
        CREATE INDEX v2_publication_outbox_claim_idx
            ON public.${tables.v2PublicationOutbox}
                (state, next_attempt_at, created_at, id)
            WHERE state = 'PENDING';
        CREATE INDEX v2_publication_outbox_lease_expiry_idx
            ON public.${tables.v2PublicationOutbox} (lease_expires_at, id)
            WHERE state = 'LEASED';
        CREATE INDEX v2_publication_outbox_application_generation_idx
            ON public.${tables.v2PublicationOutbox}
                (application_id, generation DESC, id DESC);

        CREATE FUNCTION public.v2_guard_session()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $function$
        BEGIN
            IF TG_OP = 'INSERT' THEN
                IF NEW.created_at > transaction_timestamp()
                    OR NEW.last_seen_at > transaction_timestamp()
                THEN
                    RAISE EXCEPTION 'session timestamps cannot be in the future'
                        USING ERRCODE = '55000';
                END IF;
                RETURN NEW;
            END IF;
            IF TG_OP = 'DELETE' THEN
                IF OLD.revoked_at IS NULL
                    AND transaction_timestamp() < OLD.absolute_expires_at
                    AND transaction_timestamp() < OLD.idle_expires_at
                THEN
                    RAISE EXCEPTION 'active session cannot be deleted'
                        USING ERRCODE = '55000';
                END IF;
                RETURN OLD;
            END IF;
            IF OLD.revoked_at IS NOT NULL THEN
                RAISE EXCEPTION 'revoked session is immutable'
                    USING ERRCODE = '55000';
            END IF;
            IF OLD.idle_expires_at <= transaction_timestamp()
                OR OLD.absolute_expires_at <= transaction_timestamp()
            THEN
                RAISE EXCEPTION 'expired session is immutable'
                    USING ERRCODE = '55000';
            END IF;
            IF NEW.id IS DISTINCT FROM OLD.id
                OR NEW.subject_id IS DISTINCT FROM OLD.subject_id
                OR NEW.issuer IS DISTINCT FROM OLD.issuer
                OR NEW.created_at IS DISTINCT FROM OLD.created_at
                OR NEW.absolute_expires_at IS DISTINCT FROM OLD.absolute_expires_at
                OR NEW.csrf_token_digest IS DISTINCT FROM OLD.csrf_token_digest
                OR NEW.claims_version < OLD.claims_version
                OR (NEW.claims IS DISTINCT FROM OLD.claims
                    AND NEW.claims_version <= OLD.claims_version)
                OR NEW.last_seen_at < OLD.last_seen_at
                OR NEW.last_seen_at > transaction_timestamp()
                OR NEW.idle_expires_at < OLD.idle_expires_at
                OR (NEW.revoked_at IS NOT NULL
                    AND NEW.revoked_at > transaction_timestamp())
                OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NULL)
            THEN
                RAISE EXCEPTION 'session identity and time bounds cannot regress'
                    USING ERRCODE = '55000';
            END IF;
            RETURN NEW;
        END;
        $function$;

        CREATE TRIGGER v2_sessions_guard
            BEFORE INSERT OR UPDATE OR DELETE ON public.${tables.v2Sessions}
            FOR EACH ROW EXECUTE FUNCTION public.v2_guard_session();

        CREATE FUNCTION public.v2_guard_session_truncate()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $function$
        BEGIN
            RAISE EXCEPTION 'sessions cannot be truncated'
                USING ERRCODE = '55000';
        END;
        $function$;

        CREATE TRIGGER v2_sessions_no_truncate
            BEFORE TRUNCATE ON public.${tables.v2Sessions}
            FOR EACH STATEMENT EXECUTE FUNCTION public.v2_guard_session_truncate();

        CREATE FUNCTION public.v2_guard_idempotency()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $function$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                IF transaction_timestamp() < OLD.expires_at THEN
                    RAISE EXCEPTION 'unexpired idempotency record cannot be deleted'
                        USING ERRCODE = '55000';
                END IF;
                RETURN OLD;
            END IF;
            IF OLD.expires_at <= transaction_timestamp() THEN
                RAISE EXCEPTION 'expired idempotency record is immutable'
                    USING ERRCODE = '55000';
            END IF;
            IF OLD.state = 'COMPLETED' THEN
                RAISE EXCEPTION 'completed idempotency result is immutable'
                    USING ERRCODE = '55000';
            END IF;
            IF NEW.id IS DISTINCT FROM OLD.id
                OR NEW.actor_id IS DISTINCT FROM OLD.actor_id
                OR NEW.scope IS DISTINCT FROM OLD.scope
                OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
                OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
                OR NEW.created_at IS DISTINCT FROM OLD.created_at
                OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
                OR NEW.state = 'IN_PROGRESS' AND OLD.state <> 'IN_PROGRESS'
            THEN
                RAISE EXCEPTION 'idempotency request identity is immutable'
                    USING ERRCODE = '55000';
            END IF;
            RETURN NEW;
        END;
        $function$;

        CREATE TRIGGER v2_idempotency_guard
            BEFORE UPDATE OR DELETE ON public.${tables.v2Idempotency}
            FOR EACH ROW EXECUTE FUNCTION public.v2_guard_idempotency();

        CREATE FUNCTION public.v2_guard_idempotency_truncate()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $function$
        BEGIN
            RAISE EXCEPTION 'idempotency records cannot be truncated'
                USING ERRCODE = '55000';
        END;
        $function$;

        CREATE TRIGGER v2_idempotency_no_truncate
            BEFORE TRUNCATE ON public.${tables.v2Idempotency}
            FOR EACH STATEMENT EXECUTE FUNCTION public.v2_guard_idempotency_truncate();

        CREATE FUNCTION public.v2_guard_release_job()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        AS $function$
        BEGIN
            IF TG_OP = 'INSERT' THEN
                IF NEW.state <> 'PENDING'
                    OR NEW.attempt_count <> 0
                    OR NEW.lease_version <> 0
                THEN
                    RAISE EXCEPTION 'release job must start pending and unclaimed'
                        USING ERRCODE = '55000';
                END IF;
                RETURN NEW;
            END IF;
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'release job rows cannot be deleted'
                    USING ERRCODE = '55000';
            END IF;
            IF OLD.state IN ('SUCCEEDED', 'FAILED') THEN
                RAISE EXCEPTION 'terminal release job is immutable'
                    USING ERRCODE = '55000';
            END IF;
            IF NEW.id IS DISTINCT FROM OLD.id
                OR NEW.release_id IS DISTINCT FROM OLD.release_id
                OR NEW.kind IS DISTINCT FROM OLD.kind
                OR NEW.created_at IS DISTINCT FROM OLD.created_at
                OR NEW.max_attempts IS DISTINCT FROM OLD.max_attempts
                OR NEW.updated_at < OLD.updated_at
            THEN
                RAISE EXCEPTION 'release job identity is immutable'
                    USING ERRCODE = '55000';
            END IF;

            IF OLD.state IN ('PENDING', 'RETRY_WAIT')
                AND NEW.state = 'LEASED'
            THEN
                IF OLD.next_attempt_at > clock_timestamp() THEN
                    RAISE EXCEPTION 'release job is not due for claim'
                        USING ERRCODE = '55000';
                END IF;
                IF NEW.attempt_count <> OLD.attempt_count + 1
                    OR NEW.lease_version <> OLD.lease_version + 1
                THEN
                    RAISE EXCEPTION 'release job claim must advance attempt and lease version'
                        USING ERRCODE = '55000';
                END IF;
            ELSIF OLD.state = 'LEASED' AND NEW.state = 'LEASED' THEN
                IF OLD.lease_expires_at > clock_timestamp() THEN
                    IF NEW.lease_owner IS DISTINCT FROM OLD.lease_owner
                        OR NEW.attempt_count <> OLD.attempt_count
                        OR NEW.lease_version <> OLD.lease_version
                        OR NEW.lease_expires_at < OLD.lease_expires_at
                    THEN
                        RAISE EXCEPTION 'live release job lease cannot be reclaimed'
                            USING ERRCODE = '55000';
                    END IF;
                ELSIF NEW.attempt_count <> OLD.attempt_count + 1
                    OR NEW.lease_version <> OLD.lease_version + 1
                THEN
                    RAISE EXCEPTION 'expired release job reclaim must advance fencing'
                        USING ERRCODE = '55000';
                END IF;
            ELSIF OLD.state = 'LEASED'
                AND NEW.state IN ('RETRY_WAIT', 'SUCCEEDED', 'FAILED')
            THEN
                IF NEW.attempt_count <> OLD.attempt_count
                    OR NEW.lease_version <> OLD.lease_version
                THEN
                    RAISE EXCEPTION 'release job completion must retain lease fencing'
                        USING ERRCODE = '55000';
                END IF;
                IF NOT EXISTS (
                    SELECT 1
                      FROM public.${tables.v2ReleaseJobTransitionGuards}
                     WHERE job_id = NEW.id
                       AND transaction_id = txid_current()
                ) THEN
                    RAISE EXCEPTION 'leased release job transition must use v2_finish_release_job_attempt'
                        USING ERRCODE = '55000';
                END IF;
            ELSIF OLD.state = NEW.state
                AND OLD.state IN ('PENDING', 'RETRY_WAIT')
            THEN
                IF NEW.attempt_count <> OLD.attempt_count
                    OR NEW.lease_version <> OLD.lease_version
                THEN
                    RAISE EXCEPTION 'unclaimed release job fencing cannot change'
                        USING ERRCODE = '55000';
                END IF;
            ELSE
                RAISE EXCEPTION 'illegal release job state transition'
                    USING ERRCODE = '55000';
            END IF;
            RETURN NEW;
        END;
        $function$;

        CREATE TRIGGER v2_release_jobs_guard
            BEFORE INSERT OR UPDATE OR DELETE ON public.${tables.v2ReleaseJobs}
            FOR EACH ROW EXECUTE FUNCTION public.v2_guard_release_job();

        CREATE FUNCTION public.v2_finish_release_job_attempt(
            target_job_id uuid,
            expected_lease_owner text,
            expected_lease_version bigint,
            outcome text,
            error_code text,
            failure_reason text,
            requested_retry_at timestamptz
        )
        RETURNS void
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        AS $function$
        DECLARE
            current_state text;
            current_owner text;
            current_version bigint;
            current_lease_expires_at timestamptz;
            current_attempt_count integer;
            current_max_attempts integer;
            observed_at timestamptz;
            effective_retry_at timestamptz;
        BEGIN
            IF expected_lease_owner IS NULL
                OR expected_lease_version <= 0
                OR outcome IS NULL
                OR outcome NOT IN ('RETRY', 'SUCCEEDED', 'FAILED')
            THEN
                RAISE EXCEPTION 'release job transition arguments are invalid'
                    USING ERRCODE = '22023';
            END IF;

            SELECT state, lease_owner, lease_version, lease_expires_at,
                   attempt_count, max_attempts
              INTO current_state,
                   current_owner,
                   current_version,
                   current_lease_expires_at,
                   current_attempt_count,
                   current_max_attempts
              FROM public.${tables.v2ReleaseJobs}
             WHERE id = target_job_id
             FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'leased release job not found'
                    USING ERRCODE = 'P0002';
            END IF;
            observed_at := clock_timestamp();
            IF current_state <> 'LEASED'
                OR current_owner IS DISTINCT FROM expected_lease_owner
                OR current_version IS DISTINCT FROM expected_lease_version
                OR current_lease_expires_at <= observed_at
            THEN
                RAISE EXCEPTION 'active release job lease fencing does not match'
                    USING ERRCODE = '55000';
            END IF;

            IF outcome = 'RETRY' THEN
                IF current_attempt_count >= current_max_attempts THEN
                    RAISE EXCEPTION 'final release job attempt cannot be retried'
                        USING ERRCODE = '55000';
                END IF;
                IF error_code IS NULL OR failure_reason IS NOT NULL THEN
                    RAISE EXCEPTION 'release job retry arguments are invalid'
                        USING ERRCODE = '22023';
                END IF;
                effective_retry_at := GREATEST(
                    COALESCE(requested_retry_at, observed_at),
                    observed_at
                );
            ELSIF outcome = 'SUCCEEDED' THEN
                IF error_code IS NOT NULL
                    OR failure_reason IS NOT NULL
                    OR requested_retry_at IS NOT NULL
                THEN
                    RAISE EXCEPTION 'release job success arguments are invalid'
                        USING ERRCODE = '22023';
                END IF;
            ELSIF error_code IS NULL
                OR failure_reason IS NULL
                OR requested_retry_at IS NOT NULL
            THEN
                RAISE EXCEPTION 'release job failure arguments are invalid'
                    USING ERRCODE = '22023';
            END IF;

            INSERT INTO public.${tables.v2ReleaseJobTransitionGuards}
                (job_id, transaction_id)
            VALUES (target_job_id, txid_current());

            IF outcome = 'RETRY' THEN
                UPDATE public.${tables.v2ReleaseJobs}
                   SET state = 'RETRY_WAIT',
                       lease_owner = NULL,
                       lease_expires_at = NULL,
                       next_attempt_at = effective_retry_at,
                       last_error_code = error_code,
                       terminal_reason = NULL,
                       completed_at = NULL,
                       updated_at = observed_at
                 WHERE id = target_job_id;
            ELSIF outcome = 'SUCCEEDED' THEN
                UPDATE public.${tables.v2ReleaseJobs}
                   SET state = 'SUCCEEDED',
                       lease_owner = NULL,
                       lease_expires_at = NULL,
                       next_attempt_at = NULL,
                       last_error_code = NULL,
                       terminal_reason = NULL,
                       completed_at = observed_at,
                       updated_at = observed_at
                 WHERE id = target_job_id;
            ELSE
                UPDATE public.${tables.v2ReleaseJobs}
                   SET state = 'FAILED',
                       lease_owner = NULL,
                       lease_expires_at = NULL,
                       next_attempt_at = NULL,
                       last_error_code = error_code,
                       terminal_reason = failure_reason,
                       completed_at = observed_at,
                       updated_at = observed_at
                 WHERE id = target_job_id;
            END IF;

            DELETE FROM public.${tables.v2ReleaseJobTransitionGuards}
             WHERE job_id = target_job_id
               AND transaction_id = txid_current();
        END;
        $function$;
        REVOKE ALL ON FUNCTION public.v2_finish_release_job_attempt(
            uuid, text, bigint, text, text, text, timestamptz
        ) FROM PUBLIC;

        CREATE FUNCTION public.v2_guard_release_jobs_truncate()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $function$
        BEGIN
            RAISE EXCEPTION 'release jobs cannot be truncated'
                USING ERRCODE = '55000';
        END;
        $function$;

        CREATE TRIGGER v2_release_jobs_no_truncate
            BEFORE TRUNCATE ON public.${tables.v2ReleaseJobs}
            FOR EACH STATEMENT EXECUTE FUNCTION public.v2_guard_release_jobs_truncate();

        CREATE FUNCTION public.v2_guard_publication_outbox()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        AS $function$
        DECLARE
            current_routing_id uuid;
            current_release_id uuid;
            current_generation bigint;
            current_release_state text;
            current_manifest_digest text;
            current_published_at timestamptz;
            current_idempotency_scope text;
            current_idempotency_state text;
            current_idempotency_expires_at timestamptz;
        BEGIN
            IF TG_OP = 'INSERT' THEN
                IF NEW.state <> 'PENDING'
                    OR NEW.attempt_count <> 0
                    OR NEW.lease_version <> 0
                    OR NEW.last_error_code IS NOT NULL
                THEN
                    RAISE EXCEPTION 'outbox row must start pending and unclaimed'
                        USING ERRCODE = '55000';
                END IF;
                SELECT routing_id, desired_current_release_id, desired_generation
                  INTO current_routing_id, current_release_id, current_generation
                  FROM public.${tables.v2Applications}
                 WHERE id = NEW.application_id
                 FOR SHARE;
                IF NOT FOUND
                    OR NEW.routing_id IS DISTINCT FROM current_routing_id
                    OR NEW.release_id IS DISTINCT FROM current_release_id
                    OR NEW.generation IS DISTINCT FROM current_generation
                THEN
                    RAISE EXCEPTION 'outbox payload must match desired application generation'
                        USING ERRCODE = '55000';
                END IF;
                SELECT scope, state, expires_at
                  INTO current_idempotency_scope,
                       current_idempotency_state,
                       current_idempotency_expires_at
                  FROM public.${tables.v2Idempotency}
                 WHERE id = NEW.idempotency_id
                 FOR SHARE;
                IF NOT FOUND THEN
                    RAISE EXCEPTION 'outbox idempotency identity not found'
                        USING ERRCODE = '23503';
                END IF;
                IF current_idempotency_state <> 'IN_PROGRESS'
                    OR current_idempotency_expires_at <= clock_timestamp()
                    OR current_idempotency_scope <> (CASE NEW.operation
                        WHEN 'PUBLISH' THEN 'release.publish'
                        WHEN 'RESTORE' THEN 'release.restore'
                        WHEN 'UNPUBLISH' THEN 'application.unpublish'
                    END)
                THEN
                    RAISE EXCEPTION 'outbox idempotency scope or state does not match operation'
                        USING ERRCODE = '55000';
                END IF;
                IF NEW.payload_kind = 'RELEASE' THEN
                    SELECT state, manifest_digest, published_at
                      INTO current_release_state,
                           current_manifest_digest,
                           current_published_at
                      FROM public.${tables.v2Releases}
                     WHERE application_id = NEW.application_id
                       AND id = NEW.release_id
                     FOR SHARE;
                    IF NOT FOUND
                        OR current_release_state <> 'READY'
                        OR NEW.manifest_digest IS DISTINCT FROM current_manifest_digest
                        OR (NEW.operation = 'PUBLISH'
                            AND current_published_at IS NOT NULL)
                        OR (NEW.operation = 'RESTORE'
                            AND current_published_at IS NULL)
                        OR NEW.object_prefix IS DISTINCT FROM
                            ('v2/releases/' || NEW.application_id::text || '/' || NEW.release_id::text)
                    THEN
                        RAISE EXCEPTION 'outbox release payload must match immutable READY release'
                            USING ERRCODE = '55000';
                    END IF;
                END IF;
                RETURN NEW;
            END IF;
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'publication outbox rows cannot be deleted'
                    USING ERRCODE = '55000';
            END IF;
            IF OLD.state IN ('ACKNOWLEDGED', 'FAILED') THEN
                RAISE EXCEPTION 'terminal outbox row is immutable'
                    USING ERRCODE = '55000';
            END IF;
            IF NEW.id IS DISTINCT FROM OLD.id
                OR NEW.application_id IS DISTINCT FROM OLD.application_id
                OR NEW.routing_id IS DISTINCT FROM OLD.routing_id
                OR NEW.release_id IS DISTINCT FROM OLD.release_id
                OR NEW.generation IS DISTINCT FROM OLD.generation
                OR NEW.operation IS DISTINCT FROM OLD.operation
                OR NEW.idempotency_id IS DISTINCT FROM OLD.idempotency_id
                OR NEW.payload_kind IS DISTINCT FROM OLD.payload_kind
                OR NEW.manifest_digest IS DISTINCT FROM OLD.manifest_digest
                OR NEW.object_prefix IS DISTINCT FROM OLD.object_prefix
                OR NEW.created_at IS DISTINCT FROM OLD.created_at
                OR NEW.max_attempts IS DISTINCT FROM OLD.max_attempts
                OR NEW.updated_at < OLD.updated_at
            THEN
                RAISE EXCEPTION 'outbox identity and payload are immutable'
                    USING ERRCODE = '55000';
            END IF;

            IF OLD.state = 'PENDING' AND NEW.state = 'LEASED' THEN
                IF OLD.next_attempt_at > clock_timestamp() THEN
                    RAISE EXCEPTION 'publication outbox row is not due for claim'
                        USING ERRCODE = '55000';
                END IF;
                IF NEW.attempt_count <> OLD.attempt_count + 1
                    OR NEW.lease_version <> OLD.lease_version + 1
                THEN
                    RAISE EXCEPTION 'outbox claim must advance attempt and lease version'
                        USING ERRCODE = '55000';
                END IF;
            ELSIF OLD.state = 'LEASED' AND NEW.state = 'LEASED' THEN
                IF OLD.lease_expires_at > clock_timestamp() THEN
                    IF NEW.lease_owner IS DISTINCT FROM OLD.lease_owner
                        OR NEW.attempt_count <> OLD.attempt_count
                        OR NEW.lease_version <> OLD.lease_version
                        OR NEW.lease_expires_at < OLD.lease_expires_at
                    THEN
                        RAISE EXCEPTION 'live outbox lease cannot be reclaimed'
                            USING ERRCODE = '55000';
                    END IF;
                ELSIF NEW.attempt_count <> OLD.attempt_count + 1
                    OR NEW.lease_version <> OLD.lease_version + 1
                THEN
                    RAISE EXCEPTION 'expired outbox reclaim must advance fencing'
                        USING ERRCODE = '55000';
                END IF;
            ELSIF OLD.state = 'LEASED'
                AND NEW.state IN ('PENDING', 'ACKNOWLEDGED', 'FAILED')
            THEN
                IF NEW.attempt_count <> OLD.attempt_count
                    OR NEW.lease_version <> OLD.lease_version
                THEN
                    RAISE EXCEPTION 'outbox completion must retain lease fencing'
                        USING ERRCODE = '55000';
                END IF;
                IF NOT EXISTS (
                    SELECT 1
                      FROM public.${tables.v2OutboxTransitionGuards}
                     WHERE outbox_id = NEW.id
                       AND transaction_id = txid_current()
                ) THEN
                    RAISE EXCEPTION 'leased outbox transition must use a guarded function'
                        USING ERRCODE = '55000';
                END IF;
            ELSIF OLD.state = NEW.state AND OLD.state = 'PENDING' THEN
                IF NEW.attempt_count <> OLD.attempt_count
                    OR NEW.lease_version <> OLD.lease_version
                THEN
                    RAISE EXCEPTION 'pending outbox fencing cannot change'
                        USING ERRCODE = '55000';
                END IF;
            ELSE
                RAISE EXCEPTION 'illegal publication outbox state transition'
                    USING ERRCODE = '55000';
            END IF;
            RETURN NEW;
        END;
        $function$;

        CREATE TRIGGER v2_publication_outbox_guard
            BEFORE INSERT OR UPDATE OR DELETE
            ON public.${tables.v2PublicationOutbox}
            FOR EACH ROW EXECUTE FUNCTION public.v2_guard_publication_outbox();

        CREATE FUNCTION public.v2_finish_publication_attempt(
            target_outbox_id uuid,
            expected_lease_owner text,
            expected_lease_version bigint,
            outcome text,
            error_code text,
            requested_retry_at timestamptz
        )
        RETURNS void
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        AS $function$
        DECLARE
            current_state text;
            current_owner text;
            current_version bigint;
            current_lease_expires_at timestamptz;
            current_attempt_count integer;
            current_max_attempts integer;
            observed_at timestamptz;
            effective_retry_at timestamptz;
        BEGIN
            IF expected_lease_owner IS NULL
                OR expected_lease_version <= 0
                OR outcome IS NULL
                OR outcome NOT IN ('RETRY', 'FAILED')
                OR error_code IS NULL
            THEN
                RAISE EXCEPTION 'publication attempt arguments are invalid'
                    USING ERRCODE = '22023';
            END IF;

            SELECT state, lease_owner, lease_version, lease_expires_at,
                   attempt_count, max_attempts
              INTO current_state,
                   current_owner,
                   current_version,
                   current_lease_expires_at,
                   current_attempt_count,
                   current_max_attempts
              FROM public.${tables.v2PublicationOutbox}
             WHERE id = target_outbox_id
             FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'leased outbox row not found'
                    USING ERRCODE = 'P0002';
            END IF;
            observed_at := clock_timestamp();
            IF current_state <> 'LEASED'
                OR current_owner IS DISTINCT FROM expected_lease_owner
                OR current_version IS DISTINCT FROM expected_lease_version
                OR current_lease_expires_at <= observed_at
            THEN
                RAISE EXCEPTION 'active outbox lease fencing does not match'
                    USING ERRCODE = '55000';
            END IF;

            IF outcome = 'RETRY' THEN
                IF current_attempt_count >= current_max_attempts THEN
                    RAISE EXCEPTION 'final publication attempt cannot be retried'
                        USING ERRCODE = '55000';
                END IF;
                effective_retry_at := GREATEST(
                    COALESCE(requested_retry_at, observed_at),
                    observed_at
                );
            ELSIF requested_retry_at IS NOT NULL THEN
                RAISE EXCEPTION 'failed publication cannot schedule retry'
                    USING ERRCODE = '22023';
            END IF;

            INSERT INTO public.${tables.v2OutboxTransitionGuards}
                (outbox_id, transaction_id)
            VALUES (target_outbox_id, txid_current());

            IF outcome = 'RETRY' THEN
                UPDATE public.${tables.v2PublicationOutbox}
                   SET state = 'PENDING',
                       lease_owner = NULL,
                       lease_expires_at = NULL,
                       next_attempt_at = effective_retry_at,
                       acknowledged_at = NULL,
                       projection_digest = NULL,
                       last_error_code = error_code,
                       updated_at = observed_at
                 WHERE id = target_outbox_id;
            ELSE
                UPDATE public.${tables.v2PublicationOutbox}
                   SET state = 'FAILED',
                       lease_owner = NULL,
                       lease_expires_at = NULL,
                       next_attempt_at = NULL,
                       acknowledged_at = NULL,
                       projection_digest = NULL,
                       last_error_code = error_code,
                       updated_at = observed_at
                 WHERE id = target_outbox_id;
            END IF;

            DELETE FROM public.${tables.v2OutboxTransitionGuards}
             WHERE outbox_id = target_outbox_id
               AND transaction_id = txid_current();
        END;
        $function$;
        REVOKE ALL ON FUNCTION public.v2_finish_publication_attempt(
            uuid, text, bigint, text, text, timestamptz
        ) FROM PUBLIC;

        CREATE FUNCTION public.v2_acknowledge_publication(
            target_outbox_id uuid,
            expected_lease_owner text,
            expected_lease_version bigint,
            projection_digest_value text
        )
        RETURNS text
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        AS $function$
        DECLARE
            target_application_id uuid;
            target_release_id uuid;
            target_generation bigint;
            current_state text;
            current_lease_owner text;
            current_lease_version bigint;
            current_lease_expires_at timestamptz;
            desired_release_id uuid;
            desired_generation bigint;
            assigned_version_label text;
            acknowledgement_time timestamptz;
        BEGIN
            IF expected_lease_owner IS NULL
                OR projection_digest_value !~ '^[0-9a-f]{64}$'
            THEN
                RAISE EXCEPTION 'acknowledgement arguments are invalid'
                    USING ERRCODE = '22023';
            END IF;

            SELECT application_id
              INTO target_application_id
              FROM public.${tables.v2PublicationOutbox}
             WHERE id = target_outbox_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'leased outbox row not found'
                    USING ERRCODE = 'P0002';
            END IF;

            SELECT application.desired_current_release_id,
                   application.desired_generation
              INTO desired_release_id, desired_generation
              FROM public.${tables.v2Applications} AS application
             WHERE application.id = target_application_id
             FOR UPDATE;

            SELECT release_id,
                   generation,
                   state,
                   lease_owner,
                   lease_version,
                   lease_expires_at
              INTO target_release_id,
                   target_generation,
                   current_state,
                   current_lease_owner,
                   current_lease_version,
                   current_lease_expires_at
              FROM public.${tables.v2PublicationOutbox}
             WHERE id = target_outbox_id
               AND application_id = target_application_id
             FOR UPDATE;
            acknowledgement_time := clock_timestamp();
            IF NOT FOUND
                OR current_state <> 'LEASED'
                OR current_lease_owner IS DISTINCT FROM expected_lease_owner
                OR current_lease_version IS DISTINCT FROM expected_lease_version
                OR current_lease_expires_at <= acknowledgement_time
            THEN
                RAISE EXCEPTION 'active outbox lease fencing does not match'
                    USING ERRCODE = '55000';
            END IF;
            IF target_generation IS DISTINCT FROM desired_generation
                OR target_release_id IS DISTINCT FROM desired_release_id
            THEN
                RAISE EXCEPTION 'outbox generation is no longer desired'
                    USING ERRCODE = '55000';
            END IF;

            INSERT INTO public.${tables.v2OutboxTransitionGuards}
                (outbox_id, transaction_id)
            VALUES (target_outbox_id, txid_current());

            UPDATE public.${tables.v2Applications} AS application
               SET served_current_release_id = target_release_id,
                   served_generation = target_generation,
                   updated_at = acknowledgement_time
             WHERE application.id = target_application_id
               AND application.desired_generation = target_generation
               AND application.desired_current_release_id
                   IS NOT DISTINCT FROM target_release_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'outbox generation changed during acknowledgement'
                    USING ERRCODE = '55000';
            END IF;

            IF target_release_id IS NOT NULL THEN
                SELECT public.v2_claim_release_version(
                    target_release_id,
                    acknowledgement_time
                ) INTO assigned_version_label;
            END IF;

            UPDATE public.${tables.v2PublicationOutbox}
               SET state = 'ACKNOWLEDGED',
                   lease_owner = NULL,
                   lease_expires_at = NULL,
                   next_attempt_at = NULL,
                   acknowledged_at = acknowledgement_time,
                   projection_digest = projection_digest_value,
                   last_error_code = NULL,
                   updated_at = acknowledgement_time
             WHERE id = target_outbox_id;

            DELETE FROM public.${tables.v2OutboxTransitionGuards}
             WHERE outbox_id = target_outbox_id
               AND transaction_id = txid_current();
            RETURN assigned_version_label;
        END;
        $function$;
        REVOKE ALL ON FUNCTION public.v2_acknowledge_publication(
            uuid, text, bigint, text
        ) FROM PUBLIC;

        CREATE FUNCTION public.v2_guard_publication_outbox_truncate()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $function$
        BEGIN
            RAISE EXCEPTION 'publication outbox cannot be truncated'
                USING ERRCODE = '55000';
        END;
        $function$;

        CREATE TRIGGER v2_publication_outbox_no_truncate
            BEFORE TRUNCATE ON public.${tables.v2PublicationOutbox}
            FOR EACH STATEMENT
            EXECUTE FUNCTION public.v2_guard_publication_outbox_truncate();
    `);
}

export async function down(knex: Knex): Promise<void> {
    await knex.raw(`
        LOCK TABLE
            public.${tables.v2Applications},
            public.${tables.v2Sessions},
            public.${tables.v2Idempotency},
            public.${tables.v2ReleaseJobs},
            public.${tables.v2ReleaseJobTransitionGuards},
            public.${tables.v2PublicationOutbox},
            public.${tables.v2OutboxTransitionGuards}
        IN ACCESS EXCLUSIVE MODE;

        DO $guard$
        BEGIN
            IF EXISTS (SELECT 1 FROM public.${tables.v2Sessions})
                OR EXISTS (SELECT 1 FROM public.${tables.v2Idempotency})
                OR EXISTS (SELECT 1 FROM public.${tables.v2ReleaseJobs})
                OR EXISTS (SELECT 1 FROM public.${tables.v2ReleaseJobTransitionGuards})
                OR EXISTS (SELECT 1 FROM public.${tables.v2PublicationOutbox})
                OR EXISTS (SELECT 1 FROM public.${tables.v2OutboxTransitionGuards})
            THEN
                RAISE EXCEPTION 'migration 04 contains retained v2 operational data; expand-only rollback refused'
                    USING ERRCODE = '55000';
            END IF;
        END;
        $guard$;

        DROP TRIGGER IF EXISTS v2_applications_served_projection_guard
            ON public.${tables.v2Applications};
        DROP FUNCTION IF EXISTS public.v2_acknowledge_publication(
            uuid, text, bigint, text
        );
        DROP FUNCTION IF EXISTS public.v2_finish_publication_attempt(
            uuid, text, bigint, text, text, timestamptz
        );
        DROP FUNCTION IF EXISTS public.v2_finish_release_job_attempt(
            uuid, text, bigint, text, text, text, timestamptz
        );
        DROP TABLE IF EXISTS public.${tables.v2OutboxTransitionGuards};
        DROP TABLE IF EXISTS public.${tables.v2PublicationOutbox};
        DROP TABLE IF EXISTS public.${tables.v2ReleaseJobTransitionGuards};
        DROP TABLE IF EXISTS public.${tables.v2ReleaseJobs};
        DROP TABLE IF EXISTS public.${tables.v2Idempotency};
        DROP TABLE IF EXISTS public.${tables.v2Sessions};
        ALTER TABLE public.${tables.v2Applications}
            DROP CONSTRAINT IF EXISTS v2_applications_routing_identity_unique;
        DROP FUNCTION IF EXISTS public.v2_guard_served_projection();
        DROP FUNCTION IF EXISTS public.v2_guard_publication_outbox_truncate();
        DROP FUNCTION IF EXISTS public.v2_guard_publication_outbox();
        DROP FUNCTION IF EXISTS public.v2_guard_release_jobs_truncate();
        DROP FUNCTION IF EXISTS public.v2_guard_release_job();
        DROP FUNCTION IF EXISTS public.v2_guard_idempotency_truncate();
        DROP FUNCTION IF EXISTS public.v2_guard_idempotency();
        DROP FUNCTION IF EXISTS public.v2_guard_session_truncate();
        DROP FUNCTION IF EXISTS public.v2_guard_session();
    `);
}
