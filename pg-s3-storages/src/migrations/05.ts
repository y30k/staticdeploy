import { Knex } from "knex";

import tables from "../common/tables";

/*
 * Add least-privilege database entry points for M3-05 job leasing and
 * quarantine sealing. Historical job tables and guards remain unchanged.
 */
export async function up(knex: Knex): Promise<void> {
    await knex.raw(`
        ALTER TABLE public.${tables.v2ReleaseJobs}
            ADD COLUMN work_identity text,
            ADD COLUMN completion_identity text,
            ADD CONSTRAINT v2_release_jobs_work_identity_check
                CHECK (work_identity IS NULL OR work_identity ~ '^[0-9a-f]{64}$'),
            ADD CONSTRAINT v2_release_jobs_completion_identity_check
                CHECK (completion_identity IS NULL
                    OR char_length(completion_identity) BETWEEN 2 AND 2048);
        CREATE INDEX v2_release_jobs_due_idx
            ON public.${tables.v2ReleaseJobs}
                (next_attempt_at, created_at, id)
            WHERE state IN ('PENDING', 'RETRY_WAIT');

        CREATE FUNCTION public.v2_guard_release_job_enqueue()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        SET lock_timeout = '5s'
        SET statement_timeout = '30s'
        AS $function$
        DECLARE
            release_state text;
        BEGIN
            IF NEW.kind = 'PROCESS_RELEASE' THEN
                SELECT state INTO release_state
                  FROM public.${tables.v2Releases}
                 WHERE id = NEW.release_id
                 FOR UPDATE;
                IF release_state NOT IN (
                    'UPLOADED', 'PROCESSING', 'AWAITING_DEFAULT_DOCUMENT',
                    'READY'
                ) THEN
                    RAISE EXCEPTION 'processing job release is not eligible'
                        USING ERRCODE = '55000';
                END IF;
            END IF;
            RETURN NEW;
        END;
        $function$;
        REVOKE ALL ON FUNCTION public.v2_guard_release_job_enqueue()
            FROM PUBLIC;
        CREATE TRIGGER v2_release_jobs_enqueue_guard
            BEFORE INSERT ON public.${tables.v2ReleaseJobs}
            FOR EACH ROW EXECUTE FUNCTION public.v2_guard_release_job_enqueue();

        CREATE FUNCTION public.v2_claim_release_jobs(
            requested_owner text,
            requested_lease_ms integer,
            requested_limit integer
        )
        RETURNS SETOF public.${tables.v2ReleaseJobs}
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        SET lock_timeout = '5s'
        SET statement_timeout = '30s'
        AS $function$
        DECLARE
            candidate public.${tables.v2ReleaseJobs}%ROWTYPE;
            claimed public.${tables.v2ReleaseJobs}%ROWTYPE;
            claimed_count integer := 0;
            lease_interval interval;
            observed_at timestamptz;
            release_state text;
            release_manifest_digest text;
        BEGIN
            IF requested_owner IS NULL
                OR requested_owner !~ '^[A-Za-z0-9._:-]{1,200}$'
                OR requested_lease_ms IS NULL
                OR requested_lease_ms NOT BETWEEN 100 AND 900000
                OR requested_limit IS NULL
                OR requested_limit NOT BETWEEN 1 AND 100
            THEN
                RAISE EXCEPTION 'release job claim arguments are invalid'
                    USING ERRCODE = '22023';
            END IF;
            lease_interval := make_interval(secs => requested_lease_ms / 1000.0);

            FOR candidate IN
                SELECT *
                  FROM public.${tables.v2ReleaseJobs}
                 WHERE state = 'LEASED'
                   AND lease_expires_at <= clock_timestamp()
                   AND attempt_count >= max_attempts
                 ORDER BY lease_expires_at, created_at, id
                 FOR UPDATE SKIP LOCKED
                 LIMIT requested_limit
            LOOP
                observed_at := clock_timestamp();
                IF candidate.kind = 'PROCESS_RELEASE' THEN
                    SELECT state, manifest_digest
                      INTO release_state, release_manifest_digest
                      FROM public.${tables.v2Releases}
                     WHERE id = candidate.release_id
                     FOR UPDATE;
                END IF;
                IF candidate.kind = 'PROCESS_RELEASE'
                    AND release_state = 'READY'
                    AND candidate.work_identity IS NOT NULL
                    AND release_manifest_digest = candidate.work_identity
                THEN
                    INSERT INTO public.${tables.v2ReleaseJobTransitionGuards}
                        (job_id, transaction_id)
                    VALUES (candidate.id, txid_current());
                    UPDATE public.${tables.v2ReleaseJobs}
                       SET state = 'SUCCEEDED',
                           lease_owner = NULL,
                           lease_expires_at = NULL,
                           next_attempt_at = NULL,
                           last_error_code = NULL,
                           terminal_reason = NULL,
                           completion_identity = pg_catalog.json_build_array(
                               candidate.lease_owner,
                               candidate.lease_version,
                               'SUCCEEDED', NULL, NULL, NULL,
                               candidate.work_identity
                           )::text,
                           completed_at = observed_at,
                           updated_at = observed_at
                     WHERE id = candidate.id;
                    DELETE FROM public.${tables.v2ReleaseJobTransitionGuards}
                     WHERE job_id = candidate.id
                       AND transaction_id = txid_current();
                ELSE
                    IF candidate.kind = 'PROCESS_RELEASE'
                        AND release_state IN (
                            'PENDING_UPLOAD', 'UPLOADED', 'PROCESSING',
                            'AWAITING_DEFAULT_DOCUMENT'
                        )
                    THEN
                        UPDATE public.${tables.v2Releases}
                           SET state = 'FAILED', updated_at = observed_at
                         WHERE id = candidate.release_id;
                    END IF;
                    INSERT INTO public.${tables.v2ReleaseJobTransitionGuards}
                        (job_id, transaction_id)
                    VALUES (candidate.id, txid_current());
                    UPDATE public.${tables.v2ReleaseJobs}
                       SET state = 'FAILED',
                           lease_owner = NULL,
                           lease_expires_at = NULL,
                           next_attempt_at = NULL,
                           last_error_code = 'LEASE_EXPIRED',
                           terminal_reason = 'FINAL_ATTEMPT_LEASE_EXPIRED',
                           completion_identity = pg_catalog.json_build_array(
                               candidate.lease_owner,
                               candidate.lease_version,
                               'FAILED', 'LEASE_EXPIRED',
                               'FINAL_ATTEMPT_LEASE_EXPIRED', NULL, NULL
                           )::text,
                           completed_at = observed_at,
                           updated_at = observed_at
                     WHERE id = candidate.id;
                    DELETE FROM public.${tables.v2ReleaseJobTransitionGuards}
                     WHERE job_id = candidate.id
                       AND transaction_id = txid_current();
                END IF;
            END LOOP;

            WHILE claimed_count < requested_limit LOOP
                SELECT * INTO candidate
                  FROM public.${tables.v2ReleaseJobs}
                 WHERE state = 'LEASED'
                   AND attempt_count < max_attempts
                   AND lease_expires_at <= clock_timestamp()
                 ORDER BY lease_expires_at, id
                 FOR UPDATE SKIP LOCKED
                 LIMIT 1;
                IF NOT FOUND THEN
                    SELECT * INTO candidate
                      FROM public.${tables.v2ReleaseJobs}
                     WHERE state IN ('PENDING', 'RETRY_WAIT')
                       AND attempt_count < max_attempts
                       AND next_attempt_at <= clock_timestamp()
                     ORDER BY next_attempt_at, created_at, id
                     FOR UPDATE SKIP LOCKED
                     LIMIT 1;
                END IF;
                EXIT WHEN NOT FOUND;
                observed_at := clock_timestamp();
                IF (candidate.state IN ('PENDING', 'RETRY_WAIT')
                        AND candidate.next_attempt_at > observed_at)
                    OR (candidate.state = 'LEASED'
                        AND candidate.lease_expires_at > observed_at)
                THEN
                    EXIT;
                END IF;

                UPDATE public.${tables.v2ReleaseJobs}
                   SET state = 'LEASED',
                       lease_owner = requested_owner,
                       lease_expires_at = observed_at + lease_interval,
                       attempt_count = attempt_count + 1,
                       lease_version = lease_version + 1,
                       next_attempt_at = NULL,
                       last_error_code = NULL,
                       terminal_reason = NULL,
                       completion_identity = NULL,
                       completed_at = NULL,
                       updated_at = observed_at
                 WHERE id = candidate.id
                 RETURNING * INTO claimed;
                claimed_count := claimed_count + 1;
                RETURN NEXT claimed;
            END LOOP;
        END;
        $function$;
        REVOKE ALL ON FUNCTION public.v2_claim_release_jobs(text, integer, integer)
            FROM PUBLIC;

        CREATE FUNCTION public.v2_renew_release_job(
            target_job_id uuid,
            expected_lease_owner text,
            expected_lease_version bigint,
            requested_lease_ms integer
        )
        RETURNS public.${tables.v2ReleaseJobs}
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        SET lock_timeout = '5s'
        SET statement_timeout = '30s'
        AS $function$
        DECLARE
            renewed public.${tables.v2ReleaseJobs}%ROWTYPE;
            observed_at timestamptz;
        BEGIN
            IF target_job_id IS NULL
                OR expected_lease_owner IS NULL
                OR expected_lease_owner !~ '^[A-Za-z0-9._:-]{1,200}$'
                OR expected_lease_version IS NULL
                OR expected_lease_version <= 0
                OR requested_lease_ms IS NULL
                OR requested_lease_ms NOT BETWEEN 100 AND 900000
            THEN
                RAISE EXCEPTION 'release job renewal arguments are invalid'
                    USING ERRCODE = '22023';
            END IF;
            SELECT * INTO renewed
              FROM public.${tables.v2ReleaseJobs}
             WHERE id = target_job_id
             FOR UPDATE;
            observed_at := clock_timestamp();
            IF NOT FOUND
                OR renewed.state <> 'LEASED'
                OR renewed.lease_owner IS DISTINCT FROM expected_lease_owner
                OR renewed.lease_version IS DISTINCT FROM expected_lease_version
                OR renewed.lease_expires_at <= observed_at
            THEN
                RAISE EXCEPTION 'active release job lease fencing does not match'
                    USING ERRCODE = '55000';
            END IF;
            UPDATE public.${tables.v2ReleaseJobs}
               SET lease_expires_at = GREATEST(
                       lease_expires_at,
                       observed_at + make_interval(
                           secs => requested_lease_ms / 1000.0
                       )
                   ),
                   updated_at = observed_at
             WHERE id = target_job_id
             RETURNING * INTO renewed;
            RETURN renewed;
        END;
        $function$;
        REVOKE ALL ON FUNCTION public.v2_renew_release_job(uuid, text, bigint, integer)
            FROM PUBLIC;

        CREATE FUNCTION public.v2_assert_release_job_lease(
            target_job_id uuid,
            expected_lease_owner text,
            expected_lease_version bigint
        )
        RETURNS void
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        SET lock_timeout = '5s'
        SET statement_timeout = '30s'
        AS $function$
        DECLARE
            current public.${tables.v2ReleaseJobs}%ROWTYPE;
            observed_at timestamptz;
        BEGIN
            IF target_job_id IS NULL
                OR expected_lease_owner IS NULL
                OR expected_lease_version <= 0
            THEN
                RAISE EXCEPTION 'release job lease arguments are invalid'
                    USING ERRCODE = '22023';
            END IF;
            SELECT * INTO current
              FROM public.${tables.v2ReleaseJobs}
             WHERE id = target_job_id
             FOR UPDATE;
            observed_at := clock_timestamp();
            IF NOT FOUND
                OR current.state <> 'LEASED'
                OR current.lease_owner IS DISTINCT FROM expected_lease_owner
                OR current.lease_version IS DISTINCT FROM expected_lease_version
                OR current.lease_expires_at <= observed_at
            THEN
                RAISE EXCEPTION 'active release job lease fencing does not match'
                    USING ERRCODE = '55000';
            END IF;
        END;
        $function$;
        REVOKE ALL ON FUNCTION public.v2_assert_release_job_lease(uuid, text, bigint)
            FROM PUBLIC;

        CREATE FUNCTION public.v2_bind_release_job_work(
            target_job_id uuid,
            expected_lease_owner text,
            expected_lease_version bigint,
            requested_work_identity text
        )
        RETURNS void
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        SET lock_timeout = '5s'
        SET statement_timeout = '30s'
        AS $function$
        DECLARE
            current public.${tables.v2ReleaseJobs}%ROWTYPE;
            observed_at timestamptz;
        BEGIN
            IF requested_work_identity IS NULL
                OR requested_work_identity !~ '^[0-9a-f]{64}$'
            THEN
                RAISE EXCEPTION 'release job work identity is invalid'
                    USING ERRCODE = '22023';
            END IF;
            SELECT * INTO current
              FROM public.${tables.v2ReleaseJobs}
             WHERE id = target_job_id
             FOR UPDATE;
            observed_at := clock_timestamp();
            IF NOT FOUND
                OR current.state <> 'LEASED'
                OR current.kind <> 'PROCESS_RELEASE'
                OR current.lease_owner IS DISTINCT FROM expected_lease_owner
                OR current.lease_version IS DISTINCT FROM expected_lease_version
                OR current.lease_expires_at <= observed_at
            THEN
                RAISE EXCEPTION 'active release job lease fencing does not match'
                    USING ERRCODE = '55000';
            END IF;
            IF current.work_identity IS NOT NULL
                AND current.work_identity IS DISTINCT FROM requested_work_identity
            THEN
                RAISE EXCEPTION 'release job work identity conflicts with immutable work'
                    USING ERRCODE = '55000';
            END IF;
            UPDATE public.${tables.v2ReleaseJobs}
               SET work_identity = requested_work_identity,
                   updated_at = observed_at
             WHERE id = target_job_id;
        END;
        $function$;
        REVOKE ALL ON FUNCTION public.v2_bind_release_job_work(uuid, text, bigint, text)
            FROM PUBLIC;

        CREATE FUNCTION public.v2_prepare_quarantine_cleanup(
            target_job_id uuid,
            expected_lease_owner text,
            expected_lease_version bigint,
            requested_minimum_age_ms bigint
        )
        RETURNS void
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        SET lock_timeout = '5s'
        SET statement_timeout = '30s'
        AS $function$
        DECLARE
            target_release_id uuid;
            target_kind text;
            release_state text;
            release_updated_at timestamptz;
            observed_at timestamptz;
        BEGIN
            IF requested_minimum_age_ms IS NULL
                OR requested_minimum_age_ms NOT BETWEEN 100 AND 31536000000
            THEN
                RAISE EXCEPTION 'quarantine cleanup minimum age is outside bounds'
                    USING ERRCODE = '22023';
            END IF;
            PERFORM public.v2_assert_release_job_lease(
                target_job_id,
                expected_lease_owner,
                expected_lease_version
            );
            SELECT release_id, kind
              INTO target_release_id, target_kind
              FROM public.${tables.v2ReleaseJobs}
             WHERE id = target_job_id;
            IF target_kind <> 'CLEANUP_QUARANTINE' THEN
                RAISE EXCEPTION 'release job is not a quarantine cleanup job'
                    USING ERRCODE = '55000';
            END IF;

            SELECT state, updated_at INTO release_state, release_updated_at
              FROM public.${tables.v2Releases}
             WHERE id = target_release_id
             FOR UPDATE;
            observed_at := clock_timestamp();
            IF NOT FOUND THEN
                RAISE EXCEPTION 'release not found'
                    USING ERRCODE = 'P0002';
            END IF;
            IF release_state NOT IN ('PENDING_UPLOAD', 'UPLOADED', 'FAILED')
                OR release_updated_at > observed_at
                    - make_interval(secs => requested_minimum_age_ms / 1000.0)
            THEN
                RAISE EXCEPTION 'release is not eligible for quarantine cleanup'
                    USING ERRCODE = '55000';
            END IF;
            IF EXISTS (
                SELECT 1
                  FROM public.${tables.v2ReleaseJobs}
                 WHERE release_id = target_release_id
                   AND kind = 'PROCESS_RELEASE'
                   AND state NOT IN ('SUCCEEDED', 'FAILED')
            ) THEN
                RAISE EXCEPTION 'active processing job blocks quarantine cleanup'
                    USING ERRCODE = '55000';
            END IF;
            IF release_state <> 'FAILED' THEN
                UPDATE public.${tables.v2Releases}
                   SET state = 'FAILED',
                       updated_at = observed_at
                 WHERE id = target_release_id
                   AND state = release_state;
            END IF;
        END;
        $function$;
        REVOKE ALL ON FUNCTION public.v2_prepare_quarantine_cleanup(uuid, text, bigint, bigint)
            FROM PUBLIC;

        CREATE FUNCTION public.v2_finish_release_job(
            target_job_id uuid,
            expected_release_id uuid,
            expected_kind text,
            expected_lease_owner text,
            expected_lease_version bigint,
            outcome text,
            error_code text,
            failure_reason text,
            retry_delay_ms integer,
            expected_manifest_digest text
        )
        RETURNS void
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        SET lock_timeout = '5s'
        SET statement_timeout = '30s'
        AS $function$
        DECLARE
            current public.${tables.v2ReleaseJobs}%ROWTYPE;
            ready_state text;
            ready_manifest_digest text;
            retry_at timestamptz;
            requested_completion_identity text;
        BEGIN
            IF expected_lease_owner IS NULL
                OR expected_lease_owner !~ '^[A-Za-z0-9._:-]{1,200}$'
                OR expected_lease_version IS NULL
                OR expected_lease_version <= 0
                OR expected_kind IS NULL
                OR expected_kind NOT IN ('PROCESS_RELEASE', 'CLEANUP_QUARANTINE')
                OR outcome IS NULL
                OR outcome NOT IN ('RETRY', 'SUCCEEDED', 'FAILED')
            THEN
                RAISE EXCEPTION 'release job completion arguments are invalid'
                    USING ERRCODE = '22023';
            END IF;
            IF outcome = 'RETRY' THEN
                IF error_code IS NULL OR error_code !~ '^[A-Z][A-Z0-9_]{0,127}$'
                    OR failure_reason IS NOT NULL
                    OR retry_delay_ms IS NULL
                    OR retry_delay_ms NOT BETWEEN 1 AND 900000
                    OR expected_manifest_digest IS NOT NULL
                THEN
                    RAISE EXCEPTION 'release job retry arguments are invalid'
                        USING ERRCODE = '22023';
                END IF;
            ELSIF outcome = 'SUCCEEDED' THEN
                IF error_code IS NOT NULL OR failure_reason IS NOT NULL
                    OR retry_delay_ms IS NOT NULL
                    OR (expected_kind = 'PROCESS_RELEASE'
                        AND (expected_manifest_digest IS NULL
                            OR expected_manifest_digest !~ '^[0-9a-f]{64}$'))
                    OR (expected_kind = 'CLEANUP_QUARANTINE'
                        AND expected_manifest_digest IS NOT NULL)
                THEN
                    RAISE EXCEPTION 'release job success arguments are invalid'
                        USING ERRCODE = '22023';
                END IF;
            ELSIF error_code IS NULL
                OR error_code !~ '^[A-Z][A-Z0-9_]{0,127}$'
                OR failure_reason IS NULL
                OR failure_reason !~ '^[A-Z][A-Z0-9_]{0,127}$'
                OR retry_delay_ms IS NOT NULL
                OR expected_manifest_digest IS NOT NULL
            THEN
                RAISE EXCEPTION 'release job failure arguments are invalid'
                    USING ERRCODE = '22023';
            END IF;
            requested_completion_identity := pg_catalog.json_build_array(
                expected_lease_owner, expected_lease_version, outcome,
                error_code, failure_reason, retry_delay_ms,
                expected_manifest_digest
            )::text;

            SELECT * INTO current
              FROM public.${tables.v2ReleaseJobs}
             WHERE id = target_job_id
             FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'release job not found'
                    USING ERRCODE = 'P0002';
            END IF;
            IF current.release_id IS DISTINCT FROM expected_release_id
                OR current.kind IS DISTINCT FROM expected_kind
                OR current.lease_version IS DISTINCT FROM expected_lease_version
            THEN
                RAISE EXCEPTION 'release job identity fencing does not match'
                    USING ERRCODE = '55000';
            END IF;
            IF current.state IN ('RETRY_WAIT', 'SUCCEEDED', 'FAILED') THEN
                IF current.completion_identity IS NOT DISTINCT FROM requested_completion_identity THEN
                    RETURN;
                END IF;
                RAISE EXCEPTION 'release job completion conflicts with immutable result'
                    USING ERRCODE = '55000';
            END IF;
            IF current.state <> 'LEASED'
                OR current.lease_owner IS DISTINCT FROM expected_lease_owner
            THEN
                RAISE EXCEPTION 'active release job lease fencing does not match'
                    USING ERRCODE = '55000';
            END IF;

            IF outcome = 'SUCCEEDED' AND current.kind = 'PROCESS_RELEASE' THEN
                SELECT state, manifest_digest
                  INTO ready_state, ready_manifest_digest
                  FROM public.${tables.v2Releases}
                 WHERE id = current.release_id
                 FOR SHARE;
                IF current.work_identity IS DISTINCT FROM expected_manifest_digest
                    OR ready_state IS DISTINCT FROM 'READY'
                    OR ready_manifest_digest IS DISTINCT FROM expected_manifest_digest
                THEN
                    RAISE EXCEPTION 'processing job result does not match immutable READY work'
                        USING ERRCODE = '55000';
                END IF;
            ELSIF outcome = 'SUCCEEDED' THEN
                SELECT state INTO ready_state
                  FROM public.${tables.v2Releases}
                 WHERE id = current.release_id
                 FOR SHARE;
                IF ready_state IS DISTINCT FROM 'FAILED' THEN
                    RAISE EXCEPTION 'cleanup job result requires a sealed FAILED release'
                        USING ERRCODE = '55000';
                END IF;
            ELSIF outcome = 'FAILED'
                AND current.kind = 'PROCESS_RELEASE'
            THEN
                SELECT state INTO ready_state
                  FROM public.${tables.v2Releases}
                 WHERE id = current.release_id
                 FOR UPDATE;
                IF ready_state = 'READY' THEN
                    RAISE EXCEPTION 'READY processing work cannot be failed'
                        USING ERRCODE = '55000';
                ELSIF ready_state NOT IN (
                    'PENDING_UPLOAD', 'UPLOADED', 'PROCESSING',
                    'AWAITING_DEFAULT_DOCUMENT', 'FAILED'
                ) THEN
                    RAISE EXCEPTION 'processing release cannot enter FAILED state'
                        USING ERRCODE = '55000';
                ELSIF ready_state <> 'FAILED' THEN
                    UPDATE public.${tables.v2Releases}
                       SET state = 'FAILED', updated_at = clock_timestamp()
                     WHERE id = current.release_id;
                END IF;
            END IF;
            IF outcome = 'RETRY' THEN
                retry_at := clock_timestamp()
                    + make_interval(secs => retry_delay_ms / 1000.0);
            END IF;
            UPDATE public.${tables.v2ReleaseJobs}
               SET completion_identity = requested_completion_identity
             WHERE id = target_job_id;
            PERFORM public.v2_finish_release_job_attempt(
                target_job_id,
                expected_lease_owner,
                expected_lease_version,
                outcome,
                error_code,
                failure_reason,
                retry_at
            );
        END;
        $function$;
        REVOKE ALL ON FUNCTION public.v2_finish_release_job(
            uuid, uuid, text, text, bigint, text, text, text, integer, text
        ) FROM PUBLIC;
    `);
}

export async function down(knex: Knex): Promise<void> {
    await knex.raw(`
        LOCK TABLE
            public.${tables.v2ReleaseJobs},
            public.${tables.v2Releases},
            public.${tables.v2UploadFiles}
        IN ACCESS EXCLUSIVE MODE;

        DO $guard$
        BEGIN
            IF EXISTS (SELECT 1 FROM public.${tables.v2ReleaseJobs}) THEN
                RAISE EXCEPTION 'migration 05 has retained release jobs; expand-only rollback refused'
                    USING ERRCODE = '55000';
            END IF;
        END;
        $guard$;

        DROP FUNCTION IF EXISTS public.v2_finish_release_job(
            uuid, uuid, text, text, bigint, text, text, text, integer, text
        );
        DROP TRIGGER IF EXISTS v2_release_jobs_enqueue_guard
            ON public.${tables.v2ReleaseJobs};
        DROP FUNCTION IF EXISTS public.v2_guard_release_job_enqueue();
        DROP FUNCTION IF EXISTS public.v2_prepare_quarantine_cleanup(
            uuid, text, bigint, bigint
        );
        DROP FUNCTION IF EXISTS public.v2_bind_release_job_work(
            uuid, text, bigint, text
        );
        DROP FUNCTION IF EXISTS public.v2_assert_release_job_lease(
            uuid, text, bigint
        );
        DROP FUNCTION IF EXISTS public.v2_renew_release_job(
            uuid, text, bigint, integer
        );
        DROP FUNCTION IF EXISTS public.v2_claim_release_jobs(
            text, integer, integer
        );
        DROP INDEX IF EXISTS public.v2_release_jobs_due_idx;
        ALTER TABLE public.${tables.v2ReleaseJobs}
            DROP CONSTRAINT v2_release_jobs_completion_identity_check,
            DROP CONSTRAINT v2_release_jobs_work_identity_check,
            DROP COLUMN completion_identity,
            DROP COLUMN work_identity;
    `);
}
