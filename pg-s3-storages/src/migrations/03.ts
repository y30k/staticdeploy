import { Knex } from "knex";

import tables from "../common/tables";

/*
 * Add the v2 application, release, upload, binding, and audit foundation.
 * This migration is additive: the legacy tables and rows are not modified.
 */
export async function up(knex: Knex): Promise<void> {
    await knex.raw(`
        CREATE TABLE public.${tables.v2Applications} (
            id uuid PRIMARY KEY,
            name text NOT NULL,
            description text NOT NULL DEFAULT '',
            tags jsonb NOT NULL DEFAULT '[]'::jsonb,
            owner_metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
            visibility text NOT NULL DEFAULT 'INTERNAL',
            status text NOT NULL DEFAULT 'ACTIVE',
            routing_id uuid NOT NULL,
            desired_current_release_id uuid,
            served_current_release_id uuid,
            desired_generation bigint NOT NULL DEFAULT 0,
            served_generation bigint NOT NULL DEFAULT 0,
            archived_at timestamptz,
            created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
            updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
            CONSTRAINT v2_applications_name_length_check
                CHECK (char_length(name) BETWEEN 1 AND 200),
            CONSTRAINT v2_applications_description_length_check
                CHECK (char_length(description) <= 10000),
            CONSTRAINT v2_applications_tags_array_check
                CHECK (jsonb_typeof(tags) = 'array'),
            CONSTRAINT v2_applications_owner_metadata_object_check
                CHECK (jsonb_typeof(owner_metadata) = 'object'),
            CONSTRAINT v2_applications_visibility_check
                CHECK (visibility IN ('INTERNAL')),
            CONSTRAINT v2_applications_status_check
                CHECK (status IN ('ACTIVE', 'ARCHIVED')),
            CONSTRAINT v2_applications_archive_state_check
                CHECK ((status = 'ACTIVE' AND archived_at IS NULL)
                    OR (status = 'ARCHIVED' AND archived_at IS NOT NULL)),
            CONSTRAINT v2_applications_generation_check
                CHECK (desired_generation >= 0
                    AND served_generation >= 0
                    AND served_generation <= desired_generation),
            CONSTRAINT v2_applications_name_unique UNIQUE (name),
            CONSTRAINT v2_applications_routing_id_unique UNIQUE (routing_id)
        );

        CREATE TABLE public.${tables.v2Releases} (
            id uuid PRIMARY KEY,
            application_id uuid NOT NULL,
            state text NOT NULL DEFAULT 'PENDING_UPLOAD',
            default_path text,
            manifest_digest text,
            finalized_at timestamptz,
            published_at timestamptz,
            version_label text,
            created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
            updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
            CONSTRAINT v2_releases_application_fk
                FOREIGN KEY (application_id)
                REFERENCES public.${tables.v2Applications}(id)
                ON DELETE RESTRICT,
            CONSTRAINT v2_releases_state_check
                CHECK (state IN (
                    'PENDING_UPLOAD',
                    'UPLOADED',
                    'PROCESSING',
                    'AWAITING_DEFAULT_DOCUMENT',
                    'READY',
                    'FAILED'
                )),
            CONSTRAINT v2_releases_default_path_check
                CHECK (default_path IS NULL OR (
                    char_length(default_path) BETWEEN 1 AND 1024
                    AND default_path !~ '[\\\\]'
                    AND default_path !~ '(^|/)([.]|[.][.])(/|$)'
                    AND default_path !~ '(^/|//|/$)'
                )),
            CONSTRAINT v2_releases_manifest_digest_check
                CHECK (manifest_digest IS NULL
                    OR manifest_digest ~ '^[0-9a-f]{64}$'),
            CONSTRAINT v2_releases_ready_fields_check
                CHECK (state <> 'READY' OR (
                    default_path IS NOT NULL
                    AND manifest_digest IS NOT NULL
                    AND finalized_at IS NOT NULL
                )),
            CONSTRAINT v2_releases_publication_pair_check
                CHECK ((published_at IS NULL AND version_label IS NULL)
                    OR (published_at IS NOT NULL AND version_label IS NOT NULL)),
            CONSTRAINT v2_releases_publication_state_check
                CHECK (published_at IS NULL OR state = 'READY'),
            CONSTRAINT v2_releases_version_label_check
                CHECK (version_label IS NULL
                    OR version_label ~ '^[0-9]{4}[.][0-9]{2}[.][0-9]{2}-[0-9]{2}[.][0-9]{2}[.][0-9]{2}(-([2-9]|[1-9][0-9]+)){0,1}$'),
            CONSTRAINT v2_releases_application_version_unique
                UNIQUE (application_id, version_label),
            CONSTRAINT v2_releases_application_identity_unique
                UNIQUE (application_id, id)
        );

        CREATE TABLE public.${tables.v2PublicationGuards} (
            release_id uuid PRIMARY KEY,
            transaction_id bigint NOT NULL,
            CONSTRAINT v2_publication_guards_release_fk
                FOREIGN KEY (release_id)
                REFERENCES public.${tables.v2Releases}(id)
                ON DELETE CASCADE
        );
        REVOKE ALL ON public.${tables.v2PublicationGuards} FROM PUBLIC;

        ALTER TABLE public.${tables.v2Applications}
            ADD CONSTRAINT v2_applications_desired_release_fk
                FOREIGN KEY (id, desired_current_release_id)
                REFERENCES public.${tables.v2Releases}(application_id, id)
                ON DELETE RESTRICT,
            ADD CONSTRAINT v2_applications_served_release_fk
                FOREIGN KEY (id, served_current_release_id)
                REFERENCES public.${tables.v2Releases}(application_id, id)
                ON DELETE RESTRICT;

        CREATE TABLE public.${tables.v2UploadFiles} (
            id uuid PRIMARY KEY,
            release_id uuid NOT NULL,
            state text NOT NULL DEFAULT 'DECLARED',
            declared_path text NOT NULL,
            declared_size bigint NOT NULL,
            declared_digest text,
            observed_path text,
            observed_size bigint,
            observed_digest text,
            created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
            observed_at timestamptz,
            CONSTRAINT v2_upload_files_release_fk
                FOREIGN KEY (release_id)
                REFERENCES public.${tables.v2Releases}(id)
                ON DELETE CASCADE,
            CONSTRAINT v2_upload_files_state_check
                CHECK (state IN ('DECLARED', 'OBSERVED', 'REJECTED')),
            CONSTRAINT v2_upload_files_declared_path_check
                CHECK (
                    char_length(declared_path) BETWEEN 1 AND 1024
                    AND declared_path !~ '[\\\\]'
                    AND declared_path !~ '(^|/)([.]|[.][.])(/|$)'
                    AND declared_path !~ '(^/|//|/$)'
                ),
            CONSTRAINT v2_upload_files_declared_size_check
                CHECK (declared_size >= 0),
            CONSTRAINT v2_upload_files_declared_digest_check
                CHECK (declared_digest IS NULL
                    OR declared_digest ~ '^[0-9a-f]{64}$'),
            CONSTRAINT v2_upload_files_observed_path_check
                CHECK (observed_path IS NULL OR (
                    char_length(observed_path) BETWEEN 1 AND 1024
                    AND observed_path !~ '[\\\\]'
                    AND observed_path !~ '(^|/)([.]|[.][.])(/|$)'
                    AND observed_path !~ '(^/|//|/$)'
                )),
            CONSTRAINT v2_upload_files_observed_size_check
                CHECK (observed_size IS NULL OR observed_size >= 0),
            CONSTRAINT v2_upload_files_observed_digest_check
                CHECK (observed_digest IS NULL
                    OR observed_digest ~ '^[0-9a-f]{64}$'),
            CONSTRAINT v2_upload_files_observed_fields_check
                CHECK ((state = 'OBSERVED'
                    AND observed_path IS NOT NULL
                    AND observed_size IS NOT NULL
                    AND observed_digest IS NOT NULL
                    AND observed_at IS NOT NULL)
                    OR (state <> 'OBSERVED'
                        AND observed_path IS NULL
                        AND observed_size IS NULL
                        AND observed_digest IS NULL
                        AND observed_at IS NULL)),
            CONSTRAINT v2_upload_files_release_path_unique
                UNIQUE (release_id, declared_path)
        );

        CREATE TABLE public.${tables.v2Bindings} (
            id uuid PRIMARY KEY,
            application_id uuid NOT NULL,
            group_id text NOT NULL,
            role text NOT NULL,
            created_by text NOT NULL,
            created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
            CONSTRAINT v2_bindings_application_fk
                FOREIGN KEY (application_id)
                REFERENCES public.${tables.v2Applications}(id)
                ON DELETE CASCADE,
            CONSTRAINT v2_bindings_group_id_check
                CHECK (char_length(group_id) BETWEEN 1 AND 512),
            CONSTRAINT v2_bindings_created_by_check
                CHECK (char_length(created_by) BETWEEN 1 AND 512),
            CONSTRAINT v2_bindings_role_check
                CHECK (role IN ('OWNER', 'PUBLISHER', 'VIEWER')),
            CONSTRAINT v2_bindings_application_group_unique
                UNIQUE (application_id, group_id)
        );

        CREATE TABLE public.${tables.v2AuditEvents} (
            id uuid PRIMARY KEY,
            actor_id text NOT NULL,
            action text NOT NULL,
            application_id uuid,
            release_id uuid,
            occurred_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
            metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
            CONSTRAINT v2_audit_events_actor_id_check
                CHECK (char_length(actor_id) BETWEEN 1 AND 512),
            CONSTRAINT v2_audit_events_action_check
                CHECK (action ~ '^[A-Z][A-Z0-9_]{0,127}$'),
            CONSTRAINT v2_audit_events_metadata_object_check
                CHECK (jsonb_typeof(metadata) = 'object'),
            CONSTRAINT v2_audit_events_release_scope_check
                CHECK (release_id IS NULL OR application_id IS NOT NULL),
            CONSTRAINT v2_audit_events_application_fk
                FOREIGN KEY (application_id)
                REFERENCES public.${tables.v2Applications}(id)
                ON DELETE RESTRICT,
            CONSTRAINT v2_audit_events_release_fk
                FOREIGN KEY (application_id, release_id)
                REFERENCES public.${tables.v2Releases}(application_id, id)
                ON DELETE RESTRICT
        );

        CREATE INDEX v2_applications_status_created_idx
            ON public.${tables.v2Applications} (status, created_at DESC, id DESC);
        CREATE INDEX v2_applications_name_search_idx
            ON public.${tables.v2Applications} (lower(name) text_pattern_ops, id);
        CREATE INDEX v2_releases_application_created_idx
            ON public.${tables.v2Releases} (application_id, created_at DESC, id DESC);
        CREATE INDEX v2_releases_application_published_idx
            ON public.${tables.v2Releases} (application_id, published_at DESC, id DESC)
            WHERE published_at IS NOT NULL;
        CREATE INDEX v2_upload_files_release_state_idx
            ON public.${tables.v2UploadFiles} (release_id, state, id);
        CREATE UNIQUE INDEX v2_upload_files_observed_path_unique
            ON public.${tables.v2UploadFiles} (release_id, observed_path)
            WHERE observed_path IS NOT NULL;
        CREATE INDEX v2_bindings_group_application_idx
            ON public.${tables.v2Bindings} (group_id, application_id);
        CREATE INDEX v2_audit_events_time_idx
            ON public.${tables.v2AuditEvents} (occurred_at DESC, id DESC);
        CREATE INDEX v2_audit_events_application_time_idx
            ON public.${tables.v2AuditEvents} (application_id, occurred_at DESC, id DESC);
        CREATE INDEX v2_audit_events_actor_time_idx
            ON public.${tables.v2AuditEvents} (actor_id, occurred_at DESC, id DESC);
        CREATE INDEX v2_audit_events_action_time_idx
            ON public.${tables.v2AuditEvents} (action, occurred_at DESC, id DESC);
        CREATE INDEX v2_audit_events_release_idx
            ON public.${tables.v2AuditEvents} (application_id, release_id)
            WHERE release_id IS NOT NULL;

        CREATE FUNCTION public.v2_guard_application_generation()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $function$
        BEGIN
            IF NEW.desired_generation < OLD.desired_generation
                OR NEW.served_generation < OLD.served_generation
            THEN
                RAISE EXCEPTION 'application routing generations cannot decrease'
                    USING ERRCODE = '55000';
            END IF;
            RETURN NEW;
        END;
        $function$;

        CREATE TRIGGER v2_applications_generation_monotonic
            BEFORE UPDATE ON public.${tables.v2Applications}
            FOR EACH ROW EXECUTE FUNCTION public.v2_guard_application_generation();

        CREATE FUNCTION public.v2_guard_ready_release()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $function$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                IF OLD.state = 'READY' THEN
                    RAISE EXCEPTION 'READY release is immutable'
                        USING ERRCODE = '55000';
                END IF;
                RETURN OLD;
            END IF;

            IF OLD.state = 'READY' THEN
                IF NEW.id IS DISTINCT FROM OLD.id
                    OR NEW.application_id IS DISTINCT FROM OLD.application_id
                    OR NEW.state IS DISTINCT FROM OLD.state
                    OR NEW.default_path IS DISTINCT FROM OLD.default_path
                    OR NEW.manifest_digest IS DISTINCT FROM OLD.manifest_digest
                    OR NEW.finalized_at IS DISTINCT FROM OLD.finalized_at
                    OR NEW.created_at IS DISTINCT FROM OLD.created_at
                THEN
                    RAISE EXCEPTION 'READY release content fields are immutable'
                        USING ERRCODE = '55000';
                END IF;
                IF OLD.published_at IS NOT NULL
                    AND (NEW.published_at IS DISTINCT FROM OLD.published_at
                        OR NEW.version_label IS DISTINCT FROM OLD.version_label)
                THEN
                    RAISE EXCEPTION 'release publication identity is immutable'
                        USING ERRCODE = '55000';
                END IF;
            END IF;
            RETURN NEW;
        END;
        $function$;

        CREATE TRIGGER v2_releases_ready_immutable
            BEFORE UPDATE OR DELETE ON public.${tables.v2Releases}
            FOR EACH ROW EXECUTE FUNCTION public.v2_guard_ready_release();

        CREATE FUNCTION public.v2_enforce_publication_identity()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        AS $function$
        DECLARE
            base_label text;
            candidate_label text;
            suffix integer := 1;
        BEGIN
            IF TG_OP = 'INSERT' THEN
                IF NEW.published_at IS NOT NULL OR NEW.version_label IS NOT NULL THEN
                    RAISE EXCEPTION 'publication identity must be assigned after READY finalization'
                        USING ERRCODE = '55000';
                END IF;
                RETURN NEW;
            END IF;

            IF OLD.published_at IS NULL AND NEW.published_at IS NOT NULL THEN
                IF OLD.state <> 'READY' THEN
                    RAISE EXCEPTION 'release must already be READY before publication'
                        USING ERRCODE = '55000';
                END IF;
                IF NOT EXISTS (
                    SELECT 1
                      FROM public.${tables.v2PublicationGuards}
                     WHERE release_id = NEW.id
                       AND transaction_id = txid_current()
                ) THEN
                    RAISE EXCEPTION 'publication identity must use v2_claim_release_version'
                        USING ERRCODE = '55000';
                END IF;
                base_label := to_char(
                    NEW.published_at AT TIME ZONE 'UTC',
                    'YYYY.MM.DD-HH24.MI.SS'
                );
                candidate_label := base_label;
                WHILE EXISTS (
                    SELECT 1
                      FROM public.${tables.v2Releases}
                     WHERE application_id = NEW.application_id
                       AND id <> NEW.id
                       AND version_label = candidate_label
                ) LOOP
                    suffix := suffix + 1;
                    candidate_label := base_label || '-' || suffix::text;
                END LOOP;
                NEW.version_label := candidate_label;
            END IF;
            RETURN NEW;
        END;
        $function$;

        CREATE TRIGGER v2_releases_publication_identity
            BEFORE INSERT OR UPDATE ON public.${tables.v2Releases}
            FOR EACH ROW EXECUTE FUNCTION public.v2_enforce_publication_identity();

        CREATE FUNCTION public.v2_guard_upload_file()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $function$
        DECLARE
            parent_state text;
        BEGIN
            IF TG_OP = 'INSERT' THEN
                SELECT state INTO parent_state
                  FROM public.${tables.v2Releases}
                 WHERE id = NEW.release_id
                 FOR SHARE;
                IF parent_state = 'READY' THEN
                    RAISE EXCEPTION 'READY release upload declarations are immutable'
                        USING ERRCODE = '55000';
                END IF;
            ELSIF TG_OP = 'DELETE' THEN
                SELECT state INTO parent_state
                  FROM public.${tables.v2Releases}
                 WHERE id = OLD.release_id
                 FOR SHARE;
                IF parent_state = 'READY' THEN
                    RAISE EXCEPTION 'READY release upload declarations are immutable'
                        USING ERRCODE = '55000';
                END IF;
            ELSE
                FOR parent_state IN
                    SELECT state
                      FROM public.${tables.v2Releases}
                     WHERE id IN (OLD.release_id, NEW.release_id)
                     ORDER BY id
                     FOR SHARE
                LOOP
                    IF parent_state = 'READY' THEN
                        RAISE EXCEPTION 'READY release upload declarations are immutable'
                            USING ERRCODE = '55000';
                    END IF;
                END LOOP;
            END IF;
            RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
        END;
        $function$;

        CREATE TRIGGER v2_upload_files_ready_immutable
            BEFORE INSERT OR UPDATE OR DELETE ON public.${tables.v2UploadFiles}
            FOR EACH ROW EXECUTE FUNCTION public.v2_guard_upload_file();

        CREATE FUNCTION public.v2_guard_upload_truncate()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $function$
        BEGIN
            RAISE EXCEPTION 'upload declarations cannot be truncated'
                USING ERRCODE = '55000';
        END;
        $function$;

        CREATE TRIGGER v2_upload_files_no_truncate
            BEFORE TRUNCATE ON public.${tables.v2UploadFiles}
            FOR EACH STATEMENT EXECUTE FUNCTION public.v2_guard_upload_truncate();

        CREATE FUNCTION public.v2_guard_audit_event()
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

        CREATE TRIGGER v2_audit_events_no_truncate
            BEFORE TRUNCATE ON public.${tables.v2AuditEvents}
            FOR EACH STATEMENT EXECUTE FUNCTION public.v2_guard_audit_event();

        CREATE FUNCTION public.v2_claim_release_version(
            target_release_id uuid,
            first_published_at timestamptz
        )
        RETURNS text
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        AS $function$
        DECLARE
            target_application_id uuid;
            existing_label text;
            base_label text;
            candidate_label text;
            suffix integer := 1;
        BEGIN
            IF first_published_at IS NULL THEN
                RAISE EXCEPTION 'publication timestamp is required'
                    USING ERRCODE = '22004';
            END IF;

            SELECT application_id
              INTO target_application_id
              FROM public.${tables.v2Releases}
             WHERE id = target_release_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'READY release not found'
                    USING ERRCODE = 'P0002';
            END IF;

            PERFORM 1
              FROM public.${tables.v2Applications}
             WHERE id = target_application_id
             FOR UPDATE;

            SELECT version_label
              INTO existing_label
              FROM public.${tables.v2Releases}
             WHERE id = target_release_id
               AND application_id = target_application_id
               AND state = 'READY'
             FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'READY release not found'
                    USING ERRCODE = 'P0002';
            END IF;
            IF existing_label IS NOT NULL THEN
                RETURN existing_label;
            END IF;

            base_label := to_char(
                first_published_at AT TIME ZONE 'UTC',
                'YYYY.MM.DD-HH24.MI.SS'
            );
            candidate_label := base_label;
            WHILE EXISTS (
                SELECT 1
                  FROM public.${tables.v2Releases}
                 WHERE application_id = target_application_id
                   AND version_label = candidate_label
            ) LOOP
                suffix := suffix + 1;
                candidate_label := base_label || '-' || suffix::text;
            END LOOP;

            INSERT INTO public.${tables.v2PublicationGuards}
                (release_id, transaction_id)
            VALUES (target_release_id, txid_current());

            UPDATE public.${tables.v2Releases}
               SET published_at = first_published_at,
                   version_label = candidate_label,
                   updated_at = transaction_timestamp()
             WHERE id = target_release_id;

            DELETE FROM public.${tables.v2PublicationGuards}
             WHERE release_id = target_release_id
               AND transaction_id = txid_current();
            RETURN candidate_label;
        END;
        $function$;
        REVOKE ALL ON FUNCTION public.v2_claim_release_version(uuid, timestamptz)
            FROM PUBLIC;
    `);
}

export async function down(knex: Knex): Promise<void> {
    await knex.raw(`
        LOCK TABLE
            public.${tables.v2Applications},
            public.${tables.v2Releases},
            public.${tables.v2PublicationGuards},
            public.${tables.v2UploadFiles},
            public.${tables.v2Bindings},
            public.${tables.v2AuditEvents}
        IN ACCESS EXCLUSIVE MODE;

        DO $guard$
        BEGIN
            IF EXISTS (SELECT 1 FROM public.${tables.v2Applications})
                OR EXISTS (SELECT 1 FROM public.${tables.v2Releases})
                OR EXISTS (SELECT 1 FROM public.${tables.v2PublicationGuards})
                OR EXISTS (SELECT 1 FROM public.${tables.v2UploadFiles})
                OR EXISTS (SELECT 1 FROM public.${tables.v2Bindings})
                OR EXISTS (SELECT 1 FROM public.${tables.v2AuditEvents})
            THEN
                RAISE EXCEPTION 'migration 03 contains retained v2 data; expand-only rollback refused'
                    USING ERRCODE = '55000';
            END IF;
        END;
        $guard$;

        DROP FUNCTION IF EXISTS public.v2_claim_release_version(uuid, timestamptz);
        DROP TABLE IF EXISTS public.${tables.v2AuditEvents};
        DROP TABLE IF EXISTS public.${tables.v2Bindings};
        DROP TABLE IF EXISTS public.${tables.v2UploadFiles};
        DROP TABLE IF EXISTS public.${tables.v2PublicationGuards};
        ALTER TABLE IF EXISTS public.${tables.v2Applications}
            DROP CONSTRAINT IF EXISTS v2_applications_desired_release_fk,
            DROP CONSTRAINT IF EXISTS v2_applications_served_release_fk;
        DROP TABLE IF EXISTS public.${tables.v2Releases};
        DROP TABLE IF EXISTS public.${tables.v2Applications};
        DROP FUNCTION IF EXISTS public.v2_guard_audit_event();
        DROP FUNCTION IF EXISTS public.v2_guard_upload_truncate();
        DROP FUNCTION IF EXISTS public.v2_guard_upload_file();
        DROP FUNCTION IF EXISTS public.v2_enforce_publication_identity();
        DROP FUNCTION IF EXISTS public.v2_guard_ready_release();
        DROP FUNCTION IF EXISTS public.v2_guard_application_generation();
    `);
}
