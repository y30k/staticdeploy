import { Knex } from "knex";

import tables from "../common/tables";

/* Add one-time OIDC login transactions and the narrow session API. */
export async function up(knex: Knex): Promise<void> {
    await knex.raw(`
        CREATE OR REPLACE FUNCTION public.v2_guard_session()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $function$
        BEGIN
            IF TG_OP = 'INSERT' THEN
                IF NEW.created_at > clock_timestamp()
                    OR NEW.last_seen_at > clock_timestamp()
                THEN
                    RAISE EXCEPTION 'session timestamps cannot be in the future'
                        USING ERRCODE = '55000';
                END IF;
                RETURN NEW;
            END IF;
            IF TG_OP = 'DELETE' THEN
                IF OLD.revoked_at IS NULL
                    AND clock_timestamp() < OLD.absolute_expires_at
                    AND clock_timestamp() < OLD.idle_expires_at
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
            IF OLD.idle_expires_at <= clock_timestamp()
                OR OLD.absolute_expires_at <= clock_timestamp()
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
                OR NEW.last_seen_at > clock_timestamp()
                OR NEW.idle_expires_at < OLD.idle_expires_at
                OR (NEW.revoked_at IS NOT NULL
                    AND NEW.revoked_at > clock_timestamp())
                OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NULL)
            THEN
                RAISE EXCEPTION 'session identity and time bounds cannot regress'
                    USING ERRCODE = '55000';
            END IF;
            RETURN NEW;
        END;
        $function$;

        CREATE TABLE public.${tables.v2LoginTransactions} (
            id uuid PRIMARY KEY,
            state_digest text NOT NULL,
            nonce_digest text NOT NULL,
            verifier_key_id text NOT NULL,
            verifier_nonce bytea NOT NULL,
            encrypted_code_verifier bytea NOT NULL,
            expected_issuer text NOT NULL,
            client_id text NOT NULL,
            redirect_uri text NOT NULL,
            created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
            expires_at timestamptz NOT NULL,
            consumed_at timestamptz,
            CONSTRAINT v2_login_state_digest_check
                CHECK (state_digest ~ '^[0-9a-f]{64}$'),
            CONSTRAINT v2_login_nonce_digest_check
                CHECK (nonce_digest ~ '^[0-9a-f]{64}$'),
            CONSTRAINT v2_login_key_id_check
                CHECK (char_length(verifier_key_id) BETWEEN 1 AND 200),
            CONSTRAINT v2_login_nonce_check
                CHECK (octet_length(verifier_nonce) = 12),
            CONSTRAINT v2_login_verifier_check
                CHECK (octet_length(encrypted_code_verifier) BETWEEN 16 AND 1024),
            CONSTRAINT v2_login_issuer_check
                CHECK (char_length(expected_issuer) BETWEEN 1 AND 2048),
            CONSTRAINT v2_login_client_check
                CHECK (char_length(client_id) BETWEEN 1 AND 512),
            CONSTRAINT v2_login_redirect_uri_check
                CHECK (char_length(redirect_uri) BETWEEN 1 AND 2048),
            CONSTRAINT v2_login_expiry_check
                CHECK (created_at < expires_at),
            CONSTRAINT v2_login_consumed_check
                CHECK (consumed_at IS NULL OR consumed_at BETWEEN created_at AND expires_at)
        );
        REVOKE ALL ON public.${tables.v2LoginTransactions} FROM PUBLIC;

        CREATE INDEX v2_login_transactions_expiry_idx
            ON public.${tables.v2LoginTransactions} (expires_at, id);
        CREATE INDEX v2_login_transactions_live_idx
            ON public.${tables.v2LoginTransactions} (expires_at, id)
            WHERE consumed_at IS NULL;
        CREATE INDEX v2_login_transactions_admission_idx
            ON public.${tables.v2LoginTransactions} (created_at, id);

        CREATE FUNCTION public.v2_begin_oidc_login(
            login_id uuid,
            requested_state_digest text,
            requested_nonce_digest text,
            requested_verifier_key_id text,
            requested_verifier_nonce bytea,
            requested_encrypted_verifier bytea,
            requested_expected_issuer text,
            requested_client_id text,
            requested_redirect_uri text,
            lifetime_ms integer
        ) RETURNS void
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        SET lock_timeout = '5s'
        SET statement_timeout = '10s'
        AS $function$
        DECLARE observed_at timestamptz := clock_timestamp();
        BEGIN
            IF login_id IS NULL
                OR requested_state_digest IS NULL
                OR requested_nonce_digest IS NULL
                OR requested_verifier_key_id IS NULL
                OR requested_verifier_nonce IS NULL
                OR requested_encrypted_verifier IS NULL
                OR requested_expected_issuer IS NULL
                OR requested_client_id IS NULL
                OR requested_redirect_uri IS NULL
                OR lifetime_ms IS NULL
                OR lifetime_ms < 1000 OR lifetime_ms > 300000
            THEN
                RAISE EXCEPTION 'invalid login transaction bounds'
                    USING ERRCODE = '22023';
            END IF;
            PERFORM pg_advisory_xact_lock(
                hashtextextended('staticdeploy-v2-oidc-login-admission', 0)
            );
            IF (SELECT count(*) FROM public.${tables.v2LoginTransactions}
                 WHERE created_at > observed_at - interval '1 hour') >= 10000
            THEN
                RAISE EXCEPTION 'login transaction capacity reached'
                    USING ERRCODE = '53300';
            END IF;
            INSERT INTO public.${tables.v2LoginTransactions} (
                id, state_digest, nonce_digest, verifier_key_id,
                verifier_nonce, encrypted_code_verifier, expected_issuer,
                client_id, redirect_uri, created_at, expires_at
            ) VALUES (
                login_id, requested_state_digest, requested_nonce_digest,
                requested_verifier_key_id, requested_verifier_nonce,
                requested_encrypted_verifier, requested_expected_issuer,
                requested_client_id, requested_redirect_uri, observed_at,
                observed_at + make_interval(secs => lifetime_ms / 1000.0)
            );
        END;
        $function$;
        REVOKE ALL ON FUNCTION public.v2_begin_oidc_login(
            uuid, text, text, text, bytea, bytea, text, text, text, integer
        ) FROM PUBLIC;

        CREATE FUNCTION public.v2_consume_oidc_login(
            requested_login_id uuid,
            requested_state_digest text
        ) RETURNS TABLE (
            id uuid,
            verifier_key_id text,
            verifier_nonce bytea,
            encrypted_code_verifier bytea,
            nonce_digest text,
            expected_issuer text,
            client_id text,
            redirect_uri text
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        SET lock_timeout = '5s'
        SET statement_timeout = '10s'
        AS $function$
        DECLARE target public.${tables.v2LoginTransactions}%ROWTYPE;
        DECLARE observed_at timestamptz;
        BEGIN
            IF requested_login_id IS NULL OR requested_state_digest IS NULL THEN
                RAISE EXCEPTION 'login transaction identity is required'
                    USING ERRCODE = '22023';
            END IF;
            SELECT * INTO target
              FROM public.${tables.v2LoginTransactions}
             WHERE public.${tables.v2LoginTransactions}.id = requested_login_id
             FOR UPDATE;
            observed_at := clock_timestamp();
            IF NOT FOUND OR target.state_digest <> requested_state_digest
                OR target.consumed_at IS NOT NULL
                OR target.expires_at <= observed_at
            THEN
                RAISE EXCEPTION 'login transaction is invalid or expired'
                    USING ERRCODE = '28000';
            END IF;
            UPDATE public.${tables.v2LoginTransactions}
               SET consumed_at = observed_at
             WHERE public.${tables.v2LoginTransactions}.id = target.id;
            RETURN QUERY SELECT target.id, target.verifier_key_id,
                target.verifier_nonce, target.encrypted_code_verifier,
                target.nonce_digest, target.expected_issuer,
                target.client_id, target.redirect_uri;
        END;
        $function$;
        REVOKE ALL ON FUNCTION public.v2_consume_oidc_login(uuid, text)
            FROM PUBLIC;

        CREATE FUNCTION public.v2_create_or_replace_session(
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

        CREATE FUNCTION public.v2_read_session(session_id uuid)
        RETURNS SETOF public.${tables.v2Sessions}
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        SET lock_timeout = '5s'
        SET statement_timeout = '10s'
        AS $function$
        DECLARE target public.${tables.v2Sessions}%ROWTYPE;
        DECLARE observed_at timestamptz;
        BEGIN
            IF session_id IS NULL THEN
                RAISE EXCEPTION 'session identity is required' USING ERRCODE = '22023';
            END IF;
            SELECT * INTO target FROM public.${tables.v2Sessions}
             WHERE id = session_id FOR SHARE;
            observed_at := clock_timestamp();
            IF NOT FOUND OR target.revoked_at IS NOT NULL
                OR target.idle_expires_at <= observed_at
                OR target.absolute_expires_at <= observed_at
            THEN
                RETURN;
            END IF;
            RETURN NEXT target;
        END;
        $function$;
        REVOKE ALL ON FUNCTION public.v2_read_session(uuid) FROM PUBLIC;

        CREATE FUNCTION public.v2_use_session(session_id uuid, idle_lifetime_ms integer)
        RETURNS SETOF public.${tables.v2Sessions}
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        SET lock_timeout = '5s'
        SET statement_timeout = '10s'
        AS $function$
        DECLARE target public.${tables.v2Sessions}%ROWTYPE;
        DECLARE observed_at timestamptz;
        BEGIN
            IF session_id IS NULL OR idle_lifetime_ms IS NULL
                OR idle_lifetime_ms < 1000 OR idle_lifetime_ms > 86400000
            THEN
                RAISE EXCEPTION 'invalid session use bounds' USING ERRCODE = '22023';
            END IF;
            SELECT * INTO target FROM public.${tables.v2Sessions}
             WHERE id = session_id FOR UPDATE;
            observed_at := clock_timestamp();
            IF NOT FOUND OR target.revoked_at IS NOT NULL
                OR target.idle_expires_at <= observed_at
                OR target.absolute_expires_at <= observed_at
            THEN
                RETURN;
            END IF;
            UPDATE public.${tables.v2Sessions}
               SET last_seen_at = observed_at,
                   idle_expires_at = LEAST(
                       target.absolute_expires_at,
                       observed_at + make_interval(secs => idle_lifetime_ms / 1000.0)
                   )
             WHERE id = session_id
             RETURNING * INTO target;
            RETURN NEXT target;
        END;
        $function$;
        REVOKE ALL ON FUNCTION public.v2_use_session(uuid, integer) FROM PUBLIC;

        CREATE FUNCTION public.v2_rotate_session_envelope(
            session_id uuid,
            expected_key_id text,
            replacement_key_id text,
            replacement_nonce bytea,
            replacement_material bytea
        ) RETURNS boolean
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        SET lock_timeout = '5s'
        SET statement_timeout = '10s'
        AS $function$
        DECLARE observed_at timestamptz;
        BEGIN
            IF session_id IS NULL OR expected_key_id IS NULL
                OR replacement_key_id IS NULL OR replacement_nonce IS NULL
                OR replacement_material IS NULL
            THEN
                RAISE EXCEPTION 'invalid envelope rotation' USING ERRCODE = '22023';
            END IF;
            PERFORM 1 FROM public.${tables.v2Sessions}
             WHERE id = session_id FOR UPDATE;
            observed_at := clock_timestamp();
            UPDATE public.${tables.v2Sessions}
               SET token_key_id = replacement_key_id,
                   token_nonce = replacement_nonce,
                   encrypted_token_material = replacement_material
             WHERE id = session_id AND token_key_id = expected_key_id
               AND revoked_at IS NULL AND idle_expires_at > observed_at
               AND absolute_expires_at > observed_at;
            RETURN FOUND;
        END;
        $function$;
        REVOKE ALL ON FUNCTION public.v2_rotate_session_envelope(
            uuid, text, text, bytea, bytea
        ) FROM PUBLIC;

        CREATE FUNCTION public.v2_revoke_session(session_id uuid, reason text)
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

        CREATE FUNCTION public.v2_cleanup_auth_state(
            retention_ms bigint,
            batch_size integer
        ) RETURNS TABLE (login_transactions_deleted bigint, sessions_deleted bigint)
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        SET lock_timeout = '5s'
        SET statement_timeout = '10s'
        AS $function$
        DECLARE observed_at timestamptz := clock_timestamp();
        BEGIN
            IF retention_ms IS NULL OR batch_size IS NULL
                OR retention_ms < 0 OR retention_ms > 2592000000
                OR batch_size < 1 OR batch_size > 1000
            THEN
                RAISE EXCEPTION 'invalid authentication cleanup bounds'
                    USING ERRCODE = '22023';
            END IF;
            WITH victims AS (
                SELECT id FROM public.${tables.v2LoginTransactions}
                 WHERE expires_at <= observed_at
                    - make_interval(secs => retention_ms / 1000.0)
                 ORDER BY expires_at, id
                 LIMIT batch_size
                 FOR UPDATE SKIP LOCKED
            ), deleted AS (
                DELETE FROM public.${tables.v2LoginTransactions} target
                 USING victims WHERE target.id = victims.id RETURNING 1
            ) SELECT count(*) INTO login_transactions_deleted FROM deleted;

            WITH candidates AS (
                (SELECT id, revoked_at AS due_at
                   FROM public.${tables.v2Sessions}
                  WHERE revoked_at IS NOT NULL
                    AND revoked_at <= observed_at
                        - make_interval(secs => retention_ms / 1000.0)
                  ORDER BY revoked_at, id
                  LIMIT batch_size)
                UNION ALL
                (SELECT id, idle_expires_at AS due_at
                   FROM public.${tables.v2Sessions}
                  WHERE revoked_at IS NULL
                    AND idle_expires_at <= observed_at
                        - make_interval(secs => retention_ms / 1000.0)
                  ORDER BY idle_expires_at, absolute_expires_at, id
                  LIMIT batch_size)
            ), victims AS (
                SELECT target.id
                  FROM public.${tables.v2Sessions} target
                  JOIN candidates ON candidates.id = target.id
                 ORDER BY candidates.due_at, target.id
                 LIMIT batch_size
                 FOR UPDATE OF target SKIP LOCKED
            ), deleted AS (
                DELETE FROM public.${tables.v2Sessions} target
                 USING victims WHERE target.id = victims.id RETURNING 1
            ) SELECT count(*) INTO sessions_deleted FROM deleted;
            RETURN NEXT;
        END;
        $function$;
        REVOKE ALL ON FUNCTION public.v2_cleanup_auth_state(bigint, integer)
            FROM PUBLIC;
    `);
}

export async function down(knex: Knex): Promise<void> {
    await knex.raw(`
        LOCK TABLE public.${tables.v2LoginTransactions},
            public.${tables.v2Sessions} IN ACCESS EXCLUSIVE MODE;
        DO $guard$
        BEGIN
            IF EXISTS (SELECT 1 FROM public.${tables.v2LoginTransactions})
                OR EXISTS (SELECT 1 FROM public.${tables.v2Sessions})
            THEN
                RAISE EXCEPTION 'migration 06 has retained authentication state; expand-only rollback refused'
                    USING ERRCODE = '55000';
            END IF;
        END;
        $guard$;
        DROP FUNCTION IF EXISTS public.v2_cleanup_auth_state(bigint, integer);
        DROP FUNCTION IF EXISTS public.v2_revoke_session(uuid, text);
        DROP FUNCTION IF EXISTS public.v2_rotate_session_envelope(
            uuid, text, text, bytea, bytea
        );
        DROP FUNCTION IF EXISTS public.v2_use_session(uuid, integer);
        DROP FUNCTION IF EXISTS public.v2_read_session(uuid);
        DROP FUNCTION IF EXISTS public.v2_create_or_replace_session(
            uuid, uuid, text, text, jsonb, text, text, bytea, bytea,
            integer, integer
        );
        DROP FUNCTION IF EXISTS public.v2_consume_oidc_login(uuid, text);
        DROP FUNCTION IF EXISTS public.v2_begin_oidc_login(
            uuid, text, text, text, bytea, bytea, text, text, text, integer
        );
        DROP TABLE public.${tables.v2LoginTransactions};

        CREATE OR REPLACE FUNCTION public.v2_guard_session()
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
    `);
}
