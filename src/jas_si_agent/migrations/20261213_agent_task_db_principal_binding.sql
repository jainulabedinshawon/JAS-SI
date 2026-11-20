-- Bind task leases and verifier claims to the authenticated PostgreSQL login.
-- This is a database-login boundary, not a per-process identity boundary:
-- processes sharing one LOGIN credential remain indistinguishable.
ALTER TABLE public.jas_si_agent_tasks
    ADD COLUMN IF NOT EXISTS lease_owner_principal name,
    ADD COLUMN IF NOT EXISTS verifier_claim_owner name;

GRANT CREATE ON SCHEMA public TO jas_si_agent_task_owner;
SET LOCAL ROLE jas_si_agent_task_owner;

CREATE OR REPLACE FUNCTION public.jas_si_agent_task_bind_db_principal()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_lease_changed boolean;
    v_verifier_claim_changed boolean;
BEGIN
    v_lease_changed :=
        NEW.lease_owner IS DISTINCT FROM OLD.lease_owner
        OR NEW.lease_expires_at IS DISTINCT FROM OLD.lease_expires_at
        OR NEW.lease_fence IS DISTINCT FROM OLD.lease_fence
        OR NEW.lease_owner_principal IS DISTINCT FROM OLD.lease_owner_principal;

    IF v_lease_changed THEN
        IF OLD.lease_owner IS NULL THEN
            -- A fresh claim is bound to the authenticated database login.
            NEW.lease_owner_principal :=
                CASE WHEN NEW.lease_owner IS NULL THEN NULL ELSE session_user::name END;
        ELSIF OLD.lease_expires_at IS NOT NULL
              AND OLD.lease_expires_at <= v_now
              AND NEW.lease_owner IS NULL THEN
            -- Expired leases may be cleared by the next claimant. They cannot
            -- be renewed or reported by a different login.
            NEW.lease_owner_principal := NULL;
        ELSE
            IF OLD.lease_owner_principal IS DISTINCT FROM session_user::name THEN
                RAISE EXCEPTION 'Task lease belongs to another database principal'
                    USING ERRCODE='42501';
            END IF;
            NEW.lease_owner_principal :=
                CASE WHEN NEW.lease_owner IS NULL THEN NULL ELSE session_user::name END;
        END IF;
    END IF;

    v_verifier_claim_changed :=
        NEW.verifier_claim_token IS DISTINCT FROM OLD.verifier_claim_token
        OR NEW.verifier_claimed_at IS DISTINCT FROM OLD.verifier_claimed_at
        OR NEW.verifier_lease_expires_at IS DISTINCT FROM OLD.verifier_lease_expires_at
        OR NEW.verifier_claim_owner IS DISTINCT FROM OLD.verifier_claim_owner;

    IF v_verifier_claim_changed THEN
        IF OLD.verifier_claim_token IS NULL THEN
            -- A new verifier claim is bound to the authenticated login.
            NEW.verifier_claim_owner :=
                CASE WHEN NEW.verifier_claim_token IS NULL THEN NULL ELSE session_user::name END;
        ELSIF OLD.verifier_lease_expires_at IS NOT NULL
              AND OLD.verifier_lease_expires_at <= v_now
              AND NEW.verifier_claim_token IS DISTINCT FROM OLD.verifier_claim_token THEN
            -- An expired claim can be replaced, but not finalized by its
            -- former owner after expiry.
            NEW.verifier_claim_owner :=
                CASE WHEN NEW.verifier_claim_token IS NULL THEN NULL ELSE session_user::name END;
        ELSE
            IF OLD.verifier_claim_owner IS DISTINCT FROM session_user::name THEN
                RAISE EXCEPTION 'Verifier claim belongs to another database principal'
                    USING ERRCODE='42501';
            END IF;
            NEW.verifier_claim_owner :=
                CASE WHEN NEW.verifier_claim_token IS NULL THEN NULL ELSE session_user::name END;
        END IF;
    END IF;

    RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS jas_si_agent_task_db_principal_guard
    ON public.jas_si_agent_tasks;
CREATE TRIGGER jas_si_agent_task_db_principal_guard
BEFORE UPDATE ON public.jas_si_agent_tasks
FOR EACH ROW
EXECUTE FUNCTION public.jas_si_agent_task_bind_db_principal();

RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_agent_task_owner;
REVOKE ALL ON FUNCTION public.jas_si_agent_task_bind_db_principal() FROM PUBLIC;

DO $block$
DECLARE
    v_owner text;
    v_proc oid := 'public.jas_si_agent_task_bind_db_principal()'::regprocedure;
BEGIN
    SELECT pg_catalog.pg_get_userbyid(p.proowner)
      INTO v_owner
      FROM pg_catalog.pg_proc p
     WHERE p.oid=v_proc;

    IF v_owner<>'jas_si_agent_task_owner'
       OR NOT (SELECT p.prosecdef FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
       OR NOT (SELECT COALESCE(p.proconfig,ARRAY[]::text[])
                    @> ARRAY['search_path=pg_catalog']::text[]
                 FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
       OR EXISTS (
           SELECT 1
             FROM pg_catalog.aclexplode(
                 COALESCE((SELECT p.proacl FROM pg_catalog.pg_proc p WHERE p.oid=v_proc),
                          pg_catalog.acldefault('f',(SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)))
             ) acl
            WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'
       )
       OR NOT EXISTS (
           SELECT 1
             FROM pg_catalog.pg_trigger t
            WHERE t.tgrelid='public.jas_si_agent_tasks'::regclass
              AND t.tgname='jas_si_agent_task_db_principal_guard'
              AND NOT t.tgisinternal
       ) THEN
        RAISE EXCEPTION 'Task database-principal trigger security boundary invalid';
    END IF;
END
$block$;
