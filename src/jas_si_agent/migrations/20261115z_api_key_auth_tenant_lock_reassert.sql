-- Reassert the tenant-suspension serialization contract for API-key authentication.
-- The original boundary migration can predate the row-locking revision in an existing
-- staging database. This additive migration makes the required lock and its narrow
-- UPDATE/RLS prerequisites explicit and verifiable.

DO $$
DECLARE
    v_owner record;
BEGIN
    SELECT * INTO v_owner
      FROM pg_catalog.pg_roles
     WHERE rolname='jas_si_api_key_auth_owner';

    IF NOT FOUND THEN
        RAISE EXCEPTION 'jas_si_api_key_auth_owner role is required';
    END IF;
    IF v_owner.rolcanlogin OR v_owner.rolsuper OR v_owner.rolcreatedb
       OR v_owner.rolcreaterole OR v_owner.rolreplication
       OR v_owner.rolbypassrls OR v_owner.rolinherit THEN
        RAISE EXCEPTION 'Unsafe API-key authentication owner role configuration';
    END IF;
    IF pg_catalog.to_regclass('public.jas_si_tenants') IS NULL
       OR pg_catalog.to_regclass('public.jas_si_api_keys') IS NULL THEN
        RAISE EXCEPTION 'Required API-key authentication tables are missing';
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO jas_si_api_key_auth_owner, jas_si_runtime;
GRANT SELECT (tenant_id, tenant_name, status)
    ON public.jas_si_tenants TO jas_si_api_key_auth_owner;
GRANT UPDATE (provisioning_lock_version)
    ON public.jas_si_tenants TO jas_si_api_key_auth_owner;

ALTER TABLE public.jas_si_tenants ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS jas_si_tenants_auth_owner_select
    ON public.jas_si_tenants;
CREATE POLICY jas_si_tenants_auth_owner_select
    ON public.jas_si_tenants FOR SELECT TO jas_si_api_key_auth_owner
    USING (true);
DROP POLICY IF EXISTS jas_si_tenants_auth_owner_lock
    ON public.jas_si_tenants;
CREATE POLICY jas_si_tenants_auth_owner_lock
    ON public.jas_si_tenants FOR UPDATE TO jas_si_api_key_auth_owner
    USING (true) WITH CHECK (true);

GRANT CREATE ON SCHEMA public TO jas_si_api_key_auth_owner;
SET LOCAL ROLE jas_si_api_key_auth_owner;

CREATE OR REPLACE FUNCTION public.jas_si_api_key_authenticate(
    p_key_id uuid,
    p_candidate_digest bytea
)
RETURNS TABLE(
    auth_key_id uuid,
    auth_tenant_id uuid,
    auth_tenant_name text,
    auth_scopes text[]
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog
AS $function$
BEGIN
    IF p_key_id IS NULL OR p_candidate_digest IS NULL
       OR pg_catalog.octet_length(p_candidate_digest)<>32 THEN
        RETURN;
    END IF;

    -- Derive tenant identity from the key row, then lock the active tenant
    -- before updating the key. Tenant suspension updates conflict with this
    -- shared lock; after a suspension commits, the status predicate is rechecked.
    RETURN QUERY
    WITH active_tenant AS MATERIALIZED (
        SELECT t.tenant_id,t.tenant_name
          FROM public.jas_si_tenants AS t
         WHERE t.tenant_id=(
             SELECT k.tenant_id
               FROM public.jas_si_api_keys AS k
              WHERE k.key_id=p_key_id
                AND k.secret_digest=p_candidate_digest
                AND k.pepper_version=1
                AND k.status='active'
                AND (k.expires_at IS NULL OR k.expires_at>pg_catalog.clock_timestamp())
         )
           AND t.status='active'
         FOR SHARE OF t
    )
    UPDATE public.jas_si_api_keys AS k
       SET last_used_at=pg_catalog.clock_timestamp()
      FROM active_tenant AS t
     WHERE k.key_id=p_key_id
       AND k.tenant_id=t.tenant_id
       AND k.secret_digest=p_candidate_digest
       AND k.pepper_version=1
       AND k.status='active'
       AND (k.expires_at IS NULL OR k.expires_at>pg_catalog.clock_timestamp())
    RETURNING k.key_id,k.tenant_id,t.tenant_name::text,k.scopes;
END;
$function$;

REVOKE ALL ON FUNCTION public.jas_si_api_key_authenticate(uuid,bytea)
    FROM PUBLIC, jas_si_runtime;
GRANT EXECUTE ON FUNCTION public.jas_si_api_key_authenticate(uuid,bytea)
    TO jas_si_runtime;

RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_api_key_auth_owner;

DO $$
BEGIN
    IF NOT pg_catalog.has_column_privilege(
        'jas_si_api_key_auth_owner',
        'public.jas_si_tenants',
        'provisioning_lock_version',
        'UPDATE'
    ) THEN
        RAISE EXCEPTION 'Tenant row-lock UPDATE privilege was not installed';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_policies
         WHERE schemaname='public'
           AND tablename='jas_si_tenants'
           AND policyname='jas_si_tenants_auth_owner_lock'
           AND cmd='UPDATE'
           AND 'jas_si_api_key_auth_owner'=ANY(roles)
    ) THEN
        RAISE EXCEPTION 'Tenant row-lock RLS policy was not installed';
    END IF;
    IF pg_catalog.strpos(
        pg_catalog.pg_get_functiondef(
            'public.jas_si_api_key_authenticate(uuid,bytea)'::regprocedure
        ),
        'FOR SHARE OF t'
    ) = 0 THEN
        RAISE EXCEPTION 'API-key authentication tenant row lock is missing';
    END IF;
END
$$;
