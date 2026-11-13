-- Database-owned API-key authentication boundary.
-- Apply after 007_customer_api_key_self_service.sql.
-- The API runtime receives EXECUTE only; it never reads secret_digest directly.

DO $$
DECLARE
    v_oid oid;
    v_role record;
BEGIN
    SELECT oid INTO v_oid FROM pg_catalog.pg_roles
    WHERE rolname='jas_si_api_key_auth_owner';
    IF v_oid IS NULL THEN
        CREATE ROLE jas_si_api_key_auth_owner NOLOGIN NOSUPERUSER NOCREATEDB
            NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
        SELECT oid INTO v_oid FROM pg_catalog.pg_roles
        WHERE rolname='jas_si_api_key_auth_owner';
    END IF;

    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='neondb_owner') THEN
        EXECUTE 'GRANT jas_si_api_key_auth_owner TO neondb_owner WITH ADMIN FALSE, INHERIT FALSE, SET TRUE';
    END IF;
    SELECT * INTO v_role FROM pg_catalog.pg_roles WHERE oid=v_oid;
    IF v_role.rolcanlogin OR v_role.rolsuper OR v_role.rolcreatedb
       OR v_role.rolcreaterole OR v_role.rolreplication
       OR v_role.rolbypassrls OR v_role.rolinherit
       OR EXISTS (
           SELECT 1 FROM pg_catalog.pg_auth_members m
           JOIN pg_catalog.pg_roles platform_member ON platform_member.oid=m.member
                  JOIN pg_catalog.pg_roles membership_grantor ON membership_grantor.oid=m.grantor
           WHERE m.member=v_oid OR (m.roleid=v_oid AND NOT (
               ((platform_member.rolname='neondb_owner' AND NOT m.admin_option
               AND NOT m.inherit_option AND m.set_option) OR (platform_member.rolname='neondb_owner' AND membership_grantor.rolname='cloud_admin'
               AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option))))
       ) THEN
        RAISE EXCEPTION 'Unsafe API-key authentication owner role configuration';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_runtime') THEN
        RAISE EXCEPTION 'jas_si_runtime role is required before API-key auth hardening';
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO jas_si_api_key_auth_owner, jas_si_runtime;
REVOKE CREATE ON SCHEMA public FROM jas_si_runtime;

-- SECURITY DEFINER owner receives only the columns needed to authenticate
-- and atomically update last_used_at.
GRANT SELECT (key_id, tenant_id, secret_digest, pepper_version, scopes, status, expires_at)
    ON public.jas_si_api_keys TO jas_si_api_key_auth_owner;
GRANT UPDATE (last_used_at)
    ON public.jas_si_api_keys TO jas_si_api_key_auth_owner;
GRANT SELECT (tenant_id, tenant_name, status)
    ON public.jas_si_tenants TO jas_si_api_key_auth_owner;

ALTER TABLE public.jas_si_api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.jas_si_tenants ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS jas_si_api_keys_auth_owner_select ON public.jas_si_api_keys;
CREATE POLICY jas_si_api_keys_auth_owner_select
    ON public.jas_si_api_keys FOR SELECT TO jas_si_api_key_auth_owner
    USING (true);
DROP POLICY IF EXISTS jas_si_api_keys_auth_owner_update ON public.jas_si_api_keys;
CREATE POLICY jas_si_api_keys_auth_owner_update
    ON public.jas_si_api_keys FOR UPDATE TO jas_si_api_key_auth_owner
    USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS jas_si_tenants_auth_owner_select ON public.jas_si_tenants;
CREATE POLICY jas_si_tenants_auth_owner_select
    ON public.jas_si_tenants FOR SELECT TO jas_si_api_key_auth_owner
    USING (true);

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

    -- Tenant identity is derived from the key row. The caller cannot supply
    -- a tenant UUID or a tenant GUC. A concurrent revocation/suspension is
    -- rechecked by PostgreSQL while updating the key row.
    RETURN QUERY
    UPDATE public.jas_si_api_keys AS k
       SET last_used_at=pg_catalog.clock_timestamp()
      FROM public.jas_si_tenants AS t
     WHERE k.key_id=p_key_id
       AND k.tenant_id=t.tenant_id
       AND k.secret_digest=p_candidate_digest
       AND k.pepper_version=1
       AND k.status='active'
       AND (k.expires_at IS NULL OR k.expires_at>pg_catalog.clock_timestamp())
       AND t.status='active'
    RETURNING k.key_id,k.tenant_id,t.tenant_name::text,k.scopes;
END;
$function$;

GRANT CREATE ON SCHEMA public TO jas_si_api_key_auth_owner;
GRANT CREATE ON SCHEMA public TO jas_si_api_key_auth_owner;

ALTER FUNCTION public.jas_si_api_key_authenticate(uuid,bytea)
    OWNER TO jas_si_api_key_auth_owner;
REVOKE CREATE ON SCHEMA public FROM jas_si_api_key_auth_owner;
REVOKE CREATE ON SCHEMA public FROM jas_si_api_key_auth_owner;

REVOKE ALL ON FUNCTION public.jas_si_api_key_authenticate(uuid,bytea)
    FROM PUBLIC,jas_si_runtime;
GRANT EXECUTE ON FUNCTION public.jas_si_api_key_authenticate(uuid,bytea)
    TO jas_si_runtime;

-- Remove the former direct authentication path, including any column-level
-- grants. The separate customer-key runtime and provisioner roles are intact.
REVOKE ALL PRIVILEGES ON TABLE public.jas_si_api_keys FROM jas_si_runtime;
DO $$
DECLARE v_column text;
BEGIN
    FOR v_column IN
        SELECT a.attname
        FROM pg_catalog.pg_attribute a
        WHERE a.attrelid='public.jas_si_api_keys'::regclass
          AND a.attnum>0 AND NOT a.attisdropped
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL PRIVILEGES (%I) ON TABLE public.jas_si_api_keys FROM jas_si_runtime',
            v_column
        );
    END LOOP;
END
$$;
DROP POLICY IF EXISTS jas_si_api_keys_runtime_auth ON public.jas_si_api_keys;
DROP POLICY IF EXISTS jas_si_api_keys_runtime_last_used ON public.jas_si_api_keys;
