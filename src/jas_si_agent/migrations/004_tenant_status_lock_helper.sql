-- Narrow, audited tenant row locking for the API-key provisioner.
-- Apply as the owner of jas_si_tenants (normally neondb_owner). The
-- SECURITY DEFINER function performs only a status read with a row lock;
-- it exposes no arbitrary SQL and grants no tenant-table UPDATE privilege.

CREATE OR REPLACE FUNCTION public.jas_si_lock_tenant_status(p_tenant_id uuid)
RETURNS varchar
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT tenant.status
    FROM public.jas_si_tenants AS tenant
    WHERE tenant.tenant_id = p_tenant_id
    FOR UPDATE
$function$;

REVOKE ALL ON FUNCTION public.jas_si_lock_tenant_status(uuid) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = 'jas_si_provisioner'
    ) THEN
        GRANT EXECUTE ON FUNCTION public.jas_si_lock_tenant_status(uuid)
            TO jas_si_provisioner;
    END IF;
END
$$;
