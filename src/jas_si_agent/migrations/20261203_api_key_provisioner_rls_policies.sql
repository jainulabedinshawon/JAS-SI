-- Give the dedicated API-key provisioner narrowly scoped RLS access.
-- Column grants in 006 are necessary but do not override row-level security
-- enabled by the later API-key authentication boundary migration.
-- The provisioner may read/lock tenant state and append keys/idempotency rows,
-- but cannot alter tenant business fields or revoke/change existing keys.

ALTER TABLE public.jas_si_tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.jas_si_api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.jas_si_api_key_provisioning_runs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS jas_si_provisioner_tenant_select
    ON public.jas_si_tenants;
CREATE POLICY jas_si_provisioner_tenant_select
    ON public.jas_si_tenants FOR SELECT
    TO jas_si_provisioner
    USING (true);

DROP POLICY IF EXISTS jas_si_provisioner_tenant_lock
    ON public.jas_si_tenants;
CREATE POLICY jas_si_provisioner_tenant_lock
    ON public.jas_si_tenants FOR UPDATE
    TO jas_si_provisioner
    USING (true)
    WITH CHECK (true);

DROP POLICY IF EXISTS jas_si_provisioner_api_key_select
    ON public.jas_si_api_keys;
CREATE POLICY jas_si_provisioner_api_key_select
    ON public.jas_si_api_keys FOR SELECT
    TO jas_si_provisioner
    USING (true);

DROP POLICY IF EXISTS jas_si_provisioner_api_key_insert
    ON public.jas_si_api_keys;
CREATE POLICY jas_si_provisioner_api_key_insert
    ON public.jas_si_api_keys FOR INSERT
    TO jas_si_provisioner
    WITH CHECK (true);

DROP POLICY IF EXISTS jas_si_provisioner_run_select
    ON public.jas_si_api_key_provisioning_runs;
CREATE POLICY jas_si_provisioner_run_select
    ON public.jas_si_api_key_provisioning_runs FOR SELECT
    TO jas_si_provisioner
    USING (true);

DROP POLICY IF EXISTS jas_si_provisioner_run_insert
    ON public.jas_si_api_key_provisioning_runs;
CREATE POLICY jas_si_provisioner_run_insert
    ON public.jas_si_api_key_provisioning_runs FOR INSERT
    TO jas_si_provisioner
    WITH CHECK (true);

GRANT SELECT ON public.jas_si_api_key_provisioning_runs
    TO jas_si_provisioner;
