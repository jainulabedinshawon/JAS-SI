-- Dedicated customer API-key self-service role.
-- Customer-key operations are restricted to the tenant UUID set transaction-locally
-- by PostgresApiKeyRegistry. RLS is enforced by PostgreSQL, not only by API code.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jas_si_customer_key_runtime') THEN
        CREATE ROLE jas_si_customer_key_runtime NOLOGIN;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO jas_si_customer_key_runtime;
GRANT SELECT (tenant_id, status) ON TABLE public.jas_si_tenants TO jas_si_customer_key_runtime;
GRANT UPDATE (provisioning_lock_version) ON TABLE public.jas_si_tenants TO jas_si_customer_key_runtime;

GRANT SELECT (key_id, tenant_id, key_name, key_prefix, scopes, status, created_at, expires_at, last_used_at, revoked_at)
    ON TABLE public.jas_si_api_keys TO jas_si_customer_key_runtime;
GRANT INSERT (key_id, tenant_id, key_name, key_prefix, secret_digest, pepper_version, scopes, created_by, expires_at)
    ON TABLE public.jas_si_api_keys TO jas_si_customer_key_runtime;
GRANT UPDATE (status, revoked_at) ON TABLE public.jas_si_api_keys TO jas_si_customer_key_runtime;

GRANT INSERT (singleton, last_hash), SELECT (singleton, last_hash), UPDATE (last_hash)
    ON TABLE public.jas_si_audit_chain_state TO jas_si_customer_key_runtime;
GRANT SELECT (event_id, event_payload, previous_hash, event_hash),
      INSERT (event_payload, previous_hash, event_hash)
    ON TABLE public.jas_si_audit_events TO jas_si_customer_key_runtime;
GRANT INSERT (run_id, key_id, tenant_id)
    ON TABLE public.jas_si_api_key_provisioning_runs TO jas_si_customer_key_runtime;

-- RLS is enabled for the key table. Existing API authentication needs to look up
-- key IDs across tenants; its runtime role receives read + last-used update only.
ALTER TABLE public.jas_si_api_keys ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS jas_si_api_keys_runtime_auth ON public.jas_si_api_keys;
CREATE POLICY jas_si_api_keys_runtime_auth ON public.jas_si_api_keys
    FOR SELECT TO jas_si_runtime USING (true);
DROP POLICY IF EXISTS jas_si_api_keys_runtime_last_used ON public.jas_si_api_keys;
CREATE POLICY jas_si_api_keys_runtime_last_used ON public.jas_si_api_keys
    FOR UPDATE TO jas_si_runtime USING (true) WITH CHECK (true);

-- Operator provisioning is also scoped to a transaction-local tenant context.
DROP POLICY IF EXISTS jas_si_api_keys_provisioner_tenant ON public.jas_si_api_keys;
CREATE POLICY jas_si_api_keys_provisioner_tenant ON public.jas_si_api_keys
    FOR ALL TO jas_si_provisioner
    USING (tenant_id = NULLIF(current_setting('jas_si.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('jas_si.tenant_id', true), '')::uuid);

DROP POLICY IF EXISTS jas_si_api_keys_customer_tenant ON public.jas_si_api_keys;
CREATE POLICY jas_si_api_keys_customer_tenant ON public.jas_si_api_keys
    FOR ALL TO jas_si_customer_key_runtime
    USING (tenant_id = NULLIF(current_setting('jas_si.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('jas_si.tenant_id', true), '')::uuid);

-- The customer role must never create or change tenant business status or audit history.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE public.jas_si_tenants FROM jas_si_customer_key_runtime;
