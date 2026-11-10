-- Grant the dedicated provisioner only the column/table privileges required
-- by PostgresApiKeyRegistry.issue_key_with_audit().
--
-- This role can lock an active tenant row without changing tenant business
-- fields, append and verify the audit chain, and insert key/idempotency rows.
-- It cannot create tenants, revoke keys, or modify tenant status.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = 'jas_si_provisioner'
    ) THEN
        EXECUTE
            'GRANT SELECT (tenant_id, status) '
            'ON TABLE public.jas_si_tenants TO jas_si_provisioner';
        EXECUTE
            'GRANT UPDATE (provisioning_lock_version) '
            'ON TABLE public.jas_si_tenants TO jas_si_provisioner';

        EXECUTE
            'GRANT INSERT (singleton, last_hash), '
            'SELECT (singleton, last_hash), UPDATE (last_hash) '
            'ON TABLE public.jas_si_audit_chain_state TO jas_si_provisioner';

        EXECUTE
            'GRANT SELECT (event_id, event_payload, previous_hash, event_hash), '
            'INSERT (event_payload, previous_hash, event_hash) '
            'ON TABLE public.jas_si_audit_events TO jas_si_provisioner';

        EXECUTE
            'GRANT INSERT (key_id, tenant_id, key_name, key_prefix, '
            'secret_digest, pepper_version, scopes, created_by, expires_at) '
            'ON TABLE public.jas_si_api_keys TO jas_si_provisioner';

        EXECUTE
            'GRANT SELECT, INSERT ON TABLE '
            'public.jas_si_api_key_provisioning_runs TO jas_si_provisioner';
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = 'jas_si_runtime'
    ) THEN
        EXECUTE
            'REVOKE INSERT, UPDATE, DELETE ON TABLE '
            'public.jas_si_api_keys FROM jas_si_runtime';
        EXECUTE
            'REVOKE INSERT, UPDATE, DELETE ON TABLE '
            'public.jas_si_api_key_provisioning_runs FROM jas_si_runtime';
    END IF;
END
$$;
