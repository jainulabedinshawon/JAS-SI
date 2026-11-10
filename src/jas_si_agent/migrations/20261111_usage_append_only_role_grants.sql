-- Restore the append-only least-privilege boundary for technical usage events.
-- The API runtime may append and read usage; the provisioning role has no usage-table need.
DO $
BEGIN
    -- Staging may not have applied the usage-metering migration yet.
    -- Treat an absent table as a no-op; never fail a partial migration set.
    IF to_regclass('public.jas_si_usage_events') IS NULL THEN
        RAISE NOTICE 'Skipping append-only usage grants: public.jas_si_usage_events does not exist';
        RETURN;
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jas_si_runtime') THEN
        EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON TABLE public.jas_si_usage_events FROM jas_si_runtime';
        EXECUTE 'GRANT SELECT, INSERT ON TABLE public.jas_si_usage_events TO jas_si_runtime';
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jas_si_provisioner') THEN
        EXECUTE 'REVOKE ALL PRIVILEGES ON TABLE public.jas_si_usage_events FROM jas_si_provisioner';
    END IF;
END
$;
