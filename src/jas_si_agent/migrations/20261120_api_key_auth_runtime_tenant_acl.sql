-- The API-key authentication routine owns tenant lookup under a narrowly
-- privileged SECURITY DEFINER role. The general API runtime must not retain
-- direct tenant visibility; readiness checks intentionally fail closed if it does.
DO $$
DECLARE
    v_column text;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_runtime'
    ) THEN
        RAISE EXCEPTION 'jas_si_runtime role is required before tenant ACL hardening';
    END IF;

    IF pg_catalog.to_regclass('public.jas_si_tenants') IS NULL THEN
        RAISE EXCEPTION 'Required tenant table is missing';
    END IF;

    REVOKE ALL PRIVILEGES ON TABLE public.jas_si_tenants FROM jas_si_runtime;

    FOR v_column IN
        SELECT a.attname
        FROM pg_catalog.pg_attribute a
        WHERE a.attrelid='public.jas_si_tenants'::regclass
          AND a.attnum>0 AND NOT a.attisdropped
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL PRIVILEGES (%I) ON TABLE public.jas_si_tenants FROM jas_si_runtime',
            v_column
        );
    END LOOP;

    DROP POLICY IF EXISTS jas_si_tenants_runtime_auth ON public.jas_si_tenants;

    IF pg_catalog.has_table_privilege('jas_si_runtime','public.jas_si_tenants','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_runtime','public.jas_si_tenants','INSERT')
       OR pg_catalog.has_table_privilege('jas_si_runtime','public.jas_si_tenants','UPDATE')
       OR pg_catalog.has_table_privilege('jas_si_runtime','public.jas_si_tenants','DELETE')
       OR pg_catalog.has_table_privilege('jas_si_runtime','public.jas_si_tenants','TRUNCATE')
       OR pg_catalog.has_table_privilege('jas_si_runtime','public.jas_si_tenants','REFERENCES')
       OR pg_catalog.has_table_privilege('jas_si_runtime','public.jas_si_tenants','TRIGGER')
       OR pg_catalog.has_any_column_privilege('jas_si_runtime','public.jas_si_tenants','SELECT')
       OR pg_catalog.has_any_column_privilege('jas_si_runtime','public.jas_si_tenants','INSERT')
       OR pg_catalog.has_any_column_privilege('jas_si_runtime','public.jas_si_tenants','UPDATE')
       OR pg_catalog.has_any_column_privilege('jas_si_runtime','public.jas_si_tenants','REFERENCES') THEN
        RAISE EXCEPTION 'jas_si_runtime retains effective access to jas_si_tenants';
    END IF;
END
$$;
