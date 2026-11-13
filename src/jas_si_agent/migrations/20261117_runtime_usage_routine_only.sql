-- Cut the API runtime over to authenticated API-key usage routines only.
-- Usage writes, summary, quota and history reads are performed by the narrowly
-- granted SECURITY DEFINER routines owned by jas_si_api_key_usage_owner.
-- Customer-session usage reads use the separate customer identity routines.
DO $block$
DECLARE
    v_column text;
BEGIN
    IF pg_catalog.to_regclass('public.jas_si_usage_events') IS NULL THEN
        RAISE EXCEPTION 'Usage table is required before runtime privilege revocation';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_runtime'
    ) THEN
        RAISE EXCEPTION 'jas_si_runtime role is required before usage privilege revocation';
    END IF;

    REVOKE ALL PRIVILEGES ON TABLE public.jas_si_usage_events FROM jas_si_runtime;

    FOR v_column IN
        SELECT a.attname
          FROM pg_catalog.pg_attribute a
         WHERE a.attrelid='public.jas_si_usage_events'::regclass
           AND a.attnum>0 AND NOT a.attisdropped
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL PRIVILEGES (%I) ON TABLE public.jas_si_usage_events FROM jas_si_runtime',
            v_column
        );
    END LOOP;

    -- Include inherited grants in this assertion. If the runtime inherits
    -- access through another role, migration must fail for manual review.
    IF pg_catalog.has_table_privilege('jas_si_runtime','public.jas_si_usage_events','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_runtime','public.jas_si_usage_events','INSERT')
       OR pg_catalog.has_table_privilege('jas_si_runtime','public.jas_si_usage_events','UPDATE')
       OR pg_catalog.has_table_privilege('jas_si_runtime','public.jas_si_usage_events','DELETE')
       OR pg_catalog.has_table_privilege('jas_si_runtime','public.jas_si_usage_events','TRUNCATE')
       OR pg_catalog.has_table_privilege('jas_si_runtime','public.jas_si_usage_events','REFERENCES')
       OR pg_catalog.has_table_privilege('jas_si_runtime','public.jas_si_usage_events','TRIGGER')
       OR pg_catalog.has_any_column_privilege('jas_si_runtime','public.jas_si_usage_events','SELECT')
       OR pg_catalog.has_any_column_privilege('jas_si_runtime','public.jas_si_usage_events','INSERT')
       OR pg_catalog.has_any_column_privilege('jas_si_runtime','public.jas_si_usage_events','UPDATE')
       OR pg_catalog.has_any_column_privilege('jas_si_runtime','public.jas_si_usage_events','REFERENCES') THEN
        RAISE EXCEPTION 'jas_si_runtime retains direct or inherited usage-table privileges';
    END IF;
END
$block$;
