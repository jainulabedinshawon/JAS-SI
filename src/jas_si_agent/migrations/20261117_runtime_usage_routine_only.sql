-- Cut both the API runtime and key provisioner over to authenticated usage routines only.
-- Usage writes, summary, quota and history reads are performed by narrowly
-- granted SECURITY DEFINER routines owned by jas_si_api_key_usage_owner.
-- Customer-session usage reads use separate customer identity routines.
DO $block$
DECLARE
    v_role text;
    v_column text;
BEGIN
    IF pg_catalog.to_regclass('public.jas_si_usage_events') IS NULL THEN
        RAISE EXCEPTION 'Usage table is required before runtime privilege revocation';
    END IF;

    FOREACH v_role IN ARRAY ARRAY['jas_si_runtime', 'jas_si_provisioner'] LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=v_role
        ) THEN
            RAISE EXCEPTION '% role is required before usage privilege revocation', v_role;
        END IF;

        EXECUTE pg_catalog.format(
            'REVOKE ALL PRIVILEGES ON TABLE public.jas_si_usage_events FROM %I',
            v_role
        );

        FOR v_column IN
            SELECT a.attname
              FROM pg_catalog.pg_attribute a
             WHERE a.attrelid='public.jas_si_usage_events'::regclass
               AND a.attnum>0 AND NOT a.attisdropped
        LOOP
            EXECUTE pg_catalog.format(
                'REVOKE ALL PRIVILEGES (%I) ON TABLE public.jas_si_usage_events FROM %I',
                v_column, v_role
            );
        END LOOP;

        -- Include inherited and PUBLIC-effective grants in this assertion.
        IF pg_catalog.has_table_privilege(v_role,'public.jas_si_usage_events','SELECT')
           OR pg_catalog.has_table_privilege(v_role,'public.jas_si_usage_events','INSERT')
           OR pg_catalog.has_table_privilege(v_role,'public.jas_si_usage_events','UPDATE')
           OR pg_catalog.has_table_privilege(v_role,'public.jas_si_usage_events','DELETE')
           OR pg_catalog.has_table_privilege(v_role,'public.jas_si_usage_events','TRUNCATE')
           OR pg_catalog.has_table_privilege(v_role,'public.jas_si_usage_events','REFERENCES')
           OR pg_catalog.has_table_privilege(v_role,'public.jas_si_usage_events','TRIGGER')
           OR pg_catalog.has_any_column_privilege(v_role,'public.jas_si_usage_events','SELECT')
           OR pg_catalog.has_any_column_privilege(v_role,'public.jas_si_usage_events','INSERT')
           OR pg_catalog.has_any_column_privilege(v_role,'public.jas_si_usage_events','UPDATE')
           OR pg_catalog.has_any_column_privilege(v_role,'public.jas_si_usage_events','REFERENCES') THEN
            RAISE EXCEPTION '% retains direct or inherited usage-table privileges', v_role;
        END IF;
    END LOOP;
END
$block$;
