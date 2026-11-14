-- Remove legacy broad-runtime access to customer identity secrets and PII.
-- Customer identity operations must go through the dedicated SECURITY DEFINER
-- routines exposed to jas_si_customer_runtime, never direct table reads.
DO $$
DECLARE
    v_role text;
    v_table text;
    v_column text;
BEGIN
    FOREACH v_role IN ARRAY ARRAY['jas_si_runtime', 'jas_si_provisioner'] LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = v_role
        ) THEN
            RAISE EXCEPTION 'Required general runtime role % is missing', v_role;
        END IF;

        FOREACH v_table IN ARRAY ARRAY[
            'jas_si_customer_accounts',
            'jas_si_customer_auth_tokens',
            'jas_si_customer_sessions'
        ] LOOP
            IF pg_catalog.to_regclass('public.' || v_table) IS NULL THEN
                RAISE EXCEPTION 'Required customer identity table % is missing', v_table;
            END IF;

            EXECUTE pg_catalog.format(
                'REVOKE ALL PRIVILEGES ON TABLE public.%I FROM %I',
                v_table, v_role
            );

            FOR v_column IN
                SELECT a.attname
                FROM pg_catalog.pg_attribute AS a
                WHERE a.attrelid = pg_catalog.to_regclass('public.' || v_table)
                  AND a.attnum > 0
                  AND NOT a.attisdropped
            LOOP
                EXECUTE pg_catalog.format(
                    'REVOKE ALL PRIVILEGES (%I) ON TABLE public.%I FROM %I',
                    v_column, v_table, v_role
                );
            END LOOP;

            -- Include inherited and PUBLIC-effective grants. If another grant
            -- path remains, abort the migration rather than report false isolation.
            IF pg_catalog.has_table_privilege(v_role, 'public.' || v_table, 'SELECT')
               OR pg_catalog.has_table_privilege(v_role, 'public.' || v_table, 'INSERT')
               OR pg_catalog.has_table_privilege(v_role, 'public.' || v_table, 'UPDATE')
               OR pg_catalog.has_table_privilege(v_role, 'public.' || v_table, 'DELETE')
               OR pg_catalog.has_table_privilege(v_role, 'public.' || v_table, 'TRUNCATE')
               OR pg_catalog.has_table_privilege(v_role, 'public.' || v_table, 'REFERENCES')
               OR pg_catalog.has_table_privilege(v_role, 'public.' || v_table, 'TRIGGER')
               OR pg_catalog.has_any_column_privilege(v_role, 'public.' || v_table, 'SELECT')
               OR pg_catalog.has_any_column_privilege(v_role, 'public.' || v_table, 'INSERT')
               OR pg_catalog.has_any_column_privilege(v_role, 'public.' || v_table, 'UPDATE')
               OR pg_catalog.has_any_column_privilege(v_role, 'public.' || v_table, 'REFERENCES') THEN
                RAISE EXCEPTION '% retains effective privileges on customer identity table %',
                    v_role, v_table;
            END IF;
        END LOOP;

        -- Identity SECURITY DEFINER routines are customer-runtime-only.
        -- Fail closed if a general role inherits EXECUTE through any grant path.
        IF EXISTS (
            SELECT 1
              FROM pg_catalog.pg_proc p
              JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
             WHERE n.nspname='public'
               AND pg_catalog.left(p.proname,9)='customer_'
               AND pg_catalog.has_function_privilege(v_role,p.oid,'EXECUTE')
        ) THEN
            RAISE EXCEPTION '% retains EXECUTE on customer identity routines', v_role;
        END IF;
    END LOOP;
END
$;
