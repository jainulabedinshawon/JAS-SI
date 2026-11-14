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
        IF EXISTS (
            SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = v_role
        ) THEN
            FOREACH v_table IN ARRAY ARRAY[
                'jas_si_customer_accounts',
                'jas_si_customer_auth_tokens',
                'jas_si_customer_sessions'
            ] LOOP
                IF pg_catalog.to_regclass('public.' || v_table) IS NOT NULL THEN
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
                END IF;
            END LOOP;
        END IF;
    END LOOP;
END
$$;
