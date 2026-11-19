-- Contract phase: remove direct application access after the routine-based
-- runtime has been deployed and verified in the expand phase.
-- No application role may inspect or mutate bucket state directly. The
-- database-owned routine is the only permitted access path. Revoke legacy
-- table and column grants from all application roles, including inherited
-- PUBLIC-effective grants, before asserting the effective boundary.
REVOKE ALL PRIVILEGES ON TABLE public.jas_si_customer_rate_limits
    FROM PUBLIC, jas_si_customer_runtime, jas_si_runtime, jas_si_provisioner;
DO $revoke_columns$
DECLARE
    v_column text;
BEGIN
    FOR v_column IN
        SELECT a.attname
          FROM pg_catalog.pg_attribute a
         WHERE a.attrelid='public.jas_si_customer_rate_limits'::regclass
           AND a.attnum>0 AND NOT a.attisdropped
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL PRIVILEGES (%I) ON TABLE public.jas_si_customer_rate_limits FROM PUBLIC, jas_si_customer_runtime, jas_si_runtime, jas_si_provisioner',
            v_column
        );
    END LOOP;
END
$revoke_columns$;

DO $assert_runtime_acl$
DECLARE
    v_role text;
BEGIN
    FOREACH v_role IN ARRAY ARRAY[
        'jas_si_customer_runtime','jas_si_runtime','jas_si_provisioner'
    ] LOOP
        IF pg_catalog.has_table_privilege(v_role,'public.jas_si_customer_rate_limits','SELECT')
           OR pg_catalog.has_table_privilege(v_role,'public.jas_si_customer_rate_limits','INSERT')
           OR pg_catalog.has_table_privilege(v_role,'public.jas_si_customer_rate_limits','UPDATE')
           OR pg_catalog.has_table_privilege(v_role,'public.jas_si_customer_rate_limits','DELETE')
           OR pg_catalog.has_table_privilege(v_role,'public.jas_si_customer_rate_limits','TRUNCATE')
           OR pg_catalog.has_table_privilege(v_role,'public.jas_si_customer_rate_limits','REFERENCES')
           OR pg_catalog.has_table_privilege(v_role,'public.jas_si_customer_rate_limits','TRIGGER')
           OR pg_catalog.has_any_column_privilege(v_role,'public.jas_si_customer_rate_limits','SELECT')
           OR pg_catalog.has_any_column_privilege(v_role,'public.jas_si_customer_rate_limits','INSERT')
           OR pg_catalog.has_any_column_privilege(v_role,'public.jas_si_customer_rate_limits','UPDATE')
           OR pg_catalog.has_any_column_privilege(v_role,'public.jas_si_customer_rate_limits','REFERENCES') THEN
            RAISE EXCEPTION '% retains direct customer rate-limit table privileges',v_role;
        END IF;
    END LOOP;
END
$assert_runtime_acl$;
