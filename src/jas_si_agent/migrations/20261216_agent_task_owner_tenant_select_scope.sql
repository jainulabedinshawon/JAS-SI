-- Narrow the task-owner tenant lookup back to the columns required by
-- the SECURITY DEFINER capability resolvers. The earlier Broker migration
-- granted table-wide SELECT even though the installation-binding migration
-- intentionally granted only tenant_id and status.
REVOKE SELECT ON TABLE public.jas_si_tenants
    FROM jas_si_agent_task_owner;
GRANT SELECT (tenant_id, status) ON TABLE public.jas_si_tenants
    TO jas_si_agent_task_owner;

DO $assert$
DECLARE v_extra_columns text;
BEGIN
    IF pg_catalog.has_table_privilege(
        'jas_si_agent_task_owner','public.jas_si_tenants','SELECT'
    ) THEN
        RAISE EXCEPTION 'Task owner regained table-wide tenant SELECT';
    END IF;
    IF NOT pg_catalog.has_column_privilege(
        'jas_si_agent_task_owner','public.jas_si_tenants','tenant_id','SELECT'
    ) OR NOT pg_catalog.has_column_privilege(
        'jas_si_agent_task_owner','public.jas_si_tenants','status','SELECT'
    ) THEN
        RAISE EXCEPTION 'Task owner lost required tenant identity/status column SELECT';
    END IF;

    SELECT pg_catalog.string_agg(a.attname, ', ' ORDER BY a.attnum)
      INTO v_extra_columns
      FROM pg_catalog.pg_attribute a
     WHERE a.attrelid='public.jas_si_tenants'::regclass
       AND a.attnum>0 AND NOT a.attisdropped
       AND a.attname NOT IN ('tenant_id','status')
       AND pg_catalog.has_column_privilege(
           'jas_si_agent_task_owner','public.jas_si_tenants',a.attname,'SELECT'
       );
    IF v_extra_columns IS NOT NULL THEN
        RAISE EXCEPTION 'Task owner has unexpected tenant column SELECT: %',v_extra_columns;
    END IF;
END
$assert$;
