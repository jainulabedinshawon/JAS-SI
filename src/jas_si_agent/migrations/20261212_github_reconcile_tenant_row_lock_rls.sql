-- PostgreSQL applies UPDATE RLS policies to SELECT ... FOR SHARE.
-- The reconciler owner needs this narrowly scoped row-visibility policy to
-- serialize activation against tenant suspension. Its column ACL still permits
-- UPDATE only on the inert lock-version column; status/business fields remain
-- non-writable.
DO $preflight$
BEGIN
    IF pg_catalog.to_regclass('public.jas_si_tenants') IS NULL
       OR NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_roles
            WHERE rolname='jas_si_agent_task_owner'
       ) THEN
        RAISE EXCEPTION 'Tenant reconciliation row-lock policy prerequisites are missing';
    END IF;
    IF NOT pg_catalog.has_column_privilege(
        'jas_si_agent_task_owner','public.jas_si_tenants',
        'github_reconcile_lock_version','UPDATE'
    ) OR pg_catalog.has_column_privilege(
        'jas_si_agent_task_owner','public.jas_si_tenants','status','UPDATE'
    ) OR pg_catalog.has_column_privilege(
        'jas_si_agent_task_owner','public.jas_si_tenants','tenant_name','UPDATE'
    ) THEN
        RAISE EXCEPTION 'Tenant reconciliation row-lock column ACL is not least-privilege';
    END IF;
END
$preflight$;

DROP POLICY IF EXISTS jas_si_tenants_agent_reconcile_row_lock
    ON public.jas_si_tenants;
CREATE POLICY jas_si_tenants_agent_reconcile_row_lock
    ON public.jas_si_tenants
    FOR UPDATE TO jas_si_agent_task_owner
    USING (true) WITH CHECK (true);

DO $assert$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_policy p
          JOIN pg_catalog.pg_roles r ON r.oid=ANY(p.polroles)
         WHERE p.polrelid='public.jas_si_tenants'::regclass
           AND p.polname='jas_si_tenants_agent_reconcile_row_lock'
           AND p.polcmd='w'
           AND p.polpermissive
           AND r.rolname='jas_si_agent_task_owner'
    ) OR NOT pg_catalog.has_column_privilege(
        'jas_si_agent_task_owner','public.jas_si_tenants',
        'github_reconcile_lock_version','UPDATE'
    ) OR pg_catalog.has_column_privilege(
        'jas_si_agent_task_owner','public.jas_si_tenants','status','UPDATE'
    ) OR pg_catalog.has_column_privilege(
        'jas_si_agent_task_owner','public.jas_si_tenants','tenant_name','UPDATE'
    ) THEN
        RAISE EXCEPTION 'Tenant reconciliation row-lock RLS/ACL boundary is invalid';
    END IF;
END
$assert$;
