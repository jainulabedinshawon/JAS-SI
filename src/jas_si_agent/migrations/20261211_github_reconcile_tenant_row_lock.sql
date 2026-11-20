-- Permit the GitHub reconciler's SECURITY DEFINER owner to serialize
-- Installation activation with tenant suspension without granting tenant
-- status/business-field UPDATE authority.
DO $preflight$
BEGIN
    IF pg_catalog.to_regclass('public.jas_si_tenants') IS NULL
       OR NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_roles
            WHERE rolname='jas_si_agent_task_owner'
       ) THEN
        RAISE EXCEPTION 'Tenant reconciliation lock prerequisites are missing';
    END IF;
END
$preflight$;

ALTER TABLE public.jas_si_tenants
    ADD COLUMN IF NOT EXISTS github_reconcile_lock_version bigint NOT NULL DEFAULT 0;

DO $constraint$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE conrelid='public.jas_si_tenants'::regclass
           AND conname='jas_si_tenants_github_reconcile_lock_version_nonnegative'
    ) THEN
        ALTER TABLE public.jas_si_tenants
            ADD CONSTRAINT jas_si_tenants_github_reconcile_lock_version_nonnegative
            CHECK (github_reconcile_lock_version >= 0);
    END IF;
END
$constraint$;

-- PostgreSQL requires UPDATE privilege on at least one column for SELECT ...
-- FOR SHARE. This inert column is never changed by the reconciler; its
-- column-only grant permits row locking while keeping status immutable.
GRANT UPDATE (github_reconcile_lock_version)
    ON public.jas_si_tenants TO jas_si_agent_task_owner;

DO $assert$
BEGIN
    IF NOT pg_catalog.has_column_privilege(
        'jas_si_agent_task_owner','public.jas_si_tenants',
        'github_reconcile_lock_version','UPDATE'
    ) OR pg_catalog.has_column_privilege(
        'jas_si_agent_task_owner','public.jas_si_tenants','status','UPDATE'
    ) OR pg_catalog.has_column_privilege(
        'jas_si_agent_task_owner','public.jas_si_tenants','tenant_name','UPDATE'
    ) THEN
        RAISE EXCEPTION 'GitHub tenant row-lock privilege boundary is invalid';
    END IF;
END
$assert$;
