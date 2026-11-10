-- Allow the operator provisioner to lock tenant rows during atomic issuance
-- without granting it permission to change tenant status or other tenant data.
--
-- PostgreSQL requires UPDATE privilege on at least one column for SELECT ...
-- FOR UPDATE. A dedicated inert lock-version column keeps that privilege
-- separate from tenant status and business fields.

ALTER TABLE public.jas_si_tenants
    ADD COLUMN IF NOT EXISTS provisioning_lock_version BIGINT NOT NULL DEFAULT 0;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = 'jas_si_provisioner'
    ) THEN
        EXECUTE
            'GRANT UPDATE (provisioning_lock_version) '
            'ON TABLE public.jas_si_tenants TO jas_si_provisioner';
    END IF;
END
$$;
