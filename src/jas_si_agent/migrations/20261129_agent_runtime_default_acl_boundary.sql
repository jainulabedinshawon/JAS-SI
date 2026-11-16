-- Remove broad future-object privileges from agent runtime login roles.
-- These roles must receive only explicit grants on the objects they require.
-- This migration is safe on clean replay databases where host login roles do
-- not exist yet; it also verifies the resulting default ACL when they do exist.

DO $block$
DECLARE
    v_worker_exists boolean;
    v_verifier_exists boolean;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='neondb_owner'
    ) THEN
        RAISE EXCEPTION 'Required default-privilege owner role is missing';
    END IF;

    SELECT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_agent_worker_login'
    ) INTO v_worker_exists;
    SELECT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_agent_verifier_login'
    ) INTO v_verifier_exists;

    IF v_worker_exists THEN
        EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE neondb_owner IN SCHEMA public '
             || 'REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES '
             || 'FROM jas_si_agent_worker_login';
        EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE neondb_owner IN SCHEMA public '
             || 'REVOKE SELECT, INSERT, UPDATE, DELETE ON SEQUENCES '
             || 'FROM jas_si_agent_worker_login';
    END IF;

    IF v_verifier_exists THEN
        EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE neondb_owner IN SCHEMA public '
             || 'REVOKE SELECT ON TABLES FROM jas_si_agent_verifier_login';
        EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE neondb_owner IN SCHEMA public '
             || 'REVOKE SELECT ON SEQUENCES FROM jas_si_agent_verifier_login';
    END IF;

    IF v_worker_exists AND EXISTS (
        SELECT 1
          FROM pg_catalog.pg_default_acl d
          JOIN pg_catalog.pg_roles owner_role ON owner_role.oid=d.defaclrole
          CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) acl
          JOIN pg_catalog.pg_roles grantee ON grantee.oid=acl.grantee
         WHERE owner_role.rolname='neondb_owner'
           AND d.defaclnamespace='public'::regnamespace
           AND grantee.rolname='jas_si_agent_worker_login'
           AND (
             (d.defaclobjtype='r' AND acl.privilege_type IN ('SELECT','INSERT','UPDATE','DELETE'))
             OR (d.defaclobjtype='S' AND acl.privilege_type IN ('SELECT','USAGE','UPDATE'))
           )
    ) THEN
        RAISE EXCEPTION 'Worker login retains broad future-object privileges';
    END IF;

    IF v_verifier_exists AND EXISTS (
        SELECT 1
          FROM pg_catalog.pg_default_acl d
          JOIN pg_catalog.pg_roles owner_role ON owner_role.oid=d.defaclrole
          CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) acl
          JOIN pg_catalog.pg_roles grantee ON grantee.oid=acl.grantee
         WHERE owner_role.rolname='neondb_owner'
           AND d.defaclnamespace='public'::regnamespace
           AND grantee.rolname='jas_si_agent_verifier_login'
           AND (
             (d.defaclobjtype='r' AND acl.privilege_type='SELECT')
             OR (d.defaclobjtype='S' AND acl.privilege_type IN ('SELECT','USAGE','UPDATE'))
           )
    ) THEN
        RAISE EXCEPTION 'Verifier login retains broad future-object privileges';
    END IF;
END
$block$;
