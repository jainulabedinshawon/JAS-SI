-- Align future-object privileges for general runtime/provisioner logins with
-- the verified Staging baseline: SELECT-only on tables, no sequence access.
-- This prevents new migrations from silently widening application privileges.

DO $block$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='neondb_owner'
    ) THEN
        RAISE EXCEPTION 'Required default-privilege owner role is missing';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_runtime'
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_provisioner'
    ) THEN
        RAISE EXCEPTION 'Required runtime/provisioner roles are missing';
    END IF;
END
$block$;

ALTER DEFAULT PRIVILEGES FOR ROLE neondb_owner IN SCHEMA public
    REVOKE ALL PRIVILEGES ON TABLES
    FROM jas_si_runtime, jas_si_provisioner;

ALTER DEFAULT PRIVILEGES FOR ROLE neondb_owner IN SCHEMA public
    GRANT SELECT ON TABLES
    TO jas_si_runtime, jas_si_provisioner;

ALTER DEFAULT PRIVILEGES FOR ROLE neondb_owner IN SCHEMA public
    REVOKE ALL PRIVILEGES ON SEQUENCES
    FROM jas_si_runtime, jas_si_provisioner;

DO $assert_boundary$
DECLARE
    v_role text;
BEGIN
    FOREACH v_role IN ARRAY ARRAY['jas_si_runtime','jas_si_provisioner'] LOOP
        IF EXISTS (
            SELECT 1
              FROM pg_catalog.pg_default_acl d
              JOIN pg_catalog.pg_roles owner_role ON owner_role.oid=d.defaclrole
              CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) acl
             WHERE owner_role.rolname='neondb_owner'
               AND d.defaclnamespace='public'::regnamespace
               AND acl.grantee=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=v_role)
               AND (
                   (d.defaclobjtype='r' AND acl.privilege_type<>'SELECT')
                   OR d.defaclobjtype='S'
               )
        ) THEN
            RAISE EXCEPTION '% retains excessive future-object privileges',v_role;
        END IF;

        IF NOT EXISTS (
            SELECT 1
              FROM pg_catalog.pg_default_acl d
              JOIN pg_catalog.pg_roles owner_role ON owner_role.oid=d.defaclrole
              CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) acl
             WHERE owner_role.rolname='neondb_owner'
               AND d.defaclnamespace='public'::regnamespace
               AND d.defaclobjtype='r'
               AND acl.grantee=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=v_role)
               AND acl.privilege_type='SELECT'
        ) THEN
            RAISE EXCEPTION '% is missing the verified SELECT-only table default',v_role;
        END IF;
    END LOOP;
END
$assert_boundary$;
