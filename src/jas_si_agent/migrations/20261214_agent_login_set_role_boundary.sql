-- Enforce the documented NOINHERIT / explicit SET ROLE boundary for
-- already-provisioned Worker and Verifier logins. This migration does not
-- create logins, assign passwords, or grant a missing capability membership.
DO $block$
DECLARE
    v_login text;
    v_capability text;
BEGIN
    FOR v_login, v_capability IN
        SELECT * FROM (VALUES
            ('jas_si_agent_worker_login','jas_si_agent_worker'),
            ('jas_si_agent_verifier_login','jas_si_agent_verifier')
        ) AS configured(login_name, capability_name)
    LOOP
        IF EXISTS (
            SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=v_login
        ) THEN
            EXECUTE pg_catalog.format('ALTER ROLE %I NOINHERIT',v_login);
        END IF;

        IF EXISTS (
            SELECT 1
              FROM pg_catalog.pg_roles member_role
              JOIN pg_catalog.pg_roles granted_role
                ON granted_role.rolname=v_capability
              JOIN pg_catalog.pg_auth_members membership
                ON membership.member=member_role.oid
               AND membership.roleid=granted_role.oid
             WHERE member_role.rolname=v_login
        ) THEN
            -- GRANT does not reliably rewrite existing membership options.
            -- Revoke and recreate this single expected capability membership
            -- inside the migration transaction to guarantee SET-only semantics.
            EXECUTE pg_catalog.format('REVOKE %I FROM %I',v_capability,v_login);
            EXECUTE pg_catalog.format(
                'GRANT %I TO %I WITH ADMIN FALSE, INHERIT FALSE, SET TRUE',
                v_capability,v_login
            );
        END IF;
    END LOOP;
END
$block$;

DO $assert$
DECLARE
    v_login text;
    v_capability text;
    v_login_inherit boolean;
    v_member boolean;
    v_inherit_option boolean;
    v_set_option boolean;
    v_admin_option boolean;
BEGIN
    FOR v_login, v_capability IN
        SELECT * FROM (VALUES
            ('jas_si_agent_worker_login','jas_si_agent_worker'),
            ('jas_si_agent_verifier_login','jas_si_agent_verifier')
        ) AS configured(login_name, capability_name)
    LOOP
        IF EXISTS (
            SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=v_login
        ) THEN
            SELECT rolinherit INTO v_login_inherit
              FROM pg_catalog.pg_roles WHERE rolname=v_login;

            SELECT true,membership.inherit_option,
                   membership.set_option,membership.admin_option
              INTO v_member,v_inherit_option,v_set_option,v_admin_option
              FROM pg_catalog.pg_auth_members membership
              JOIN pg_catalog.pg_roles member_role
                ON member_role.oid=membership.member
              JOIN pg_catalog.pg_roles granted_role
                ON granted_role.oid=membership.roleid
             WHERE member_role.rolname=v_login
               AND granted_role.rolname=v_capability;

            IF v_login_inherit IS DISTINCT FROM false
               OR v_member IS DISTINCT FROM true
               OR v_inherit_option IS DISTINCT FROM false
               OR v_set_option IS DISTINCT FROM true
               OR v_admin_option IS DISTINCT FROM false THEN
                RAISE EXCEPTION 'Agent database login capability membership is not NOINHERIT/SET-only';
            END IF;
        END IF;
    END LOOP;
END
$assert$;
