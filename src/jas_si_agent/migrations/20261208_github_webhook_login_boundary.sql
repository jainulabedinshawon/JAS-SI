-- Dedicated least-privilege identity for the GitHub webhook API.
--
-- jas_si_runtime is an existing LOGIN role with direct audit-table privileges.
-- It must not be used as the webhook DSN. This role is intentionally created
-- NOLOGIN; an operator may later enable LOGIN and set its password through the
-- approved Neon credential workflow. It receives only direct EXECUTE grants on
-- the four webhook inbox routines. Its membership in jas_si_runtime exists
-- solely so the SECURITY DEFINER routines can validate session_user membership;
-- INHERIT and SET are both disabled to prevent audit privilege inheritance.
--
-- No password or credential material is created by this migration.

DO $roles$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
         WHERE rolname='jas_si_github_webhook_login'
    ) THEN
        CREATE ROLE jas_si_github_webhook_login
            NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOREPLICATION NOBYPASSRLS;
    END IF;
END
$roles$;

DO $preflight$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
         WHERE rolname='jas_si_runtime' AND rolcanlogin
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
         WHERE rolname='jas_si_agent_task_owner'
    ) THEN
        RAISE EXCEPTION 'GitHub webhook login boundary prerequisite roles are missing';
    END IF;
END
$preflight$;

GRANT jas_si_runtime TO jas_si_github_webhook_login
    WITH INHERIT FALSE, SET FALSE;

GRANT USAGE ON SCHEMA public TO jas_si_github_webhook_login;

SET LOCAL ROLE jas_si_agent_task_owner;

REVOKE ALL ON FUNCTION public.jas_si_github_webhook_receive(text,text,text,bigint,bytea,jsonb)
    FROM PUBLIC, jas_si_runtime;
REVOKE ALL ON FUNCTION public.jas_si_github_webhook_claim(integer,integer)
    FROM PUBLIC, jas_si_runtime;
REVOKE ALL ON FUNCTION public.jas_si_github_webhook_mark_processed(text,uuid)
    FROM PUBLIC, jas_si_runtime;
REVOKE ALL ON FUNCTION public.jas_si_github_webhook_mark_failed(text,text,uuid,integer)
    FROM PUBLIC, jas_si_runtime;

GRANT EXECUTE ON FUNCTION public.jas_si_github_webhook_receive(text,text,text,bigint,bytea,jsonb)
    TO jas_si_github_webhook_login;
GRANT EXECUTE ON FUNCTION public.jas_si_github_webhook_claim(integer,integer)
    TO jas_si_github_webhook_login;
GRANT EXECUTE ON FUNCTION public.jas_si_github_webhook_mark_processed(text,uuid)
    TO jas_si_github_webhook_login;
GRANT EXECUTE ON FUNCTION public.jas_si_github_webhook_mark_failed(text,text,uuid,integer)
    TO jas_si_github_webhook_login;

RESET ROLE;

DO $assert$
DECLARE
    v_function text;
    v_privilege text;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
         WHERE rolname='jas_si_github_webhook_login'
           AND NOT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb
           AND NOT rolcreaterole AND NOT rolreplication
           AND NOT rolbypassrls AND NOT rolinherit
    ) THEN
        RAISE EXCEPTION 'Dedicated GitHub webhook login role has unsafe role attributes';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_auth_members m
          JOIN pg_catalog.pg_roles granted ON granted.oid=m.roleid
          JOIN pg_catalog.pg_roles member ON member.oid=m.member
         WHERE granted.rolname='jas_si_runtime'
           AND member.rolname='jas_si_github_webhook_login'
           AND NOT m.inherit_option
           AND NOT m.set_option
           AND NOT m.admin_option
    ) THEN
        RAISE EXCEPTION 'Webhook login membership must be non-inheriting and non-settable';
    END IF;

    IF pg_catalog.pg_has_role(
        'jas_si_github_webhook_login','jas_si_runtime','USAGE'
    ) OR pg_catalog.pg_has_role(
        'jas_si_github_webhook_login','jas_si_runtime','SET'
    ) OR NOT pg_catalog.pg_has_role(
        'jas_si_github_webhook_login','jas_si_runtime','MEMBER'
    ) THEN
        RAISE EXCEPTION 'Webhook login has incorrect runtime role membership semantics';
    END IF;

    IF NOT pg_catalog.has_schema_privilege(
        'jas_si_github_webhook_login','public','USAGE'
    ) OR pg_catalog.has_schema_privilege(
        'jas_si_github_webhook_login','public','CREATE'
    ) THEN
        RAISE EXCEPTION 'Webhook login schema privileges are not least-privilege';
    END IF;

    FOREACH v_function IN ARRAY ARRAY[
        'jas_si_github_webhook_receive(text,text,text,bigint,bytea,jsonb)',
        'jas_si_github_webhook_claim(integer,integer)',
        'jas_si_github_webhook_mark_processed(text,uuid)',
        'jas_si_github_webhook_mark_failed(text,text,uuid,integer)'
    ] LOOP
        IF NOT pg_catalog.has_function_privilege(
            'jas_si_github_webhook_login',
            ('public.'||v_function)::regprocedure,
            'EXECUTE'
        ) THEN
            RAISE EXCEPTION 'Webhook login is missing required EXECUTE: %',v_function;
        END IF;
        IF pg_catalog.has_function_privilege(
            'jas_si_runtime',
            ('public.'||v_function)::regprocedure,
            'EXECUTE'
        ) THEN
            RAISE EXCEPTION 'Broad runtime role retains webhook EXECUTE: %',v_function;
        END IF;
    END LOOP;

    FOREACH v_privilege IN ARRAY ARRAY[
        'SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'
    ] LOOP
        IF pg_catalog.has_table_privilege(
            'jas_si_github_webhook_login',
            'public.jas_si_github_webhook_inbox',
            v_privilege
        ) OR pg_catalog.has_table_privilege(
            'jas_si_github_webhook_login',
            'public.jas_si_audit_events',
            v_privilege
        ) OR pg_catalog.has_table_privilege(
            'jas_si_github_webhook_login',
            'public.jas_si_audit_chain_state',
            v_privilege
        ) THEN
            RAISE EXCEPTION 'Webhook login has forbidden direct table privilege: %',v_privilege;
        END IF;
    END LOOP;

    IF pg_catalog.has_any_column_privilege(
        'jas_si_github_webhook_login','public.jas_si_github_webhook_inbox','SELECT'
    ) OR pg_catalog.has_any_column_privilege(
        'jas_si_github_webhook_login','public.jas_si_audit_events','SELECT'
    ) OR pg_catalog.has_any_column_privilege(
        'jas_si_github_webhook_login','public.jas_si_audit_chain_state','SELECT'
    ) THEN
        RAISE EXCEPTION 'Webhook login has forbidden column-level SELECT privileges';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM pg_catalog.aclexplode(COALESCE(
              (SELECT p.proacl FROM pg_catalog.pg_proc p
                WHERE p.oid='public.jas_si_github_webhook_receive(text,text,text,bigint,bytea,jsonb)'::regprocedure),
              pg_catalog.acldefault('f',(
                  SELECT p.proowner FROM pg_catalog.pg_proc p
                   WHERE p.oid='public.jas_si_github_webhook_receive(text,text,text,bigint,bytea,jsonb)'::regprocedure
              ))
          )) acl
         WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'
    ) THEN
        RAISE EXCEPTION 'PUBLIC retains webhook function execution';
    END IF;
END
$assert$;
