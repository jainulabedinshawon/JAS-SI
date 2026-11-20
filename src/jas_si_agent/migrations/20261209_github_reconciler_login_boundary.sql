-- Dedicated login identity for the GitHub Installation reconciler.
--
-- The application explicitly executes SET ROLE jas_si_github_reconciler on
-- every database connection. The login has no inherited capability privileges,
-- no direct table privileges, and no authority to SET any other role.
-- Password creation/rotation is intentionally outside this migration.

DO $roles$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
         WHERE rolname='jas_si_github_reconciler_login'
    ) THEN
        CREATE ROLE jas_si_github_reconciler_login
            NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOREPLICATION NOBYPASSRLS;
    END IF;
END
$roles$;

DO $preflight$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
         WHERE rolname='jas_si_github_reconciler'
           AND NOT rolcanlogin
           AND NOT rolinherit
    ) THEN
        RAISE EXCEPTION 'GitHub reconciler capability role is missing or unsafe';
    END IF;
END
$preflight$;

GRANT jas_si_github_reconciler TO jas_si_github_reconciler_login
    WITH INHERIT FALSE, SET TRUE;

GRANT USAGE ON SCHEMA public TO jas_si_github_reconciler_login;

DO $assert$
DECLARE
    v_function text;
    v_table text;
    v_privilege text;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
         WHERE rolname='jas_si_github_reconciler_login'
           AND NOT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb
           AND NOT rolcreaterole AND NOT rolreplication
           AND NOT rolbypassrls AND NOT rolinherit
    ) THEN
        RAISE EXCEPTION 'GitHub reconciler login role has unsafe role attributes';
    END IF;

    IF NOT pg_catalog.pg_has_role(
        'jas_si_github_reconciler_login','jas_si_github_reconciler','MEMBER'
    ) OR pg_catalog.pg_has_role(
        'jas_si_github_reconciler_login','jas_si_github_reconciler','USAGE'
    ) OR NOT pg_catalog.pg_has_role(
        'jas_si_github_reconciler_login','jas_si_github_reconciler','SET'
    ) THEN
        RAISE EXCEPTION 'Reconciler login must have SET-only capability membership';
    END IF;

    IF NOT pg_catalog.has_schema_privilege(
        'jas_si_github_reconciler_login','public','USAGE'
    ) OR pg_catalog.has_schema_privilege(
        'jas_si_github_reconciler_login','public','CREATE'
    ) THEN
        RAISE EXCEPTION 'Reconciler login schema privileges are not least-privilege';
    END IF;

    FOREACH v_function IN ARRAY ARRAY[
        'jas_si_github_installation_claim_pending(integer)',
        'jas_si_github_installation_reconcile_apply(bigint,uuid,text,text,jsonb)',
        'jas_si_github_webhook_claim(integer,integer)',
        'jas_si_github_webhook_mark_processed(text,uuid)',
        'jas_si_github_webhook_mark_failed(text,text,uuid,integer)'
    ] LOOP
        IF NOT pg_catalog.has_function_privilege(
            'jas_si_github_reconciler',
            ('public.'||v_function)::regprocedure,
            'EXECUTE'
        ) THEN
            RAISE EXCEPTION 'Reconciler capability is missing required EXECUTE: %',v_function;
        END IF;
    END LOOP;

    FOREACH v_table IN ARRAY ARRAY[
        'jas_si_github_app_installations',
        'jas_si_github_app_installation_repositories',
        'jas_si_github_webhook_inbox',
        'jas_si_github_oauth_attempts',
        'jas_si_github_installation_claims'
    ] LOOP
        FOREACH v_privilege IN ARRAY ARRAY[
            'SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'
        ] LOOP
            IF pg_catalog.has_table_privilege(
                'jas_si_github_reconciler_login',
                'public.'||v_table,
                v_privilege
            ) THEN
                RAISE EXCEPTION 'Reconciler login has direct table privilege: %.%',
                    v_table,v_privilege;
            END IF;
        END LOOP;
    END LOOP;

    IF pg_catalog.has_any_column_privilege(
        'jas_si_github_reconciler_login',
        'public.jas_si_github_app_installations','SELECT'
    ) OR pg_catalog.has_any_column_privilege(
        'jas_si_github_reconciler_login',
        'public.jas_si_github_app_installation_repositories','SELECT'
    ) OR pg_catalog.has_any_column_privilege(
        'jas_si_github_reconciler_login',
        'public.jas_si_github_webhook_inbox','SELECT'
    ) OR pg_catalog.has_any_column_privilege(
        'jas_si_github_reconciler_login',
        'public.jas_si_github_oauth_attempts','SELECT'
    ) OR pg_catalog.has_any_column_privilege(
        'jas_si_github_reconciler_login',
        'public.jas_si_github_installation_claims','SELECT'
    ) THEN
        RAISE EXCEPTION 'Reconciler login has forbidden column-level SELECT privileges';
    END IF;
END
$assert$;
