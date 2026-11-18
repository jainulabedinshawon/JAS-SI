-- Tenant-owned GitHub App installation and repository allowlist.
-- Rows are intentionally not auto-created: an installation must be verified
-- by a trusted GitHub App callback/operator before it can become active.
-- Worker and Verifier can resolve only active, verified bindings through one
-- SECURITY DEFINER routine; neither role can read or mutate the backing tables.

DO $preflight$
BEGIN
    IF pg_catalog.to_regclass('public.jas_si_tenants') IS NULL
       OR NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_roles
            WHERE rolname='jas_si_agent_task_owner'
       )
       OR NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_roles
            WHERE rolname='jas_si_agent_worker'
       )
       OR NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_roles
            WHERE rolname='jas_si_agent_verifier'
       ) THEN
        RAISE EXCEPTION 'Tenant and agent capability-role prerequisites are missing';
    END IF;
END
$preflight$;

GRANT CREATE ON SCHEMA public TO jas_si_agent_task_owner;
SET LOCAL ROLE jas_si_agent_task_owner;

CREATE TABLE IF NOT EXISTS public.jas_si_github_app_installations (
    installation_id bigint PRIMARY KEY CHECK (installation_id > 0),
    tenant_id uuid NOT NULL
        REFERENCES public.jas_si_tenants(tenant_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    account_login varchar(39) NOT NULL
        CHECK (account_login ~ '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$'),
    status varchar(16) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','active','revoked')),
    verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT jas_si_github_installation_status_verification
        CHECK ((status='active' AND verified_at IS NOT NULL)
            OR (status IN ('pending','revoked')))
);
DO $constraint$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE conname='jas_si_github_installation_tenant_pair_unique'
           AND conrelid='public.jas_si_github_app_installations'::regclass
    ) THEN
        ALTER TABLE public.jas_si_github_app_installations
            ADD CONSTRAINT jas_si_github_installation_tenant_pair_unique
            UNIQUE (installation_id,tenant_id);
    END IF;
END
$constraint$;

CREATE TABLE IF NOT EXISTS public.jas_si_github_app_installation_repositories (
    installation_id bigint NOT NULL,
    tenant_id uuid NOT NULL,
    repository_full_name varchar(140) NOT NULL
        CHECK (repository_full_name ~ '^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9_.-]{1,100}),
    status varchar(16) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','active','revoked')),
    verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (installation_id,repository_full_name),
    CONSTRAINT jas_si_github_repo_installation_tenant_fk
        FOREIGN KEY (installation_id,tenant_id)
        REFERENCES public.jas_si_github_app_installations(installation_id,tenant_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT jas_si_github_repo_status_verification
        CHECK ((status='active' AND verified_at IS NOT NULL)
            OR (status IN ('pending','revoked')))
);
CREATE UNIQUE INDEX IF NOT EXISTS jas_si_github_repo_tenant_name_unique
    ON public.jas_si_github_app_installation_repositories
       (tenant_id,pg_catalog.lower(repository_full_name));

REVOKE ALL PRIVILEGES ON TABLE
    public.jas_si_github_app_installations,
    public.jas_si_github_app_installation_repositories
    FROM PUBLIC,jas_si_runtime,jas_si_provisioner,
         jas_si_agent_worker,jas_si_agent_verifier,
         jas_si_agent_worker_login,jas_si_agent_verifier_login;

ALTER TABLE public.jas_si_github_app_installations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.jas_si_github_app_installations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS jas_si_github_installation_owner_all
    ON public.jas_si_github_app_installations;
CREATE POLICY jas_si_github_installation_owner_all
    ON public.jas_si_github_app_installations
    FOR ALL TO jas_si_agent_task_owner USING (true) WITH CHECK (true);

ALTER TABLE public.jas_si_github_app_installation_repositories ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.jas_si_github_app_installation_repositories FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS jas_si_github_repository_owner_all
    ON public.jas_si_github_app_installation_repositories;
CREATE POLICY jas_si_github_repository_owner_all
    ON public.jas_si_github_app_installation_repositories
    FOR ALL TO jas_si_agent_task_owner USING (true) WITH CHECK (true);

CREATE OR REPLACE FUNCTION public.jas_si_github_installation_binding_resolve(
    p_tenant_id uuid,
    p_repository_full_name text
) RETURNS TABLE(
    tenant_id uuid,
    installation_id bigint,
    repository_full_name text
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
BEGIN
    IF NOT (
        pg_catalog.pg_has_role(session_user,'jas_si_agent_worker','MEMBER')
        OR pg_catalog.pg_has_role(session_user,'jas_si_agent_verifier','MEMBER')
    ) THEN
        RAISE EXCEPTION 'Agent host identity is not authorized' USING ERRCODE='42501';
    END IF;
    IF p_tenant_id IS NULL OR p_repository_full_name IS NULL
       OR length(p_repository_full_name)>140
       OR p_repository_full_name !~ '^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9_.-]{1,100} THEN
        RAISE EXCEPTION 'Invalid tenant GitHub repository binding request' USING ERRCODE='22023';
    END IF;

    RETURN QUERY
    SELECT i.tenant_id,i.installation_id,r.repository_full_name::text
      FROM public.jas_si_github_app_installations i
      JOIN public.jas_si_github_app_installation_repositories r
        ON r.installation_id=i.installation_id AND r.tenant_id=i.tenant_id
      JOIN public.jas_si_tenants t ON t.tenant_id=i.tenant_id
     WHERE i.tenant_id=p_tenant_id
       AND pg_catalog.lower(r.repository_full_name)=pg_catalog.lower(p_repository_full_name)
       AND i.status='active' AND i.verified_at IS NOT NULL
       AND r.status='active' AND r.verified_at IS NOT NULL
       AND t.status='active'
     LIMIT 1;
END;
$function$;

REVOKE ALL ON FUNCTION public.jas_si_github_installation_binding_resolve(uuid,text)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.jas_si_github_installation_binding_resolve(uuid,text)
    TO jas_si_agent_worker,jas_si_agent_verifier;

RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_agent_task_owner;

DO $assert$
DECLARE v_proc oid; v_owner text;
BEGIN
    SELECT p.oid,pg_catalog.pg_get_userbyid(p.proowner)
      INTO v_proc,v_owner
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
     WHERE n.nspname='public'
       AND p.proname='jas_si_github_installation_binding_resolve'
       AND pg_catalog.pg_get_function_identity_arguments(p.oid)='p_tenant_id uuid, p_repository_full_name text';
    IF v_proc IS NULL OR v_owner<>'jas_si_agent_task_owner'
       OR NOT (SELECT p.prosecdef FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
       OR NOT (SELECT COALESCE(p.proconfig,ARRAY[]::text[]) @> ARRAY['search_path=pg_catalog']
                 FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
       OR NOT pg_catalog.has_function_privilege('jas_si_agent_worker',v_proc,'EXECUTE')
       OR NOT pg_catalog.has_function_privilege('jas_si_agent_verifier',v_proc,'EXECUTE')
       OR EXISTS (
           SELECT 1 FROM pg_catalog.aclexplode(
               COALESCE((SELECT p.proacl FROM pg_catalog.pg_proc p WHERE p.oid=v_proc),
                        pg_catalog.acldefault('f',(SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)))
           ) acl WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'
       )
       OR pg_catalog.has_table_privilege('jas_si_agent_worker','public.jas_si_github_app_installations','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_agent_verifier','public.jas_si_github_app_installations','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_agent_worker','public.jas_si_github_app_installation_repositories','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_agent_verifier','public.jas_si_github_app_installation_repositories','SELECT') THEN
        RAISE EXCEPTION 'Tenant GitHub installation binding security boundary is invalid';
    END IF;
END
$assert$;
),
    status varchar(16) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','active','revoked')),
    verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (installation_id,repository_full_name),
    CONSTRAINT jas_si_github_repo_installation_tenant_fk
        FOREIGN KEY (installation_id,tenant_id)
        REFERENCES public.jas_si_github_app_installations(installation_id,tenant_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT jas_si_github_repo_status_verification
        CHECK ((status='active' AND verified_at IS NOT NULL)
            OR (status IN ('pending','revoked')))
);
CREATE UNIQUE INDEX IF NOT EXISTS jas_si_github_repo_tenant_name_unique
    ON public.jas_si_github_app_installation_repositories
       (tenant_id,pg_catalog.lower(repository_full_name));

REVOKE ALL PRIVILEGES ON TABLE
    public.jas_si_github_app_installations,
    public.jas_si_github_app_installation_repositories
    FROM PUBLIC,jas_si_runtime,jas_si_provisioner,
         jas_si_agent_worker,jas_si_agent_verifier,
         jas_si_agent_worker_login,jas_si_agent_verifier_login;

ALTER TABLE public.jas_si_github_app_installations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.jas_si_github_app_installations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS jas_si_github_installation_owner_all
    ON public.jas_si_github_app_installations;
CREATE POLICY jas_si_github_installation_owner_all
    ON public.jas_si_github_app_installations
    FOR ALL TO jas_si_agent_task_owner USING (true) WITH CHECK (true);

ALTER TABLE public.jas_si_github_app_installation_repositories ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.jas_si_github_app_installation_repositories FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS jas_si_github_repository_owner_all
    ON public.jas_si_github_app_installation_repositories;
CREATE POLICY jas_si_github_repository_owner_all
    ON public.jas_si_github_app_installation_repositories
    FOR ALL TO jas_si_agent_task_owner USING (true) WITH CHECK (true);

CREATE OR REPLACE FUNCTION public.jas_si_github_installation_binding_resolve(
    p_tenant_id uuid,
    p_repository_full_name text
) RETURNS TABLE(
    tenant_id uuid,
    installation_id bigint,
    repository_full_name text
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
BEGIN
    IF NOT (
        pg_catalog.pg_has_role(session_user,'jas_si_agent_worker','MEMBER')
        OR pg_catalog.pg_has_role(session_user,'jas_si_agent_verifier','MEMBER')
    ) THEN
        RAISE EXCEPTION 'Agent host identity is not authorized' USING ERRCODE='42501';
    END IF;
    IF p_tenant_id IS NULL OR p_repository_full_name IS NULL
       OR length(p_repository_full_name)>140
       OR p_repository_full_name !~ '^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}$' THEN
        RAISE EXCEPTION 'Invalid tenant GitHub repository binding request' USING ERRCODE='22023';
    END IF;

    RETURN QUERY
    SELECT i.tenant_id,i.installation_id,r.repository_full_name::text
      FROM public.jas_si_github_app_installations i
      JOIN public.jas_si_github_app_installation_repositories r
        ON r.installation_id=i.installation_id AND r.tenant_id=i.tenant_id
      JOIN public.jas_si_tenants t ON t.tenant_id=i.tenant_id
     WHERE i.tenant_id=p_tenant_id
       AND pg_catalog.lower(r.repository_full_name)=pg_catalog.lower(p_repository_full_name)
       AND i.status='active' AND i.verified_at IS NOT NULL
       AND r.status='active' AND r.verified_at IS NOT NULL
       AND t.status='active'
     LIMIT 1;
END;
$function$;

REVOKE ALL ON FUNCTION public.jas_si_github_installation_binding_resolve(uuid,text)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.jas_si_github_installation_binding_resolve(uuid,text)
    TO jas_si_agent_worker,jas_si_agent_verifier;

RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_agent_task_owner;

DO $assert$
DECLARE v_proc oid; v_owner text;
BEGIN
    SELECT p.oid,pg_catalog.pg_get_userbyid(p.proowner)
      INTO v_proc,v_owner
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
     WHERE n.nspname='public'
       AND p.proname='jas_si_github_installation_binding_resolve'
       AND pg_catalog.pg_get_function_identity_arguments(p.oid)='p_tenant_id uuid, p_repository_full_name text';
    IF v_proc IS NULL OR v_owner<>'jas_si_agent_task_owner'
       OR NOT (SELECT p.prosecdef FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
       OR NOT (SELECT COALESCE(p.proconfig,ARRAY[]::text[]) @> ARRAY['search_path=pg_catalog']
                 FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
       OR NOT pg_catalog.has_function_privilege('jas_si_agent_worker',v_proc,'EXECUTE')
       OR NOT pg_catalog.has_function_privilege('jas_si_agent_verifier',v_proc,'EXECUTE')
       OR EXISTS (
           SELECT 1 FROM pg_catalog.aclexplode(
               COALESCE((SELECT p.proacl FROM pg_catalog.pg_proc p WHERE p.oid=v_proc),
                        pg_catalog.acldefault('f',(SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)))
           ) acl WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'
       )
       OR pg_catalog.has_table_privilege('jas_si_agent_worker','public.jas_si_github_app_installations','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_agent_verifier','public.jas_si_github_app_installations','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_agent_worker','public.jas_si_github_app_installation_repositories','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_agent_verifier','public.jas_si_github_app_installation_repositories','SELECT') THEN
        RAISE EXCEPTION 'Tenant GitHub installation binding security boundary is invalid';
    END IF;
END
$assert$;
 THEN
        RAISE EXCEPTION 'Invalid tenant GitHub repository binding request' USING ERRCODE='22023';
    END IF;

    RETURN QUERY
    SELECT i.tenant_id,i.installation_id,r.repository_full_name::text
      FROM public.jas_si_github_app_installations i
      JOIN public.jas_si_github_app_installation_repositories r
        ON r.installation_id=i.installation_id AND r.tenant_id=i.tenant_id
      JOIN public.jas_si_tenants t ON t.tenant_id=i.tenant_id
     WHERE i.tenant_id=p_tenant_id
       AND pg_catalog.lower(r.repository_full_name)=pg_catalog.lower(p_repository_full_name)
       AND i.status='active' AND i.verified_at IS NOT NULL
       AND r.status='active' AND r.verified_at IS NOT NULL
       AND t.status='active'
     LIMIT 1;
END;
$function$;

REVOKE ALL ON FUNCTION public.jas_si_github_installation_binding_resolve(uuid,text)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.jas_si_github_installation_binding_resolve(uuid,text)
    TO jas_si_agent_worker,jas_si_agent_verifier;

RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_agent_task_owner;

DO $assert$
DECLARE v_proc oid; v_owner text;
BEGIN
    SELECT p.oid,pg_catalog.pg_get_userbyid(p.proowner)
      INTO v_proc,v_owner
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
     WHERE n.nspname='public'
       AND p.proname='jas_si_github_installation_binding_resolve'
       AND pg_catalog.pg_get_function_identity_arguments(p.oid)='p_tenant_id uuid, p_repository_full_name text';
    IF v_proc IS NULL OR v_owner<>'jas_si_agent_task_owner'
       OR NOT (SELECT p.prosecdef FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
       OR NOT (SELECT COALESCE(p.proconfig,ARRAY[]::text[]) @> ARRAY['search_path=pg_catalog']
                 FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
       OR NOT pg_catalog.has_function_privilege('jas_si_agent_worker',v_proc,'EXECUTE')
       OR NOT pg_catalog.has_function_privilege('jas_si_agent_verifier',v_proc,'EXECUTE')
       OR EXISTS (
           SELECT 1 FROM pg_catalog.aclexplode(
               COALESCE((SELECT p.proacl FROM pg_catalog.pg_proc p WHERE p.oid=v_proc),
                        pg_catalog.acldefault('f',(SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)))
           ) acl WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'
       )
       OR pg_catalog.has_table_privilege('jas_si_agent_worker','public.jas_si_github_app_installations','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_agent_verifier','public.jas_si_github_app_installations','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_agent_worker','public.jas_si_github_app_installation_repositories','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_agent_verifier','public.jas_si_github_app_installation_repositories','SELECT') THEN
        RAISE EXCEPTION 'Tenant GitHub installation binding security boundary is invalid';
    END IF;
END
$assert$;
),
    status varchar(16) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','active','revoked')),
    verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (installation_id,repository_full_name),
    CONSTRAINT jas_si_github_repo_installation_tenant_fk
        FOREIGN KEY (installation_id,tenant_id)
        REFERENCES public.jas_si_github_app_installations(installation_id,tenant_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT jas_si_github_repo_status_verification
        CHECK ((status='active' AND verified_at IS NOT NULL)
            OR (status IN ('pending','revoked')))
);
CREATE UNIQUE INDEX IF NOT EXISTS jas_si_github_repo_tenant_name_unique
    ON public.jas_si_github_app_installation_repositories
       (tenant_id,pg_catalog.lower(repository_full_name));

REVOKE ALL PRIVILEGES ON TABLE
    public.jas_si_github_app_installations,
    public.jas_si_github_app_installation_repositories
    FROM PUBLIC,jas_si_runtime,jas_si_provisioner,
         jas_si_agent_worker,jas_si_agent_verifier,
         jas_si_agent_worker_login,jas_si_agent_verifier_login;

ALTER TABLE public.jas_si_github_app_installations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.jas_si_github_app_installations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS jas_si_github_installation_owner_all
    ON public.jas_si_github_app_installations;
CREATE POLICY jas_si_github_installation_owner_all
    ON public.jas_si_github_app_installations
    FOR ALL TO jas_si_agent_task_owner USING (true) WITH CHECK (true);

ALTER TABLE public.jas_si_github_app_installation_repositories ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.jas_si_github_app_installation_repositories FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS jas_si_github_repository_owner_all
    ON public.jas_si_github_app_installation_repositories;
CREATE POLICY jas_si_github_repository_owner_all
    ON public.jas_si_github_app_installation_repositories
    FOR ALL TO jas_si_agent_task_owner USING (true) WITH CHECK (true);

CREATE OR REPLACE FUNCTION public.jas_si_github_installation_binding_resolve(
    p_tenant_id uuid,
    p_repository_full_name text
) RETURNS TABLE(
    tenant_id uuid,
    installation_id bigint,
    repository_full_name text
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
BEGIN
    IF NOT (
        pg_catalog.pg_has_role(session_user,'jas_si_agent_worker','MEMBER')
        OR pg_catalog.pg_has_role(session_user,'jas_si_agent_verifier','MEMBER')
    ) THEN
        RAISE EXCEPTION 'Agent host identity is not authorized' USING ERRCODE='42501';
    END IF;
    IF p_tenant_id IS NULL OR p_repository_full_name IS NULL
       OR length(p_repository_full_name)>140
       OR p_repository_full_name !~ '^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}$' THEN
        RAISE EXCEPTION 'Invalid tenant GitHub repository binding request' USING ERRCODE='22023';
    END IF;

    RETURN QUERY
    SELECT i.tenant_id,i.installation_id,r.repository_full_name::text
      FROM public.jas_si_github_app_installations i
      JOIN public.jas_si_github_app_installation_repositories r
        ON r.installation_id=i.installation_id AND r.tenant_id=i.tenant_id
      JOIN public.jas_si_tenants t ON t.tenant_id=i.tenant_id
     WHERE i.tenant_id=p_tenant_id
       AND pg_catalog.lower(r.repository_full_name)=pg_catalog.lower(p_repository_full_name)
       AND i.status='active' AND i.verified_at IS NOT NULL
       AND r.status='active' AND r.verified_at IS NOT NULL
       AND t.status='active'
     LIMIT 1;
END;
$function$;

REVOKE ALL ON FUNCTION public.jas_si_github_installation_binding_resolve(uuid,text)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.jas_si_github_installation_binding_resolve(uuid,text)
    TO jas_si_agent_worker,jas_si_agent_verifier;

RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_agent_task_owner;

DO $assert$
DECLARE v_proc oid; v_owner text;
BEGIN
    SELECT p.oid,pg_catalog.pg_get_userbyid(p.proowner)
      INTO v_proc,v_owner
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
     WHERE n.nspname='public'
       AND p.proname='jas_si_github_installation_binding_resolve'
       AND pg_catalog.pg_get_function_identity_arguments(p.oid)='p_tenant_id uuid, p_repository_full_name text';
    IF v_proc IS NULL OR v_owner<>'jas_si_agent_task_owner'
       OR NOT (SELECT p.prosecdef FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
       OR NOT (SELECT COALESCE(p.proconfig,ARRAY[]::text[]) @> ARRAY['search_path=pg_catalog']
                 FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
       OR NOT pg_catalog.has_function_privilege('jas_si_agent_worker',v_proc,'EXECUTE')
       OR NOT pg_catalog.has_function_privilege('jas_si_agent_verifier',v_proc,'EXECUTE')
       OR EXISTS (
           SELECT 1 FROM pg_catalog.aclexplode(
               COALESCE((SELECT p.proacl FROM pg_catalog.pg_proc p WHERE p.oid=v_proc),
                        pg_catalog.acldefault('f',(SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)))
           ) acl WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'
       )
       OR pg_catalog.has_table_privilege('jas_si_agent_worker','public.jas_si_github_app_installations','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_agent_verifier','public.jas_si_github_app_installations','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_agent_worker','public.jas_si_github_app_installation_repositories','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_agent_verifier','public.jas_si_github_app_installation_repositories','SELECT') THEN
        RAISE EXCEPTION 'Tenant GitHub installation binding security boundary is invalid';
    END IF;
END
$assert$;
