-- Task-scoped DB authorization for the isolated GitHub Capability Broker.
-- Broker TLS/certificate authentication occurs in the service; this routine
-- independently fences that authenticated principal against persisted task state.
-- This migration does not create LOGIN roles, credentials, services, or tokens.

DO $roles$
DECLARE v_role pg_catalog.pg_roles%ROWTYPE;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_agent_capability_broker') THEN
        CREATE ROLE jas_si_agent_capability_broker
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOREPLICATION NOBYPASSRLS NOINHERIT;
    END IF;
    SELECT * INTO v_role FROM pg_catalog.pg_roles
     WHERE rolname='jas_si_agent_capability_broker';
    IF v_role.rolcanlogin OR v_role.rolsuper OR v_role.rolcreatedb
       OR v_role.rolcreaterole OR v_role.rolreplication
       OR v_role.rolbypassrls OR v_role.rolinherit THEN
        RAISE EXCEPTION 'Unsafe JAS-SI capability broker role';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_auth_members m
        JOIN pg_catalog.pg_roles login_role ON login_role.oid=m.member
        JOIN pg_catalog.pg_roles grantor_role ON grantor_role.oid=m.grantor
        WHERE m.roleid=v_role.oid
          AND NOT (
              (login_role.rolname LIKE 'jas_si_agent_broker_login%'
               AND login_role.rolcanlogin AND NOT login_role.rolinherit
               AND NOT login_role.rolsuper AND NOT login_role.rolcreatedb
               AND NOT login_role.rolcreaterole AND NOT login_role.rolreplication
               AND NOT login_role.rolbypassrls
               AND NOT m.inherit_option AND m.set_option AND NOT m.admin_option)
              OR
              (login_role.rolname='neondb_owner'
               AND grantor_role.rolsuper
               AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option)
          )
    ) OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=v_role.oid
    ) THEN
        RAISE EXCEPTION 'Broker capability membership is not a dedicated SET-only login boundary';
    END IF;
    IF pg_catalog.to_regclass('public.jas_si_agent_tasks') IS NULL
       OR pg_catalog.to_regclass('public.jas_si_github_app_installations') IS NULL
       OR pg_catalog.to_regclass('public.jas_si_github_app_installation_repositories') IS NULL
       OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_agent_task_owner')
       OR pg_catalog.to_regprocedure('public.jas_si_github_installation_binding_resolve(uuid,text)') IS NULL THEN
        RAISE EXCEPTION 'Task and verified GitHub binding migrations must precede Broker authorization';
    END IF;
END
$roles$;

GRANT USAGE ON SCHEMA public TO jas_si_agent_capability_broker;
-- The task-owner SECURITY DEFINER lookup joins active tenant state under FORCE RLS.
GRANT SELECT ON public.jas_si_tenants TO jas_si_agent_task_owner;
GRANT CREATE ON SCHEMA public TO jas_si_agent_task_owner;
SET LOCAL ROLE jas_si_agent_task_owner;

-- Existing resolver was callable by the hosts and is not lease/claim scoped.
-- Revoke it from both workload roles; only the Broker may use it directly.
REVOKE ALL ON FUNCTION public.jas_si_github_installation_binding_resolve(uuid,text)
    FROM PUBLIC,jas_si_agent_worker,jas_si_agent_verifier;
-- Broker uses the stricter task-scoped resolver below; do not grant it the
-- legacy unscoped installation lookup routine.

CREATE OR REPLACE FUNCTION public.jas_si_github_task_capability_resolve(
    p_task_id uuid,
    p_workload_principal name,
    p_workload_role text,
    p_lease_fence bigint DEFAULT NULL,
    p_verifier_claim_token uuid DEFAULT NULL
) RETURNS TABLE(
    task_id uuid,
    tenant_id uuid,
    installation_id bigint,
    repository_full_name text,
    capability_role text,
    lease_fence bigint,
    verifier_claim_token uuid,
    expires_at timestamptz,
    commit_sha text,
    repository_paths jsonb
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog
AS $function$
DECLARE v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_agent_capability_broker','MEMBER') THEN
        RAISE EXCEPTION 'Capability Broker database identity is not authorized'
            USING ERRCODE='42501';
    END IF;
    IF p_task_id IS NULL OR p_workload_principal IS NULL
       OR p_workload_role IS NULL
       OR p_workload_role NOT IN ('worker','verifier')
       OR (p_workload_role='worker' AND (p_lease_fence IS NULL OR p_verifier_claim_token IS NOT NULL))
       OR (p_workload_role='verifier' AND (p_verifier_claim_token IS NULL OR p_lease_fence IS NOT NULL)) THEN
        RAISE EXCEPTION 'Invalid capability lookup request' USING ERRCODE='22023';
    END IF;

    RETURN QUERY
    SELECT q.task_id,q.tenant_id,i.installation_id,r.repository_full_name::text,
           p_workload_role,
           CASE WHEN p_workload_role='worker' THEN q.lease_fence ELSE NULL::bigint END,
           CASE WHEN p_workload_role='verifier' THEN q.verifier_claim_token ELSE NULL::uuid END,
           CASE WHEN p_workload_role='worker' THEN q.lease_expires_at ELSE q.verifier_lease_expires_at END,
           q.input_payload->>'commit_sha',
           q.input_payload->'paths'
      FROM public.jas_si_agent_tasks q
      JOIN public.jas_si_tenants t ON t.tenant_id=q.tenant_id
      JOIN public.jas_si_github_app_installations i ON i.tenant_id=q.tenant_id
      JOIN public.jas_si_github_app_installation_repositories r
        ON r.tenant_id=i.tenant_id AND r.installation_id=i.installation_id
     WHERE q.task_id=p_task_id
       AND q.task_type='github.read_repository'
       AND q.input_payload->>'commit_sha' ~ '^[0-9a-f]{40}$'
       AND CASE
             WHEN pg_catalog.jsonb_typeof(q.input_payload->'paths') <> 'array' THEN false
             ELSE pg_catalog.jsonb_array_length(q.input_payload->'paths') BETWEEN 1 AND 10
               AND NOT EXISTS (
                   SELECT 1
                     FROM pg_catalog.jsonb_array_elements(q.input_payload->'paths') AS path_item(value)
                    WHERE pg_catalog.jsonb_typeof(path_item.value) <> 'string'
                       OR pg_catalog.length(path_item.value #>> '{}') NOT BETWEEN 1 AND 512
                       OR (path_item.value #>> '{}') ~ '(^/|(^|/)\\.\\.?(/|$)|[[:cntrl:]])'
                       OR pg_catalog.position(pg_catalog.chr(92) IN (path_item.value #>> '{}')) > 0
               )
           END
       AND t.status='active'
       AND i.status='active' AND i.verified_at IS NOT NULL
       AND r.status='active' AND r.verified_at IS NOT NULL
       AND pg_catalog.lower(r.repository_full_name)
           =pg_catalog.lower(q.input_payload->>'repository')
       AND (
          (p_workload_role='worker'
           AND q.status='running'
           AND q.lease_owner_principal=p_workload_principal
           AND q.lease_expires_at>v_now
           AND q.lease_fence=p_lease_fence)
          OR
          (p_workload_role='verifier'
           AND q.status='awaiting_verification'
           AND q.verifier_claim_owner=p_workload_principal
           AND q.verifier_claim_token=p_verifier_claim_token
           AND q.verifier_lease_expires_at>v_now)
       )
     LIMIT 1;
END;
$function$;

REVOKE ALL ON FUNCTION public.jas_si_github_task_capability_resolve(uuid,name,text,bigint,uuid)
    FROM PUBLIC,jas_si_agent_worker,jas_si_agent_verifier;
GRANT EXECUTE ON FUNCTION public.jas_si_github_task_capability_resolve(uuid,name,text,bigint,uuid)
    TO jas_si_agent_capability_broker;

RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_agent_task_owner;

DO $assert$
DECLARE v_proc oid; v_owner text; v_binding oid;
BEGIN
    SELECT p.oid,pg_catalog.pg_get_userbyid(p.proowner)
      INTO v_proc,v_owner FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
     WHERE n.nspname='public'
       AND p.proname='jas_si_github_task_capability_resolve'
       AND p.oid='public.jas_si_github_task_capability_resolve(uuid,name,text,bigint,uuid)'::regprocedure;
    v_binding := 'public.jas_si_github_installation_binding_resolve(uuid,text)'::regprocedure;
    IF v_proc IS NULL OR v_owner<>'jas_si_agent_task_owner'
       OR NOT (SELECT prosecdef FROM pg_catalog.pg_proc WHERE oid=v_proc)
       OR NOT (SELECT COALESCE(proconfig,ARRAY[]::text[]) @> ARRAY['search_path=pg_catalog']
                 FROM pg_catalog.pg_proc WHERE oid=v_proc)
       OR NOT pg_catalog.has_function_privilege('jas_si_agent_capability_broker',v_proc,'EXECUTE')
       OR pg_catalog.has_function_privilege('jas_si_agent_worker',v_proc,'EXECUTE')
       OR pg_catalog.has_function_privilege('jas_si_agent_verifier',v_proc,'EXECUTE')
       OR pg_catalog.has_function_privilege('jas_si_agent_worker',v_binding,'EXECUTE')
       OR pg_catalog.has_function_privilege('jas_si_agent_verifier',v_binding,'EXECUTE')
       OR pg_catalog.has_function_privilege('jas_si_agent_capability_broker',v_binding,'EXECUTE')
       OR EXISTS (SELECT 1 FROM pg_catalog.aclexplode(
          COALESCE((SELECT proacl FROM pg_catalog.pg_proc WHERE oid=v_proc),
                   pg_catalog.acldefault('f',(SELECT proowner FROM pg_catalog.pg_proc WHERE oid=v_proc)))
          ) acl WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE') THEN
        RAISE EXCEPTION 'Broker task-scoped authorization routine ACL/owner boundary invalid';
    END IF;
END
$assert$;
