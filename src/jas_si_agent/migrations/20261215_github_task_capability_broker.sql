-- Task-scoped database capability lookup for the isolated GitHub Broker.
-- Broker authenticates workload certificates before calling this routine.
-- The DB confirms the dedicated Broker login and the persisted lease/claim;
-- task, tenant and repository fields supplied by the caller are never authority.

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
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members
                WHERE member=v_role.oid OR roleid=v_role.oid) THEN
        RAISE EXCEPTION 'Broker role must have no role memberships; provision a dedicated broker login separately';
    END IF;
    IF pg_catalog.to_regclass('public.jas_si_agent_tasks') IS NULL
       OR pg_catalog.to_regclass('public.jas_si_github_app_installations') IS NULL
       OR pg_catalog.to_regclass('public.jas_si_github_app_installation_repositories') IS NULL
       OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_agent_task_owner') THEN
        RAISE EXCEPTION 'Task and verified GitHub binding migrations must precede broker authorization';
    END IF;
END
$roles$;

GRANT USAGE ON SCHEMA public TO jas_si_agent_capability_broker;
GRANT CREATE ON SCHEMA public TO jas_si_agent_task_owner;
SET LOCAL ROLE jas_si_agent_task_owner;

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
    fence bigint,
    expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_agent_capability_broker','MEMBER') THEN
        RAISE EXCEPTION 'Capability Broker database identity is not authorized'
            USING ERRCODE='42501';
    END IF;
    IF p_task_id IS NULL OR p_workload_principal IS NULL
       OR p_workload_role NOT IN ('worker','verifier')
       OR (p_workload_role='worker' AND (p_lease_fence IS NULL OR p_verifier_claim_token IS NOT NULL))
       OR (p_workload_role='verifier' AND (p_verifier_claim_token IS NULL OR p_lease_fence IS NOT NULL)) THEN
        RAISE EXCEPTION 'Invalid capability lookup request' USING ERRCODE='22023';
    END IF;

    RETURN QUERY
    SELECT q.task_id,q.tenant_id,i.installation_id,r.repository_full_name::text,
           p_workload_role,
           CASE WHEN p_workload_role='worker' THEN q.lease_fence ELSE q.verifier_attempt_count::bigint END,
           CASE WHEN p_workload_role='worker' THEN q.lease_expires_at ELSE q.verifier_lease_expires_at END
      FROM public.jas_si_agent_tasks q
      JOIN public.jas_si_tenants t ON t.tenant_id=q.tenant_id
      JOIN public.jas_si_github_app_installations i ON i.tenant_id=q.tenant_id
      JOIN public.jas_si_github_app_installation_repositories r
        ON r.tenant_id=i.tenant_id AND r.installation_id=i.installation_id
     WHERE q.task_id=p_task_id
       AND q.task_type='github.read_repository'
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
DECLARE v_proc oid; v_owner text;
BEGIN
    SELECT p.oid,pg_catalog.pg_get_userbyid(p.proowner)
      INTO v_proc,v_owner FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
     WHERE n.nspname='public'
       AND p.proname='jas_si_github_task_capability_resolve'
       AND p.oid='public.jas_si_github_task_capability_resolve(uuid,name,text,bigint,uuid)'::regprocedure;
    IF v_proc IS NULL OR v_owner<>'jas_si_agent_task_owner'
       OR NOT (SELECT prosecdef FROM pg_catalog.pg_proc WHERE oid=v_proc)
       OR NOT (SELECT COALESCE(proconfig,ARRAY[]::text[]) @> ARRAY['search_path=pg_catalog']
                 FROM pg_catalog.pg_proc WHERE oid=v_proc)
       OR NOT pg_catalog.has_function_privilege('jas_si_agent_capability_broker',v_proc,'EXECUTE')
       OR pg_catalog.has_function_privilege('jas_si_agent_worker',v_proc,'EXECUTE')
       OR pg_catalog.has_function_privilege('jas_si_agent_verifier',v_proc,'EXECUTE')
       OR EXISTS (SELECT 1 FROM pg_catalog.aclexplode(
          COALESCE((SELECT proacl FROM pg_catalog.pg_proc WHERE oid=v_proc),
                   pg_catalog.acldefault('f',(SELECT proowner FROM pg_catalog.pg_proc WHERE oid=v_proc)))
          ) acl WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE') THEN
        RAISE EXCEPTION 'Broker task-scoped authorization routine ACL/owner boundary invalid';
    END IF;
END
$assert$;
