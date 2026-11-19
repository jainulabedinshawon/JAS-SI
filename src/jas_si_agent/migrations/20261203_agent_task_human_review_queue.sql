-- Tenant-scoped read-only Human Review queue and audit history.
-- All reads cross SECURITY DEFINER routines; runtime has no direct task/audit table access.

GRANT CREATE ON SCHEMA public TO jas_si_agent_task_owner;
SET LOCAL ROLE jas_si_agent_task_owner;

CREATE OR REPLACE FUNCTION public.jas_si_agent_task_human_review_queue(
    p_tenant_id uuid,
    p_limit integer DEFAULT 50
) RETURNS TABLE(
    task_id uuid,
    task_type text,
    task_status text,
    verification_status text,
    verification_reason_code text,
    verifier_attempt_count integer,
    created_at timestamptz,
    updated_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog
AS $function$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_runtime','MEMBER') THEN
        RAISE EXCEPTION 'Customer review runtime identity is not authorized'
            USING ERRCODE='42501';
    END IF;
    IF p_tenant_id IS NULL OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 THEN
        RAISE EXCEPTION 'Invalid human review queue request'
            USING ERRCODE='22023';
    END IF;

    RETURN QUERY
    SELECT q.task_id,q.task_type::text,q.status::text,
           q.verifier_last_status::text,q.verifier_last_reason::text,
           q.verifier_attempt_count,q.created_at,q.updated_at
      FROM public.jas_si_agent_tasks q
     WHERE q.tenant_id=p_tenant_id
       AND q.status='human_review_required'
     ORDER BY q.updated_at,q.task_id
     LIMIT p_limit;
END;
$function$;

CREATE OR REPLACE FUNCTION public.jas_si_agent_task_human_review_history(
    p_tenant_id uuid,
    p_task_id uuid,
    p_limit integer DEFAULT 50
) RETURNS TABLE(
    task_exists boolean,
    decision_event_id uuid,
    decision text,
    reason_code text,
    previous_status text,
    resulting_status text,
    decided_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog
AS $function$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_runtime','MEMBER') THEN
        RAISE EXCEPTION 'Customer review runtime identity is not authorized'
            USING ERRCODE='42501';
    END IF;
    IF p_tenant_id IS NULL OR p_task_id IS NULL
       OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 THEN
        RAISE EXCEPTION 'Invalid human review history request'
            USING ERRCODE='22023';
    END IF;

    RETURN QUERY
    SELECT true,e.decision_event_id,e.decision::text,e.reason_code::text,
           e.previous_status::text,e.resulting_status::text,e.decided_at
      FROM public.jas_si_agent_tasks q
      LEFT JOIN LATERAL (
          SELECT event.decision_event_id,event.decision,event.reason_code,
                 event.previous_status,event.resulting_status,event.decided_at
            FROM public.jas_si_agent_task_review_events event
           WHERE event.task_id=q.task_id AND event.tenant_id=q.tenant_id
           ORDER BY event.decided_at DESC,event.decision_event_id DESC
           LIMIT p_limit
      ) e ON true
     WHERE q.task_id=p_task_id AND q.tenant_id=p_tenant_id
     ORDER BY e.decided_at DESC NULLS LAST,e.decision_event_id DESC NULLS LAST;
END;
$function$;

REVOKE ALL ON FUNCTION public.jas_si_agent_task_human_review_queue(uuid,integer)
    FROM PUBLIC;
REVOKE ALL ON FUNCTION public.jas_si_agent_task_human_review_history(uuid,uuid,integer)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.jas_si_agent_task_human_review_queue(uuid,integer)
    TO jas_si_runtime;
GRANT EXECUTE ON FUNCTION public.jas_si_agent_task_human_review_history(uuid,uuid,integer)
    TO jas_si_runtime;

RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_agent_task_owner;

DO $block$
DECLARE v_proc oid; v_owner text;
BEGIN
    FOREACH v_proc IN ARRAY ARRAY[
        'public.jas_si_agent_task_human_review_queue(uuid,integer)'::regprocedure::oid,
        'public.jas_si_agent_task_human_review_history(uuid,uuid,integer)'::regprocedure::oid
    ] LOOP
        SELECT pg_catalog.pg_get_userbyid(p.proowner) INTO v_owner
          FROM pg_catalog.pg_proc p WHERE p.oid=v_proc;
        IF v_owner<>'jas_si_agent_task_owner'
           OR NOT (SELECT p.prosecdef FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
           OR NOT (SELECT COALESCE(p.proconfig,ARRAY[]::text[])
                      @> ARRAY['search_path=pg_catalog']::text[]
                     FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
           OR NOT pg_catalog.has_function_privilege('jas_si_runtime',v_proc,'EXECUTE')
           OR EXISTS (
               SELECT 1 FROM pg_catalog.aclexplode(
                   COALESCE((SELECT p.proacl FROM pg_catalog.pg_proc p WHERE p.oid=v_proc),
                            pg_catalog.acldefault('f',(SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)))
               ) acl WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'
           ) THEN
            RAISE EXCEPTION 'Human review read routine security boundary invalid';
        END IF;
    END LOOP;
END
$block$;
