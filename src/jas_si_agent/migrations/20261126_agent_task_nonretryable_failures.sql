-- Deterministic authorization, simulation, and handler-contract failures
-- are terminal. Retrying them cannot improve the outcome and can repeatedly
-- consume worker/database resources. Transient handler errors remain retryable.
--
-- Preserve the existing SECURITY DEFINER owner, fixed search_path, signature,
-- and worker-only EXECUTE grant while tightening the database-owned transition.

GRANT CREATE ON SCHEMA public TO jas_si_agent_task_owner;
SET LOCAL ROLE jas_si_agent_task_owner;

CREATE OR REPLACE FUNCTION public.jas_si_agent_task_fail(
    p_worker_id uuid,p_task_id uuid,p_lease_fence bigint,
    p_error_code text,p_retry_delay_seconds integer DEFAULT 0
) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE v_status text;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_agent_worker','MEMBER') THEN
        RAISE EXCEPTION 'Worker identity is not authorized' USING ERRCODE='42501';
    END IF;
    IF p_worker_id IS NULL OR p_task_id IS NULL OR p_lease_fence IS NULL
       OR p_error_code IS NULL OR p_error_code !~ '^[A-Z0-9_]{1,64}$'
       OR p_retry_delay_seconds IS NULL OR p_retry_delay_seconds NOT BETWEEN 0 AND 3600 THEN
        RAISE EXCEPTION 'Invalid worker failure report' USING ERRCODE='22023';
    END IF;

    -- A cancellation request takes precedence. Otherwise, deterministic
    -- security/configuration/contract failures are terminal; only potentially
    -- transient failures may be requeued while the attempt budget remains.
    UPDATE public.jas_si_agent_tasks q
       SET status=CASE
           WHEN q.status='cancel_requested' THEN 'cancelled'
           WHEN p_error_code = ANY (ARRAY[
               'ACTION_NOT_AUTHORIZED',
               'SIMULATION_REQUIRED',
               'SIMULATION_INVALID',
               'SIMULATION_REJECTED',
               'INVALID_HANDLER_RESULT',
               'RESERVED_RESULT_FIELD_COLLISION',
               'UNSUPPORTED_TASK_TYPE'
           ]::text[]) THEN 'failed'
           WHEN q.attempt_count<q.max_attempts THEN 'queued'
           ELSE 'failed'
       END,
           next_attempt_at=pg_catalog.clock_timestamp()
               + pg_catalog.make_interval(secs=>p_retry_delay_seconds),
           lease_owner=NULL,lease_expires_at=NULL,
           error_code=CASE WHEN q.status='cancel_requested'
                           THEN 'CANCELLED_AFTER_WORKER_ERROR'
                           ELSE p_error_code END,
           updated_at=pg_catalog.clock_timestamp(),
           completed_at=CASE
               WHEN q.status='cancel_requested'
                 OR p_error_code = ANY (ARRAY[
                     'ACTION_NOT_AUTHORIZED',
                     'SIMULATION_REQUIRED',
                     'SIMULATION_INVALID',
                     'SIMULATION_REJECTED',
                     'INVALID_HANDLER_RESULT',
                     'RESERVED_RESULT_FIELD_COLLISION',
                     'UNSUPPORTED_TASK_TYPE'
                 ]::text[])
                 OR q.attempt_count>=q.max_attempts
               THEN pg_catalog.clock_timestamp()
               ELSE NULL
           END
     WHERE q.task_id=p_task_id AND q.lease_owner=p_worker_id::text
       AND q.lease_fence=p_lease_fence
       AND q.status IN ('running','cancel_requested')
       AND q.lease_expires_at>pg_catalog.clock_timestamp()
    RETURNING q.status::text INTO v_status;
    RETURN v_status;
END;
$function$;

RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_agent_task_owner;

DO $block$
DECLARE v_proc oid; v_owner text; v_acl_ok boolean; v_config_ok boolean;
BEGIN
    v_proc := 'public.jas_si_agent_task_fail(uuid,uuid,bigint,text,integer)'::regprocedure;
    SELECT pg_catalog.pg_get_userbyid(p.proowner),
           p.prosecdef,
           COALESCE(p.proconfig,ARRAY[]::text[]) @> ARRAY['search_path=pg_catalog']::text[],
           NOT EXISTS (
               SELECT 1 FROM pg_catalog.aclexplode(
                   COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))
               ) acl
               WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'
           )
      INTO v_owner,v_config_ok,v_acl_ok,v_proc
      FROM pg_catalog.pg_proc p WHERE p.oid=v_proc;
    IF v_owner<>'jas_si_agent_task_owner'
       OR NOT v_config_ok OR NOT v_acl_ok
       OR NOT pg_catalog.has_function_privilege(
           'jas_si_agent_worker',
           'public.jas_si_agent_task_fail(uuid,uuid,bigint,text,integer)',
           'EXECUTE'
       ) THEN
        RAISE EXCEPTION 'Agent task failure routine security boundary invalid';
    END IF;
END
$block$;
