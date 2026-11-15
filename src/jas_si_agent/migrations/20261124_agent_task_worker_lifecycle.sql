-- Add database-owned worker lifecycle primitives to the durable task store.
-- This migration enables claiming and lease management only. It deliberately
-- does not execute tools or mark a task successful: reports enter
-- awaiting_verification until an independent trusted verifier is integrated.

DO $block$
DECLARE
    v_role oid;
BEGIN
    SELECT oid INTO v_role FROM pg_catalog.pg_roles
     WHERE rolname='jas_si_agent_worker';
    IF v_role IS NULL THEN
        CREATE ROLE jas_si_agent_worker
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOREPLICATION NOBYPASSRLS NOINHERIT;
        SELECT oid INTO v_role FROM pg_catalog.pg_roles
         WHERE rolname='jas_si_agent_worker';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles r
         WHERE r.oid=v_role AND (
             r.rolcanlogin OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole
             OR r.rolreplication OR r.rolbypassrls OR r.rolinherit
         )
    ) OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_auth_members m
         WHERE m.member=v_role
    ) THEN
        RAISE EXCEPTION 'Unsafe JAS-SI worker capability role';
    END IF;
    IF pg_catalog.to_regclass('public.jas_si_agent_tasks') IS NULL
       OR NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_agent_task_owner'
       ) THEN
        RAISE EXCEPTION 'Durable agent task store migration is required first';
    END IF;
END
$block$;

ALTER TABLE public.jas_si_agent_tasks
    ADD COLUMN IF NOT EXISTS lease_fence bigint NOT NULL DEFAULT 0;
ALTER TABLE public.jas_si_agent_tasks
    ADD COLUMN IF NOT EXISTS reported_at timestamptz;

ALTER TABLE public.jas_si_agent_tasks
    DROP CONSTRAINT IF EXISTS jas_si_agent_task_status_check;
ALTER TABLE public.jas_si_agent_tasks
    ADD CONSTRAINT jas_si_agent_task_status_check
    CHECK (status IN (
        'queued','running','cancel_requested','awaiting_verification',
        'succeeded','failed','cancelled'
    ));

ALTER TABLE public.jas_si_agent_tasks
    DROP CONSTRAINT IF EXISTS jas_si_agent_task_completion_consistency;
ALTER TABLE public.jas_si_agent_tasks
    ADD CONSTRAINT jas_si_agent_task_completion_consistency
    CHECK (
        (status IN ('succeeded','failed','cancelled') AND completed_at IS NOT NULL)
        OR
        (status IN ('queued','running','cancel_requested','awaiting_verification')
         AND completed_at IS NULL)
    );

ALTER TABLE public.jas_si_agent_tasks
    DROP CONSTRAINT IF EXISTS jas_si_agent_task_fence_nonnegative;
ALTER TABLE public.jas_si_agent_tasks
    ADD CONSTRAINT jas_si_agent_task_fence_nonnegative
    CHECK (lease_fence >= 0);

GRANT USAGE ON SCHEMA public TO jas_si_agent_worker;
GRANT CREATE ON SCHEMA public TO jas_si_agent_task_owner;
SET LOCAL ROLE jas_si_agent_task_owner;

CREATE OR REPLACE FUNCTION public.jas_si_agent_task_claim(
    p_worker_id uuid,
    p_lease_seconds integer DEFAULT 60
) RETURNS TABLE(
    task_id uuid,task_type text,input_payload jsonb,attempt_count integer,
    max_attempts integer,lease_fence bigint,lease_expires_at timestamptz
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_agent_worker','MEMBER') THEN
        RAISE EXCEPTION 'Worker identity is not authorized' USING ERRCODE='42501';
    END IF;
    IF p_worker_id IS NULL OR p_lease_seconds IS NULL OR p_lease_seconds NOT BETWEEN 15 AND 300 THEN
        RAISE EXCEPTION 'Invalid worker claim request' USING ERRCODE='22023';
    END IF;

    -- Expired work is made eligible for retry, or terminally failed when
    -- its attempt budget is exhausted. A lost cancellation acknowledgement
    -- is never misreported as a confirmed cancellation.
    UPDATE public.jas_si_agent_tasks q
       SET status=CASE WHEN q.status='cancel_requested' THEN 'failed'
                       WHEN q.attempt_count < q.max_attempts
                       THEN 'queued' ELSE 'failed' END,
           lease_owner=NULL,
           lease_expires_at=NULL,
           next_attempt_at=v_now,
           error_code=CASE
               WHEN q.status='cancel_requested'
                   THEN 'WORKER_LOST_DURING_CANCELLATION'
               WHEN q.attempt_count < q.max_attempts
                   THEN 'WORKER_LEASE_EXPIRED_RETRY'
               ELSE 'WORKER_LEASE_EXPIRED_MAX_ATTEMPTS'
           END,
           updated_at=v_now,
           completed_at=CASE WHEN q.status='cancel_requested'
                                      OR q.attempt_count >= q.max_attempts
                             THEN v_now ELSE NULL END
     WHERE q.status IN ('running','cancel_requested')
       AND q.lease_expires_at <= v_now;

    RETURN QUERY
    WITH candidate AS (
        SELECT q.task_id
          FROM public.jas_si_agent_tasks q
         WHERE q.status='queued'
           AND q.next_attempt_at <= v_now
           AND q.attempt_count < q.max_attempts
         ORDER BY q.next_attempt_at,q.created_at,q.task_id
         FOR UPDATE SKIP LOCKED
         LIMIT 1
    )
    UPDATE public.jas_si_agent_tasks q
       SET status='running',
           attempt_count=q.attempt_count+1,
           lease_owner=p_worker_id::text,
           lease_expires_at=v_now+pg_catalog.make_interval(secs=>p_lease_seconds),
           lease_fence=q.lease_fence+1,
           updated_at=v_now,
           error_code=NULL
      FROM candidate c
     WHERE q.task_id=c.task_id
    RETURNING q.task_id,q.task_type::text,q.input_payload,q.attempt_count,
              q.max_attempts,q.lease_fence,q.lease_expires_at;
END;
$function$;

CREATE OR REPLACE FUNCTION public.jas_si_agent_task_renew(
    p_worker_id uuid,p_task_id uuid,p_lease_fence bigint,
    p_lease_seconds integer DEFAULT 60
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE v_updated integer;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_agent_worker','MEMBER') THEN
        RAISE EXCEPTION 'Worker identity is not authorized' USING ERRCODE='42501';
    END IF;
    IF p_worker_id IS NULL OR p_task_id IS NULL OR p_lease_fence IS NULL
       OR p_lease_seconds IS NULL OR p_lease_seconds NOT BETWEEN 15 AND 300 THEN
        RAISE EXCEPTION 'Invalid worker lease renewal' USING ERRCODE='22023';
    END IF;
    UPDATE public.jas_si_agent_tasks q
       SET lease_expires_at=pg_catalog.clock_timestamp()
              + pg_catalog.make_interval(secs=>p_lease_seconds),
           updated_at=pg_catalog.clock_timestamp()
     WHERE q.task_id=p_task_id
       AND q.lease_owner=p_worker_id::text
       AND q.lease_fence=p_lease_fence
       AND q.status IN ('running','cancel_requested')
       AND q.lease_expires_at>pg_catalog.clock_timestamp();
    GET DIAGNOSTICS v_updated=ROW_COUNT;
    RETURN v_updated=1;
END;
$function$;

CREATE OR REPLACE FUNCTION public.jas_si_agent_task_ack_cancel(
    p_worker_id uuid,p_task_id uuid,p_lease_fence bigint
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE v_updated integer;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_agent_worker','MEMBER') THEN
        RAISE EXCEPTION 'Worker identity is not authorized' USING ERRCODE='42501';
    END IF;
    IF p_worker_id IS NULL OR p_task_id IS NULL OR p_lease_fence IS NULL THEN
        RAISE EXCEPTION 'Invalid cancellation acknowledgement' USING ERRCODE='22023';
    END IF;
    UPDATE public.jas_si_agent_tasks q
       SET status='cancelled',lease_owner=NULL,lease_expires_at=NULL,
           error_code='CANCELLED_BY_WORKER',updated_at=pg_catalog.clock_timestamp(),
           completed_at=pg_catalog.clock_timestamp()
     WHERE q.task_id=p_task_id AND q.lease_owner=p_worker_id::text
       AND q.lease_fence=p_lease_fence AND q.status='cancel_requested'
       AND q.lease_expires_at>pg_catalog.clock_timestamp();
    GET DIAGNOSTICS v_updated=ROW_COUNT;
    RETURN v_updated=1;
END;
$function$;

CREATE OR REPLACE FUNCTION public.jas_si_agent_task_report(
    p_worker_id uuid,p_task_id uuid,p_lease_fence bigint,p_result_payload jsonb
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE v_updated integer;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_agent_worker','MEMBER') THEN
        RAISE EXCEPTION 'Worker identity is not authorized' USING ERRCODE='42501';
    END IF;
    IF p_worker_id IS NULL OR p_task_id IS NULL OR p_lease_fence IS NULL
       OR p_result_payload IS NULL OR pg_catalog.jsonb_typeof(p_result_payload)<>'object'
       OR pg_catalog.octet_length(p_result_payload::text)>65536 THEN
        RAISE EXCEPTION 'Invalid worker task report' USING ERRCODE='22023';
    END IF;
    UPDATE public.jas_si_agent_tasks q
       SET status='awaiting_verification',result_payload=p_result_payload,
           reported_at=pg_catalog.clock_timestamp(),lease_owner=NULL,
           lease_expires_at=NULL,error_code=NULL,
           updated_at=pg_catalog.clock_timestamp(),completed_at=NULL
     WHERE q.task_id=p_task_id AND q.lease_owner=p_worker_id::text
       AND q.lease_fence=p_lease_fence AND q.status IN ('running','cancel_requested')
       AND q.lease_expires_at>pg_catalog.clock_timestamp();
    GET DIAGNOSTICS v_updated=ROW_COUNT;
    RETURN v_updated=1;
END;
$function$;

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
    -- A worker error is not proof that cancellation completed. If the
    -- tenant requested cancellation, stop retries but record a truthful
    -- terminal failure unless the worker used the explicit ack_cancel path.
    UPDATE public.jas_si_agent_tasks q
       SET status=CASE WHEN q.status='cancel_requested' THEN 'failed'
                       WHEN q.attempt_count<q.max_attempts
                       THEN 'queued' ELSE 'failed' END,
           next_attempt_at=pg_catalog.clock_timestamp()
               + pg_catalog.make_interval(secs=>p_retry_delay_seconds),
           lease_owner=NULL,lease_expires_at=NULL,
           error_code=CASE WHEN q.status='cancel_requested'
                           THEN 'WORKER_FAILED_AFTER_CANCEL_REQUEST'
                           ELSE p_error_code END,
           updated_at=pg_catalog.clock_timestamp(),
           completed_at=CASE WHEN q.status='cancel_requested'
                                  OR q.attempt_count>=q.max_attempts
                             THEN pg_catalog.clock_timestamp() ELSE NULL END
     WHERE q.task_id=p_task_id AND q.lease_owner=p_worker_id::text
       AND q.lease_fence=p_lease_fence AND q.status IN ('running','cancel_requested')
       AND q.lease_expires_at>pg_catalog.clock_timestamp()
    RETURNING q.status::text INTO v_status;
    RETURN v_status;
END;
$function$;

REVOKE ALL ON FUNCTION public.jas_si_agent_task_claim(uuid,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.jas_si_agent_task_renew(uuid,uuid,bigint,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.jas_si_agent_task_ack_cancel(uuid,uuid,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.jas_si_agent_task_report(uuid,uuid,bigint,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.jas_si_agent_task_fail(uuid,uuid,bigint,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.jas_si_agent_task_claim(uuid,integer) TO jas_si_agent_worker;
GRANT EXECUTE ON FUNCTION public.jas_si_agent_task_renew(uuid,uuid,bigint,integer) TO jas_si_agent_worker;
GRANT EXECUTE ON FUNCTION public.jas_si_agent_task_ack_cancel(uuid,uuid,bigint) TO jas_si_agent_worker;
GRANT EXECUTE ON FUNCTION public.jas_si_agent_task_report(uuid,uuid,bigint,jsonb) TO jas_si_agent_worker;
GRANT EXECUTE ON FUNCTION public.jas_si_agent_task_fail(uuid,uuid,bigint,text,integer) TO jas_si_agent_worker;

RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_agent_task_owner;

DO $block$
DECLARE v_name text; v_owner text; v_proc oid;
BEGIN
    FOREACH v_name IN ARRAY ARRAY[
        'jas_si_agent_task_claim(uuid,integer)',
        'jas_si_agent_task_renew(uuid,uuid,bigint,integer)',
        'jas_si_agent_task_ack_cancel(uuid,uuid,bigint)',
        'jas_si_agent_task_report(uuid,uuid,bigint,jsonb)',
        'jas_si_agent_task_fail(uuid,uuid,bigint,text,integer)'
    ] LOOP
        v_proc := ('public.'||v_name)::regprocedure;
        SELECT pg_catalog.pg_get_userbyid(p.proowner) INTO v_owner
          FROM pg_catalog.pg_proc p WHERE p.oid=v_proc;
        IF v_owner<>'jas_si_agent_task_owner'
           OR NOT (SELECT p.prosecdef FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
           OR NOT (SELECT COALESCE(p.proconfig,ARRAY[]::text[])
                      @> ARRAY['search_path=pg_catalog']::text[]
                     FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
           OR EXISTS (
               SELECT 1 FROM pg_catalog.aclexplode(
                   COALESCE((SELECT p.proacl FROM pg_catalog.pg_proc p WHERE p.oid=v_proc),
                            pg_catalog.acldefault('f',(SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)))
               ) acl WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'
           ) THEN
            RAISE EXCEPTION 'Worker routine security boundary invalid: %',v_name;
        END IF;
    END LOOP;
    IF pg_catalog.has_table_privilege('jas_si_agent_worker','public.jas_si_agent_tasks','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_agent_worker','public.jas_si_agent_tasks','INSERT')
       OR pg_catalog.has_table_privilege('jas_si_agent_worker','public.jas_si_agent_tasks','UPDATE')
       OR pg_catalog.has_table_privilege('jas_si_agent_worker','public.jas_si_agent_tasks','DELETE') THEN
        RAISE EXCEPTION 'Worker capability role has direct task table access';
    END IF;
END
$block$;
