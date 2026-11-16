-- Persist inconclusive verifier outcomes and bound retries.
-- Exhausted or repeatedly inconclusive verification is routed to human review;
-- it is never converted into success or failure without independent evidence.

ALTER TABLE public.jas_si_agent_tasks
    ADD COLUMN IF NOT EXISTS verifier_next_attempt_at timestamptz DEFAULT pg_catalog.clock_timestamp(),
    ADD COLUMN IF NOT EXISTS verifier_last_status varchar(32),
    ADD COLUMN IF NOT EXISTS verifier_last_reason varchar(64);

ALTER TABLE public.jas_si_agent_tasks
    DROP CONSTRAINT IF EXISTS jas_si_agent_task_status_check;
ALTER TABLE public.jas_si_agent_tasks
    ADD CONSTRAINT jas_si_agent_task_status_check
    CHECK (status IN (
        'queued','running','cancel_requested','awaiting_verification',
        'human_review_required','succeeded','failed','cancelled'
    ));

ALTER TABLE public.jas_si_agent_tasks
    DROP CONSTRAINT IF EXISTS jas_si_agent_task_completion_consistency;
ALTER TABLE public.jas_si_agent_tasks
    ADD CONSTRAINT jas_si_agent_task_completion_consistency
    CHECK (
        (status IN ('succeeded','failed','cancelled') AND completed_at IS NOT NULL)
        OR
        (status IN ('queued','running','cancel_requested','awaiting_verification','human_review_required')
         AND completed_at IS NULL)
    );

DO $block$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE conname='jas_si_agent_task_verifier_last_status_check'
           AND conrelid='public.jas_si_agent_tasks'::regclass
    ) THEN
        ALTER TABLE public.jas_si_agent_tasks
            ADD CONSTRAINT jas_si_agent_task_verifier_last_status_check
            CHECK (verifier_last_status IS NULL OR verifier_last_status='INCONCLUSIVE');
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE conname='jas_si_agent_task_verifier_last_reason_check'
           AND conrelid='public.jas_si_agent_tasks'::regclass
    ) THEN
        ALTER TABLE public.jas_si_agent_tasks
            ADD CONSTRAINT jas_si_agent_task_verifier_last_reason_check
            CHECK (verifier_last_reason IS NULL OR verifier_last_reason ~ '^[A-Z0-9_]{1,64}$');
    END IF;
END
$block$;

GRANT CREATE ON SCHEMA public TO jas_si_agent_task_owner;
SET LOCAL ROLE jas_si_agent_task_owner;

CREATE OR REPLACE FUNCTION public.jas_si_agent_task_verification_claim(
    p_limit integer DEFAULT 10,
    p_lease_seconds integer DEFAULT 120
) RETURNS TABLE(
    task_id uuid,tenant_id uuid,task_type text,input_payload jsonb,
    result_payload jsonb,reported_at timestamptz,verifier_claim_token uuid
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_agent_verifier','MEMBER') THEN
        RAISE EXCEPTION 'Verifier identity is not authorized' USING ERRCODE='42501';
    END IF;
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 20
       OR p_lease_seconds IS NULL OR p_lease_seconds NOT BETWEEN 5 AND 300 THEN
        RAISE EXCEPTION 'Invalid verifier claim bounds' USING ERRCODE='22023';
    END IF;

    -- A verifier that crashes on its final permitted attempt is moved to
    -- review when its lease expires; it cannot loop forever.
    UPDATE public.jas_si_agent_tasks q
       SET status='human_review_required',
           verifier_claim_token=NULL,
           verifier_claimed_at=NULL,
           verifier_lease_expires_at=NULL,
           verifier_next_attempt_at=NULL,
           verifier_last_status='INCONCLUSIVE',
           verifier_last_reason='VERIFIER_LEASE_EXPIRED_AFTER_RETRY_LIMIT',
           error_code='VERIFICATION_RETRY_EXHAUSTED',
           updated_at=v_now
     WHERE q.status='awaiting_verification'
       AND q.verifier_attempt_count>=3
       AND q.verifier_claim_token IS NOT NULL
       AND q.verifier_lease_expires_at<=v_now;

    RETURN QUERY
    WITH candidates AS (
        SELECT q.task_id
          FROM public.jas_si_agent_tasks q
         WHERE q.status='awaiting_verification'
           AND q.task_type='github.read_repository'
           AND q.result_payload IS NOT NULL
           AND q.reported_at IS NOT NULL
           AND q.verifier_attempt_count<3
           AND q.verifier_next_attempt_at<=v_now
           AND (q.verifier_claim_token IS NULL OR q.verifier_lease_expires_at<=v_now)
         ORDER BY q.verifier_next_attempt_at,q.reported_at,q.task_id
         LIMIT p_limit
         FOR UPDATE SKIP LOCKED
    )
    UPDATE public.jas_si_agent_tasks q
       SET verifier_claim_token=pg_catalog.gen_random_uuid(),
           verifier_claimed_at=v_now,
           verifier_lease_expires_at=v_now+pg_catalog.make_interval(secs=>p_lease_seconds),
           verifier_attempt_count=q.verifier_attempt_count+1,
           updated_at=v_now
      FROM candidates c
     WHERE q.task_id=c.task_id
    RETURNING q.task_id,q.tenant_id,q.task_type::text,q.input_payload,
              q.result_payload,q.reported_at,q.verifier_claim_token;
END;
$function$;

CREATE OR REPLACE FUNCTION public.jas_si_agent_task_verification_record_inconclusive(
    p_task_id uuid,
    p_tenant_id uuid,
    p_claim_token uuid,
    p_reason_code text
) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_attempt integer;
    v_status text;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_agent_verifier','MEMBER') THEN
        RAISE EXCEPTION 'Verifier identity is not authorized' USING ERRCODE='42501';
    END IF;
    IF p_task_id IS NULL OR p_tenant_id IS NULL OR p_claim_token IS NULL
       OR p_reason_code IS NULL OR p_reason_code !~ '^[A-Z0-9_]{1,64}$' THEN
        RAISE EXCEPTION 'Invalid inconclusive verifier outcome' USING ERRCODE='22023';
    END IF;

    SELECT q.verifier_attempt_count INTO v_attempt
      FROM public.jas_si_agent_tasks q
     WHERE q.task_id=p_task_id
       AND q.tenant_id=p_tenant_id
       AND q.status='awaiting_verification'
       AND q.verifier_claim_token=p_claim_token
       AND q.verifier_lease_expires_at>v_now
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    IF v_attempt>=3 THEN
        v_status := 'human_review_required';
        UPDATE public.jas_si_agent_tasks
           SET status=v_status,
               verifier_last_status='INCONCLUSIVE',
               verifier_last_reason=p_reason_code,
               verifier_next_attempt_at=NULL,
               verifier_claim_token=NULL,
               verifier_claimed_at=NULL,
               verifier_lease_expires_at=NULL,
               error_code='VERIFICATION_RETRY_EXHAUSTED',
               updated_at=v_now
         WHERE task_id=p_task_id AND tenant_id=p_tenant_id
           AND status='awaiting_verification' AND verifier_claim_token=p_claim_token;
    ELSE
        v_status := 'awaiting_verification';
        UPDATE public.jas_si_agent_tasks
           SET verifier_last_status='INCONCLUSIVE',
               verifier_last_reason=p_reason_code,
               verifier_next_attempt_at=v_now
                   + pg_catalog.make_interval(secs=>LEAST(300,15*(2^GREATEST(v_attempt-1,0))::integer)),
               verifier_claim_token=NULL,
               verifier_claimed_at=NULL,
               verifier_lease_expires_at=NULL,
               error_code='VERIFICATION_INCONCLUSIVE_RETRY',
               updated_at=v_now
         WHERE task_id=p_task_id AND tenant_id=p_tenant_id
           AND status='awaiting_verification' AND verifier_claim_token=p_claim_token;
    END IF;
    RETURN v_status;
END;
$function$;

CREATE OR REPLACE FUNCTION public.jas_si_agent_task_review_metadata(
    p_api_key_id uuid,
    p_candidate_digest bytea,
    p_task_id uuid
) RETURNS TABLE(
    review_required boolean,
    verification_status text,
    verification_reason_code text
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE v_tenant_id uuid;
BEGIN
    IF p_api_key_id IS NULL OR p_candidate_digest IS NULL
       OR pg_catalog.octet_length(p_candidate_digest)<>32 OR p_task_id IS NULL THEN
        RAISE EXCEPTION 'Invalid task review metadata request' USING ERRCODE='22023';
    END IF;
    SELECT auth.auth_tenant_id INTO v_tenant_id
      FROM public.jas_si_api_key_authenticate(p_api_key_id,p_candidate_digest) auth
     WHERE 'agent:tasks:read'=ANY(auth.auth_scopes);
    IF v_tenant_id IS NULL THEN
        RAISE EXCEPTION 'Agent task API key is not authorized' USING ERRCODE='42501';
    END IF;

    RETURN QUERY
    SELECT q.status='human_review_required',
           CASE WHEN q.status='human_review_required' THEN q.verifier_last_status END,
           CASE WHEN q.status='human_review_required' THEN q.verifier_last_reason END
      FROM public.jas_si_agent_tasks q
     WHERE q.task_id=p_task_id AND q.tenant_id=v_tenant_id;
END;
$function$;

REVOKE ALL ON FUNCTION public.jas_si_agent_task_verification_claim(integer,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.jas_si_agent_task_verification_record_inconclusive(uuid,uuid,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.jas_si_agent_task_review_metadata(uuid,bytea,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.jas_si_agent_task_verification_claim(integer,integer) TO jas_si_agent_verifier;
GRANT EXECUTE ON FUNCTION public.jas_si_agent_task_verification_record_inconclusive(uuid,uuid,uuid,text) TO jas_si_agent_verifier;
GRANT EXECUTE ON FUNCTION public.jas_si_agent_task_review_metadata(uuid,bytea,uuid) TO jas_si_runtime;

RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_agent_task_owner;

DO $block$
DECLARE v_proc oid; v_owner text;
BEGIN
    FOREACH v_proc IN ARRAY ARRAY[
        'public.jas_si_agent_task_verification_claim(integer,integer)'::regprocedure::oid,
        'public.jas_si_agent_task_verification_record_inconclusive(uuid,uuid,uuid,text)'::regprocedure::oid,
        'public.jas_si_agent_task_review_metadata(uuid,bytea,uuid)'::regprocedure::oid
    ] LOOP
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
            RAISE EXCEPTION 'Verifier inconclusive routine security boundary invalid';
        END IF;
    END LOOP;
    IF pg_catalog.has_table_privilege('jas_si_agent_verifier','public.jas_si_agent_tasks','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_agent_verifier','public.jas_si_agent_tasks','UPDATE') THEN
        RAISE EXCEPTION 'Verifier capability role has direct task table access';
    END IF;
END
$block$;
