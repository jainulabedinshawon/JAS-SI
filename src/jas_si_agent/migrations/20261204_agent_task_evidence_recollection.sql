-- Evidence-only recollection requests created atomically from immutable review events.
-- This queue never re-enters the Worker task queue and cannot replay task actions.

GRANT CREATE ON SCHEMA public TO jas_si_agent_task_owner;
GRANT REFERENCES (decision_event_id) ON TABLE public.jas_si_agent_task_review_events
    TO jas_si_agent_task_owner;
GRANT TRIGGER ON TABLE public.jas_si_agent_task_review_events
    TO jas_si_agent_task_owner;
SET LOCAL ROLE jas_si_agent_task_owner;

CREATE TABLE IF NOT EXISTS public.jas_si_agent_evidence_requests (
    request_id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
    task_id uuid NOT NULL REFERENCES public.jas_si_agent_tasks(task_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    tenant_id uuid NOT NULL,
    review_event_id uuid NOT NULL UNIQUE
        REFERENCES public.jas_si_agent_task_review_events(decision_event_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    status varchar(16) NOT NULL DEFAULT 'pending',
    attempt_count smallint NOT NULL DEFAULT 0,
    claim_token uuid,
    claimed_at timestamptz,
    lease_expires_at timestamptz,
    next_attempt_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    last_reason_code varchar(64),
    requested_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    completed_at timestamptz,
    CONSTRAINT jas_si_agent_evidence_request_status_check
        CHECK (status IN ('pending','claimed','completed','inconclusive')),
    CONSTRAINT jas_si_agent_evidence_request_attempt_check
        CHECK (attempt_count BETWEEN 0 AND 3),
    CONSTRAINT jas_si_agent_evidence_request_reason_check
        CHECK (last_reason_code IS NULL OR last_reason_code ~ '^[A-Z0-9_]{1,64}$'),
    CONSTRAINT jas_si_agent_evidence_request_lease_check
        CHECK (
            (status='claimed' AND claim_token IS NOT NULL AND claimed_at IS NOT NULL
             AND lease_expires_at IS NOT NULL AND lease_expires_at>claimed_at)
            OR
            (status<>'claimed' AND claim_token IS NULL AND claimed_at IS NULL
             AND lease_expires_at IS NULL)
        ),
    CONSTRAINT jas_si_agent_evidence_request_completion_check
        CHECK (
            (status='completed' AND completed_at IS NOT NULL)
            OR (status<>'completed' AND completed_at IS NULL)
        )
);

CREATE INDEX IF NOT EXISTS jas_si_agent_evidence_requests_pending_idx
    ON public.jas_si_agent_evidence_requests(next_attempt_at,requested_at,request_id)
    WHERE status IN ('pending','claimed');

ALTER TABLE public.jas_si_agent_evidence_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.jas_si_agent_evidence_requests FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS jas_si_agent_evidence_request_owner_all
    ON public.jas_si_agent_evidence_requests;
CREATE POLICY jas_si_agent_evidence_request_owner_all
    ON public.jas_si_agent_evidence_requests
    FOR ALL TO jas_si_agent_task_owner USING (true) WITH CHECK (true);

REVOKE ALL ON TABLE public.jas_si_agent_evidence_requests
    FROM PUBLIC,jas_si_runtime,jas_si_provisioner,jas_si_agent_worker,
         jas_si_agent_worker_login,jas_si_agent_verifier,jas_si_agent_verifier_login;
GRANT SELECT,INSERT,UPDATE ON TABLE public.jas_si_agent_evidence_requests
    TO jas_si_agent_task_owner;
REVOKE DELETE,TRUNCATE,REFERENCES,TRIGGER ON TABLE public.jas_si_agent_evidence_requests
    FROM jas_si_agent_task_owner;

CREATE OR REPLACE FUNCTION public.jas_si_agent_evidence_request_enqueue_review_event()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog
AS $function$
BEGIN
    IF NEW.decision='request_more_evidence' THEN
        INSERT INTO public.jas_si_agent_evidence_requests(
            task_id,tenant_id,review_event_id
        ) VALUES (
            NEW.task_id,NEW.tenant_id,NEW.decision_event_id
        )
        ON CONFLICT (review_event_id) DO NOTHING;
    END IF;
    RETURN NEW;
END;
$function$;

REVOKE ALL ON FUNCTION public.jas_si_agent_evidence_request_enqueue_review_event()
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.jas_si_agent_evidence_request_enqueue_review_event()
    TO jas_si_agent_review_audit_owner;
RESET ROLE;

SET LOCAL ROLE jas_si_agent_review_audit_owner;
DROP TRIGGER IF EXISTS jas_si_agent_evidence_request_after_review
    ON public.jas_si_agent_task_review_events;
CREATE TRIGGER jas_si_agent_evidence_request_after_review
    AFTER INSERT ON public.jas_si_agent_task_review_events
    FOR EACH ROW
    EXECUTE FUNCTION public.jas_si_agent_evidence_request_enqueue_review_event();
RESET ROLE;

SET LOCAL ROLE jas_si_agent_task_owner;

CREATE OR REPLACE FUNCTION public.jas_si_agent_evidence_request_claim(
    p_limit integer DEFAULT 10,
    p_lease_seconds integer DEFAULT 120
) RETURNS TABLE(
    request_id uuid,task_id uuid,tenant_id uuid,task_type text,
    input_payload jsonb,result_payload jsonb,claim_token uuid
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog
AS $function$
DECLARE v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_agent_verifier','MEMBER') THEN
        RAISE EXCEPTION 'Verifier identity is not authorized' USING ERRCODE='42501';
    END IF;
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 20
       OR p_lease_seconds IS NULL OR p_lease_seconds NOT BETWEEN 5 AND 300 THEN
        RAISE EXCEPTION 'Invalid evidence request claim bounds' USING ERRCODE='22023';
    END IF;

    UPDATE public.jas_si_agent_evidence_requests r
       SET status='inconclusive',claim_token=NULL,claimed_at=NULL,
           lease_expires_at=NULL,next_attempt_at=NULL,
           last_reason_code='EVIDENCE_REQUEST_RETRY_EXHAUSTED'
     WHERE r.status='claimed' AND r.attempt_count>=3
       AND r.lease_expires_at<=v_now;

    RETURN QUERY
    WITH candidates AS (
        SELECT r.request_id
          FROM public.jas_si_agent_evidence_requests r
          JOIN public.jas_si_agent_tasks q
            ON q.task_id=r.task_id AND q.tenant_id=r.tenant_id
          JOIN public.jas_si_agent_task_review_events e
            ON e.decision_event_id=r.review_event_id
           AND e.task_id=r.task_id AND e.tenant_id=r.tenant_id
         WHERE r.status IN ('pending','claimed')
           AND r.attempt_count<3
           AND r.next_attempt_at<=v_now
           AND (r.status='pending' OR r.lease_expires_at<=v_now)
           AND q.status='human_review_required'
           AND q.task_type='github.read_repository'
           AND q.input_payload IS NOT NULL
           AND q.result_payload IS NOT NULL
           AND e.decision='request_more_evidence'
         ORDER BY r.next_attempt_at,r.requested_at,r.request_id
         LIMIT p_limit
         FOR UPDATE OF r SKIP LOCKED
    )
    UPDATE public.jas_si_agent_evidence_requests r
       SET status='claimed',claim_token=pg_catalog.gen_random_uuid(),
           claimed_at=v_now,
           lease_expires_at=v_now+pg_catalog.make_interval(secs=>p_lease_seconds),
           attempt_count=r.attempt_count+1
      FROM candidates c
      JOIN public.jas_si_agent_tasks q ON q.task_id=(
          SELECT x.task_id FROM public.jas_si_agent_evidence_requests x
           WHERE x.request_id=c.request_id
      )
     WHERE r.request_id=c.request_id
    RETURNING r.request_id,r.task_id,r.tenant_id,q.task_type::text,
              q.input_payload,q.result_payload,r.claim_token;
END;
$function$;

CREATE OR REPLACE FUNCTION public.jas_si_agent_evidence_request_record_inconclusive(
    p_request_id uuid,p_task_id uuid,p_tenant_id uuid,
    p_claim_token uuid,p_reason_code text
) RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog
AS $function$
DECLARE v_now timestamptz := pg_catalog.clock_timestamp(); v_attempt integer;
        v_status text;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_agent_verifier','MEMBER') THEN
        RAISE EXCEPTION 'Verifier identity is not authorized' USING ERRCODE='42501';
    END IF;
    IF p_request_id IS NULL OR p_task_id IS NULL OR p_tenant_id IS NULL
       OR p_claim_token IS NULL OR p_reason_code IS NULL
       OR p_reason_code !~ '^[A-Z0-9_]{1,64}$' THEN
        RAISE EXCEPTION 'Invalid evidence request outcome' USING ERRCODE='22023';
    END IF;

    SELECT r.attempt_count INTO v_attempt
      FROM public.jas_si_agent_evidence_requests r
      JOIN public.jas_si_agent_tasks q
        ON q.task_id=r.task_id AND q.tenant_id=r.tenant_id
     WHERE r.request_id=p_request_id AND r.task_id=p_task_id
       AND r.tenant_id=p_tenant_id AND r.status='claimed'
       AND r.claim_token=p_claim_token AND r.lease_expires_at>v_now
       AND q.status='human_review_required'
     FOR UPDATE OF r;
    IF NOT FOUND THEN RETURN NULL; END IF;

    IF v_attempt>=3 THEN
        v_status := 'inconclusive';
        UPDATE public.jas_si_agent_evidence_requests
           SET status=v_status,last_reason_code=p_reason_code,
               claim_token=NULL,claimed_at=NULL,lease_expires_at=NULL,
               next_attempt_at=NULL
         WHERE request_id=p_request_id AND claim_token=p_claim_token;
    ELSE
        v_status := 'pending';
        UPDATE public.jas_si_agent_evidence_requests
           SET status=v_status,last_reason_code=p_reason_code,
               claim_token=NULL,claimed_at=NULL,lease_expires_at=NULL,
               next_attempt_at=v_now+pg_catalog.make_interval(
                   secs=>LEAST(300,15*(2^GREATEST(v_attempt-1,0))::integer)
               )
         WHERE request_id=p_request_id AND claim_token=p_claim_token;
    END IF;
    RETURN v_status;
END;
$function$;

CREATE OR REPLACE FUNCTION public.jas_si_agent_evidence_request_finalize_success(
    p_request_id uuid,p_task_id uuid,p_tenant_id uuid,p_claim_token uuid,
    p_evidence_id uuid,p_collector_id text,p_evidence_digest bytea,
    p_evidence_payload jsonb,p_collected_at timestamptz
) RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_success boolean;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_agent_verifier','MEMBER') THEN
        RAISE EXCEPTION 'Verifier identity is not authorized' USING ERRCODE='42501';
    END IF;
    IF p_request_id IS NULL OR p_task_id IS NULL OR p_tenant_id IS NULL
       OR p_claim_token IS NULL THEN
        RAISE EXCEPTION 'Invalid evidence request finalization fence' USING ERRCODE='22023';
    END IF;

    PERFORM 1
      FROM public.jas_si_agent_evidence_requests r
      JOIN public.jas_si_agent_tasks q
        ON q.task_id=r.task_id AND q.tenant_id=r.tenant_id
     WHERE r.request_id=p_request_id AND r.task_id=p_task_id
       AND r.tenant_id=p_tenant_id AND r.status='claimed'
       AND r.claim_token=p_claim_token AND r.lease_expires_at>v_now
       AND q.status='human_review_required'
       AND q.task_type='github.read_repository'
     FOR UPDATE OF r;
    IF NOT FOUND THEN RETURN false; END IF;

    -- Temporarily enter the existing verifier finalizer's required state inside
    -- this transaction. No other transaction can observe the intermediate
    -- state; any failure rolls it back to human_review_required.
    UPDATE public.jas_si_agent_tasks
       SET status='awaiting_verification',
           verifier_claim_token=p_claim_token,
           verifier_claimed_at=v_now,
           verifier_lease_expires_at=v_now+pg_catalog.make_interval(secs=>120),
           updated_at=v_now
     WHERE task_id=p_task_id AND tenant_id=p_tenant_id
       AND status='human_review_required';
    IF NOT FOUND THEN RETURN false; END IF;

    SELECT public.jas_si_agent_task_finalize_success(
        p_evidence_id,p_task_id,p_tenant_id,p_claim_token,p_collector_id,
        p_evidence_digest,p_evidence_payload,p_collected_at
    ) INTO v_success;

    IF v_success IS NOT TRUE THEN
        UPDATE public.jas_si_agent_tasks
           SET status='human_review_required',
               verifier_claim_token=NULL,verifier_claimed_at=NULL,
               verifier_lease_expires_at=NULL,updated_at=v_now
         WHERE task_id=p_task_id AND tenant_id=p_tenant_id
           AND status='awaiting_verification'
           AND verifier_claim_token=p_claim_token;
        RETURN false;
    END IF;

    UPDATE public.jas_si_agent_evidence_requests
       SET status='completed',completed_at=v_now,last_reason_code=NULL,
           claim_token=NULL,claimed_at=NULL,lease_expires_at=NULL,
           next_attempt_at=NULL
     WHERE request_id=p_request_id AND claim_token=p_claim_token;
    RETURN FOUND;
END;
$function$;

REVOKE ALL ON FUNCTION public.jas_si_agent_evidence_request_claim(integer,integer)
    FROM PUBLIC;
REVOKE ALL ON FUNCTION public.jas_si_agent_evidence_request_record_inconclusive(uuid,uuid,uuid,uuid,text)
    FROM PUBLIC;
REVOKE ALL ON FUNCTION public.jas_si_agent_evidence_request_finalize_success(uuid,uuid,uuid,uuid,uuid,text,bytea,jsonb,timestamptz)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.jas_si_agent_evidence_request_claim(integer,integer)
    TO jas_si_agent_verifier;
GRANT EXECUTE ON FUNCTION public.jas_si_agent_evidence_request_record_inconclusive(uuid,uuid,uuid,uuid,text)
    TO jas_si_agent_verifier;
GRANT EXECUTE ON FUNCTION public.jas_si_agent_evidence_request_finalize_success(uuid,uuid,uuid,uuid,uuid,text,bytea,jsonb,timestamptz)
    TO jas_si_agent_verifier;

RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_agent_task_owner;

DO $block$
DECLARE v_proc oid; v_owner text;
BEGIN
    FOREACH v_proc IN ARRAY ARRAY[
        'public.jas_si_agent_evidence_request_claim(integer,integer)'::regprocedure::oid,
        'public.jas_si_agent_evidence_request_record_inconclusive(uuid,uuid,uuid,uuid,text)'::regprocedure::oid,
        'public.jas_si_agent_evidence_request_finalize_success(uuid,uuid,uuid,uuid,uuid,text,bytea,jsonb,timestamptz)'::regprocedure::oid
    ] LOOP
        SELECT pg_catalog.pg_get_userbyid(p.proowner) INTO v_owner
          FROM pg_catalog.pg_proc p WHERE p.oid=v_proc;
        IF v_owner<>'jas_si_agent_task_owner'
           OR NOT (SELECT p.prosecdef FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
           OR NOT (SELECT COALESCE(p.proconfig,ARRAY[]::text[])
                      @> ARRAY['search_path=pg_catalog']::text[]
                     FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
           OR NOT pg_catalog.has_function_privilege('jas_si_agent_verifier',v_proc,'EXECUTE')
           OR pg_catalog.has_function_privilege('jas_si_agent_worker',v_proc,'EXECUTE')
           OR EXISTS (
               SELECT 1 FROM pg_catalog.aclexplode(
                   COALESCE((SELECT p.proacl FROM pg_catalog.pg_proc p WHERE p.oid=v_proc),
                            pg_catalog.acldefault('f',(SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)))
               ) acl WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'
           ) THEN
            RAISE EXCEPTION 'Evidence recollection routine security boundary invalid';
        END IF;
    END LOOP;

    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_trigger t
         WHERE t.tgrelid='public.jas_si_agent_task_review_events'::regclass
           AND t.tgname='jas_si_agent_evidence_request_after_review'
           AND t.tgenabled='O'
    ) OR pg_catalog.has_table_privilege(
        'jas_si_agent_worker','public.jas_si_agent_evidence_requests','SELECT'
    ) OR pg_catalog.has_table_privilege(
        'jas_si_agent_verifier','public.jas_si_agent_evidence_requests','SELECT'
    ) THEN
        RAISE EXCEPTION 'Evidence recollection queue access boundary invalid';
    END IF;
END
$block$;
