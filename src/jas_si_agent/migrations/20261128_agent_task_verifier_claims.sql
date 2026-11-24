-- Add atomic verifier work ownership with expiring, task-bound fencing tokens.
-- A verifier crash leaves a claim that can be reclaimed after its bounded lease.
ALTER TABLE public.jas_si_agent_tasks
    ADD COLUMN IF NOT EXISTS verifier_claim_token uuid,
    ADD COLUMN IF NOT EXISTS verifier_claimed_at timestamptz,
    ADD COLUMN IF NOT EXISTS verifier_lease_expires_at timestamptz,
    ADD COLUMN IF NOT EXISTS verifier_attempt_count integer NOT NULL DEFAULT 0;
DO $block$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname='jas_si_agent_task_verifier_attempt_count_check' AND conrelid='public.jas_si_agent_tasks'::regclass) THEN
        ALTER TABLE public.jas_si_agent_tasks ADD CONSTRAINT jas_si_agent_task_verifier_attempt_count_check CHECK (verifier_attempt_count >= 0);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname='jas_si_agent_task_verifier_claim_shape_check' AND conrelid='public.jas_si_agent_tasks'::regclass) THEN
        ALTER TABLE public.jas_si_agent_tasks ADD CONSTRAINT jas_si_agent_task_verifier_claim_shape_check CHECK (
            (verifier_claim_token IS NULL AND verifier_claimed_at IS NULL AND verifier_lease_expires_at IS NULL)
            OR (verifier_claim_token IS NOT NULL AND verifier_claimed_at IS NOT NULL AND verifier_lease_expires_at IS NOT NULL AND verifier_lease_expires_at > verifier_claimed_at)
        );
    END IF;
END
$block$;
CREATE INDEX IF NOT EXISTS jas_si_agent_tasks_verifier_claim_idx ON public.jas_si_agent_tasks(reported_at,task_id)
    WHERE status='awaiting_verification' AND task_type='github.read_repository';
DROP FUNCTION IF EXISTS public.jas_si_agent_task_verification_list(integer);
DROP FUNCTION IF EXISTS public.jas_si_agent_task_finalize_success(uuid,uuid,uuid,text,bytea,jsonb,timestamptz);
GRANT CREATE ON SCHEMA public TO jas_si_agent_task_owner;
SET LOCAL ROLE jas_si_agent_task_owner;
CREATE OR REPLACE FUNCTION public.jas_si_agent_task_verification_claim(p_limit integer DEFAULT 10,p_lease_seconds integer DEFAULT 120)
RETURNS TABLE(task_id uuid,tenant_id uuid,task_type text,input_payload jsonb,result_payload jsonb,reported_at timestamptz,verifier_claim_token uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_agent_verifier','MEMBER') THEN RAISE EXCEPTION 'Verifier identity is not authorized' USING ERRCODE='42501'; END IF;
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 20 OR p_lease_seconds IS NULL OR p_lease_seconds NOT BETWEEN 5 AND 300 THEN
        RAISE EXCEPTION 'Invalid verifier claim bounds' USING ERRCODE='22023';
    END IF;
    RETURN QUERY
    WITH candidates AS (
        SELECT q.task_id FROM public.jas_si_agent_tasks q
         WHERE q.status='awaiting_verification' AND q.task_type='github.read_repository'
           AND q.result_payload IS NOT NULL AND q.reported_at IS NOT NULL
           AND (q.verifier_claim_token IS NULL OR q.verifier_lease_expires_at <= pg_catalog.clock_timestamp())
         ORDER BY q.reported_at,q.task_id LIMIT p_limit FOR UPDATE SKIP LOCKED
    )
    UPDATE public.jas_si_agent_tasks q
       SET verifier_claim_token=pg_catalog.gen_random_uuid(),verifier_claimed_at=pg_catalog.clock_timestamp(),
           verifier_lease_expires_at=pg_catalog.clock_timestamp()+pg_catalog.make_interval(secs=>p_lease_seconds),
           verifier_attempt_count=q.verifier_attempt_count+1,updated_at=pg_catalog.clock_timestamp()
      FROM candidates c WHERE q.task_id=c.task_id
    RETURNING q.task_id,q.tenant_id,q.task_type::text,q.input_payload,q.result_payload,q.reported_at,q.verifier_claim_token;
END;
$function$;
CREATE OR REPLACE FUNCTION public.jas_si_agent_task_verification_release(p_task_id uuid,p_tenant_id uuid,p_claim_token uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_agent_verifier','MEMBER') THEN RAISE EXCEPTION 'Verifier identity is not authorized' USING ERRCODE='42501'; END IF;
    IF p_task_id IS NULL OR p_tenant_id IS NULL OR p_claim_token IS NULL THEN RAISE EXCEPTION 'Verifier claim binding is required' USING ERRCODE='22023'; END IF;
    UPDATE public.jas_si_agent_tasks SET verifier_claim_token=NULL,verifier_claimed_at=NULL,verifier_lease_expires_at=NULL,updated_at=pg_catalog.clock_timestamp()
     WHERE task_id=p_task_id AND tenant_id=p_tenant_id AND status='awaiting_verification' AND verifier_claim_token=p_claim_token;
    RETURN FOUND;
END;
$function$;
CREATE OR REPLACE FUNCTION public.jas_si_agent_task_finalize_success(
    p_evidence_id uuid,p_task_id uuid,p_tenant_id uuid,p_claim_token uuid,p_collector_id text,
    p_evidence_digest bytea,p_evidence_payload jsonb,p_collected_at timestamptz
) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE v_task public.jas_si_agent_tasks%ROWTYPE; v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_agent_verifier','MEMBER') THEN RAISE EXCEPTION 'Verifier identity is not authorized' USING ERRCODE='42501'; END IF;
    IF p_evidence_id IS NULL OR p_task_id IS NULL OR p_tenant_id IS NULL OR p_claim_token IS NULL
       OR p_collector_id IS NULL OR length(btrim(p_collector_id)) NOT BETWEEN 1 AND 128
       OR p_evidence_digest IS NULL OR octet_length(p_evidence_digest)<>32
       OR p_evidence_payload IS NULL OR pg_catalog.jsonb_typeof(p_evidence_payload)<>'object'
       OR pg_catalog.octet_length(p_evidence_payload::text)>65536 OR p_collected_at IS NULL OR p_collected_at>v_now THEN
        RAISE EXCEPTION 'Invalid independent evidence finalization request' USING ERRCODE='22023';
    END IF;
    SELECT q.* INTO v_task FROM public.jas_si_agent_tasks q WHERE q.task_id=p_task_id AND q.tenant_id=p_tenant_id FOR UPDATE;
    IF NOT FOUND OR v_task.status<>'awaiting_verification' OR v_task.task_type<>'github.read_repository'
       OR v_task.verifier_claim_token IS DISTINCT FROM p_claim_token OR v_task.verifier_lease_expires_at IS NULL
       OR v_task.verifier_lease_expires_at<=v_now THEN RETURN false; END IF;
    IF p_evidence_payload->>'collector_id' IS DISTINCT FROM p_collector_id
       OR p_evidence_payload->>'verification_status' IS DISTINCT FROM 'VERIFIED_SUCCESS'
       OR p_evidence_payload->>'task_id' IS DISTINCT FROM p_task_id::text
       OR p_evidence_payload->>'tenant_id' IS DISTINCT FROM p_tenant_id::text
       OR p_evidence_payload->>'repository' IS DISTINCT FROM v_task.input_payload->>'repository'
       OR p_evidence_payload->>'commit_sha' IS DISTINCT FROM v_task.input_payload->>'commit_sha'
       OR p_evidence_payload->>'evidence_digest' IS DISTINCT FROM pg_catalog.encode(p_evidence_digest,'hex') THEN
        RAISE EXCEPTION 'Independent evidence is not bound to the persisted task' USING ERRCODE='22023';
    END IF;
    INSERT INTO public.jas_si_agent_evidence_records(evidence_id,task_id,tenant_id,collector_id,verification_status,evidence_digest,evidence_payload,collected_at)
    VALUES (p_evidence_id,p_task_id,p_tenant_id,p_collector_id,'VERIFIED_SUCCESS',p_evidence_digest,p_evidence_payload,p_collected_at);
    UPDATE public.jas_si_agent_tasks SET status='succeeded',verifier_evidence_id=p_evidence_id,completed_at=v_now,updated_at=v_now,
        error_code=NULL,verifier_claim_token=NULL,verifier_claimed_at=NULL,verifier_lease_expires_at=NULL
     WHERE task_id=p_task_id AND tenant_id=p_tenant_id AND status='awaiting_verification' AND verifier_claim_token=p_claim_token;
    RETURN FOUND;
END;
$function$;
REVOKE ALL ON FUNCTION public.jas_si_agent_task_verification_claim(integer,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.jas_si_agent_task_verification_release(uuid,uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.jas_si_agent_task_finalize_success(uuid,uuid,uuid,uuid,text,bytea,jsonb,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.jas_si_agent_task_verification_claim(integer,integer) TO jas_si_agent_verifier;
GRANT EXECUTE ON FUNCTION public.jas_si_agent_task_verification_release(uuid,uuid,uuid) TO jas_si_agent_verifier;
GRANT EXECUTE ON FUNCTION public.jas_si_agent_task_finalize_success(uuid,uuid,uuid,uuid,text,bytea,jsonb,timestamptz) TO jas_si_agent_verifier;
RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_agent_task_owner;
DO $block$
DECLARE v_proc oid; v_owner text;
BEGIN
    FOREACH v_proc IN ARRAY ARRAY[
        'public.jas_si_agent_task_verification_claim(integer,integer)'::regprocedure::oid,
        'public.jas_si_agent_task_verification_release(uuid,uuid,uuid)'::regprocedure::oid,
        'public.jas_si_agent_task_finalize_success(uuid,uuid,uuid,uuid,text,bytea,jsonb,timestamptz)'::regprocedure::oid
    ] LOOP
        SELECT pg_catalog.pg_get_userbyid(p.proowner) INTO v_owner FROM pg_catalog.pg_proc p WHERE p.oid=v_proc;
        IF v_owner<>'jas_si_agent_task_owner'
           OR NOT (SELECT p.prosecdef FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
           OR NOT (SELECT COALESCE(p.proconfig,ARRAY[]::text[]) @> ARRAY['search_path=pg_catalog']::text[] FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
           OR EXISTS (SELECT 1 FROM pg_catalog.aclexplode(COALESCE((SELECT p.proacl FROM pg_catalog.pg_proc p WHERE p.oid=v_proc),
                    pg_catalog.acldefault('f',(SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)))) acl
                    WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE') THEN
            RAISE EXCEPTION 'Verifier routine security boundary invalid';
        END IF;
    END LOOP;
    IF pg_catalog.has_table_privilege('jas_si_agent_verifier','public.jas_si_agent_tasks','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_agent_verifier','public.jas_si_agent_tasks','UPDATE')
       OR pg_catalog.has_table_privilege('jas_si_agent_verifier','public.jas_si_agent_evidence_records','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_agent_verifier','public.jas_si_agent_evidence_records','INSERT') THEN
        RAISE EXCEPTION 'Verifier capability role has direct table access';
    END IF;
END
$block$;
