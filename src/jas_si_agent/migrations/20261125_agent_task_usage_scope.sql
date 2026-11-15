-- Extend the existing database-owned usage reservation allowlist for agent task submissions.
-- The API still reserves exactly one unit; tenant and scope are derived from the authenticated key.
-- Existing function owner, SECURITY DEFINER boundary, and runtime-only EXECUTE grant are preserved.

GRANT CREATE ON SCHEMA public TO jas_si_api_key_usage_owner;
SET LOCAL ROLE jas_si_api_key_usage_owner;

CREATE OR REPLACE FUNCTION public.jas_si_api_key_usage_reserve(
    p_key_id uuid, p_candidate_digest bytea, p_required_scope text,
    p_request_id text, p_idempotency_key text, p_operation text,
    p_request_fingerprint text, p_units bigint, p_monthly_limit bigint
) RETURNS TABLE(
    event_id uuid, operation text, units bigint, occurred_at timestamptz,
    replayed boolean, monthly_limit bigint, used_units bigint,
    remaining_units bigint, period_start timestamptz, resets_at timestamptz
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE
    v_tenant_id uuid;
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_period_start timestamptz;
    v_period_end timestamptz;
    v_existing record;
    v_used bigint;
    v_event_id uuid;
BEGIN
    IF p_key_id IS NULL OR p_candidate_digest IS NULL
       OR pg_catalog.octet_length(p_candidate_digest)<>32
       OR p_units<>1 OR p_monthly_limit IS NULL
       OR p_monthly_limit NOT BETWEEN 1 AND 1000000
       OR p_request_id IS NULL OR pg_catalog.length(p_request_id) NOT BETWEEN 1 AND 64
       OR p_idempotency_key IS NULL OR pg_catalog.length(p_idempotency_key) NOT BETWEEN 1 AND 128
       OR p_request_fingerprint IS NULL
       OR p_request_fingerprint !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'Invalid API-key usage reservation request' USING ERRCODE='22023';
    END IF;

    IF p_operation NOT IN ('authorization.evaluate','outcome.submit','github.evidence.verify','agent.task.submit')
       OR (p_operation='authorization.evaluate' AND p_required_scope<>'authorization:check')
       OR (p_operation='outcome.submit' AND p_required_scope<>'outcomes:submit')
       OR (p_operation='github.evidence.verify' AND p_required_scope<>'github:evidence:verify')
       OR (p_operation='agent.task.submit' AND p_required_scope<>'agent:tasks:write') THEN
        RAISE EXCEPTION 'API-key usage operation/scope mismatch' USING ERRCODE='42501';
    END IF;

    SELECT k.tenant_id INTO v_tenant_id
      FROM public.jas_si_api_keys k
      JOIN public.jas_si_tenants t ON t.tenant_id=k.tenant_id
     WHERE k.key_id=p_key_id AND k.secret_digest=p_candidate_digest
       AND k.pepper_version=1 AND k.status='active'
       AND (k.expires_at IS NULL OR k.expires_at>v_now)
       AND t.status='active' AND p_required_scope=ANY(k.scopes);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Invalid API-key usage authorization' USING ERRCODE='28000';
    END IF;

    v_period_start := pg_catalog.date_trunc('month',v_now AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
    v_period_end := v_period_start + interval '1 month';
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(v_tenant_id::text,0)
    );

    SELECT e.event_id,e.api_key_id,e.operation,e.units,e.request_fingerprint,e.occurred_at
      INTO v_existing
      FROM public.jas_si_usage_events e
     WHERE e.tenant_id=v_tenant_id AND e.idempotency_key=p_idempotency_key;
    IF FOUND THEN
        IF v_existing.api_key_id<>p_key_id
           OR v_existing.operation<>p_operation OR v_existing.units<>p_units
           OR v_existing.request_fingerprint IS NULL
           OR v_existing.request_fingerprint<>p_request_fingerprint THEN
            RAISE EXCEPTION 'Idempotency key conflicts with a different usage event'
                USING ERRCODE='23505';
        END IF;
        SELECT COALESCE(pg_catalog.sum(e.units),0)::bigint INTO v_used
          FROM public.jas_si_usage_events e
         WHERE e.tenant_id=v_tenant_id
           AND e.occurred_at>=v_period_start AND e.occurred_at<v_period_end;
        RETURN QUERY SELECT v_existing.event_id,v_existing.operation::text,
            v_existing.units,v_existing.occurred_at,true,p_monthly_limit,v_used,
            CASE WHEN p_monthly_limit>v_used THEN p_monthly_limit-v_used ELSE 0 END,
            v_period_start,v_period_end;
        RETURN;
    END IF;

    SELECT COALESCE(pg_catalog.sum(e.units),0)::bigint INTO v_used
      FROM public.jas_si_usage_events e
     WHERE e.tenant_id=v_tenant_id
       AND e.occurred_at>=v_period_start AND e.occurred_at<v_period_end;
    IF v_used+p_units>p_monthly_limit THEN
        RAISE EXCEPTION 'API-key monthly usage quota exceeded'
            USING ERRCODE='P0001',
            DETAIL=pg_catalog.json_build_object(
                'monthly_limit',p_monthly_limit,'used_units',v_used,
                'requested_units',p_units,'resets_at',v_period_end
            )::text;
    END IF;

    v_event_id := pg_catalog.gen_random_uuid();
    INSERT INTO public.jas_si_usage_events(
        event_id,tenant_id,api_key_id,request_id,idempotency_key,
        operation,units,occurred_at,request_fingerprint
    ) VALUES (
        v_event_id,v_tenant_id,p_key_id,p_request_id,p_idempotency_key,
        p_operation,p_units,v_now,p_request_fingerprint
    );
    RETURN QUERY SELECT v_event_id,p_operation,p_units,v_now,false,p_monthly_limit,
        v_used+p_units,
        CASE WHEN p_monthly_limit>v_used+p_units THEN p_monthly_limit-v_used-p_units ELSE 0 END,
        v_period_start,v_period_end;
END;
$function$;

REVOKE ALL ON FUNCTION public.jas_si_api_key_usage_reserve(uuid,bytea,text,text,text,text,text,bigint,bigint)
    FROM PUBLIC,jas_si_runtime;
GRANT EXECUTE ON FUNCTION public.jas_si_api_key_usage_reserve(uuid,bytea,text,text,text,text,text,bigint,bigint)
    TO jas_si_runtime;

RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_api_key_usage_owner;
