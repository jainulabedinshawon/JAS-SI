-- Customer-session-bound usage reads. The customer runtime receives EXECUTE only;
-- tenant identity is derived and validated inside PostgreSQL from the session digest.
GRANT SELECT (tenant_id,event_id,request_id,operation,units,occurred_at)
    ON public.jas_si_usage_events TO jas_si_customer_identity_owner;

CREATE OR REPLACE FUNCTION public.customer_usage_summary(
    p_session_digest bytea, p_since timestamptz
) RETURNS TABLE(
    tenant_id uuid, total_units bigint, event_count bigint,
    by_operation jsonb, current_month_units bigint
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $function$
DECLARE
    v_tenant_id uuid;
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_month_start timestamptz;
BEGIN
    IF p_session_digest IS NULL OR pg_catalog.octet_length(p_session_digest) <> 32
       OR p_since IS NULL THEN
        RAISE EXCEPTION 'Invalid customer usage request' USING ERRCODE='22023';
    END IF;
    SELECT a.tenant_id INTO v_tenant_id
      FROM public.jas_si_customer_sessions s
      JOIN public.jas_si_customer_accounts a ON a.account_id=s.account_id
     WHERE s.token_digest=p_session_digest
       AND s.revoked_at IS NULL
       AND s.expires_at > v_now
       AND a.status='active'
     FOR SHARE OF s,a;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Invalid customer session' USING ERRCODE='28000';
    END IF;
    v_month_start := pg_catalog.date_trunc('month',v_now AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
    RETURN QUERY
    SELECT v_tenant_id,
        COALESCE((SELECT pg_catalog.sum(e.units) FROM public.jas_si_usage_events e
                  WHERE e.tenant_id=v_tenant_id AND e.occurred_at >= p_since),0)::bigint,
        COALESCE((SELECT pg_catalog.count(*) FROM public.jas_si_usage_events e
                  WHERE e.tenant_id=v_tenant_id AND e.occurred_at >= p_since),0)::bigint,
        COALESCE((
            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                'operation',g.operation,'events',g.event_count,'units',g.total_units,
                'last_recorded_at',g.last_recorded_at
            ) ORDER BY g.operation)
            FROM (
                SELECT e.operation,pg_catalog.count(*) AS event_count,
                       pg_catalog.sum(e.units) AS total_units,
                       pg_catalog.max(e.occurred_at) AS last_recorded_at
                  FROM public.jas_si_usage_events e
                 WHERE e.tenant_id=v_tenant_id AND e.occurred_at >= p_since
                 GROUP BY e.operation
            ) g
        ),'[]'::jsonb),
        COALESCE((SELECT pg_catalog.sum(e.units) FROM public.jas_si_usage_events e
                  WHERE e.tenant_id=v_tenant_id AND e.occurred_at >= v_month_start),0)::bigint;
END;
$function$;

CREATE OR REPLACE FUNCTION public.customer_usage_events(
    p_session_digest bytea, p_limit integer,
    p_before timestamptz, p_before_event_id uuid
) RETURNS TABLE(
    event_id uuid, request_id varchar, operation varchar,
    units bigint, occurred_at timestamptz
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $function$
DECLARE v_tenant_id uuid; v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
    IF p_session_digest IS NULL OR pg_catalog.octet_length(p_session_digest) <> 32
       OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100
       OR ((p_before IS NULL) <> (p_before_event_id IS NULL)) THEN
        RAISE EXCEPTION 'Invalid customer usage history request' USING ERRCODE='22023';
    END IF;
    SELECT a.tenant_id INTO v_tenant_id
      FROM public.jas_si_customer_sessions s
      JOIN public.jas_si_customer_accounts a ON a.account_id=s.account_id
     WHERE s.token_digest=p_session_digest
       AND s.revoked_at IS NULL
       AND s.expires_at > v_now
       AND a.status='active'
     FOR SHARE OF s,a;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Invalid customer session' USING ERRCODE='28000';
    END IF;
    IF p_before IS NULL THEN
        RETURN QUERY
        SELECT e.event_id,e.request_id,e.operation,e.units,e.occurred_at
          FROM public.jas_si_usage_events e
         WHERE e.tenant_id=v_tenant_id
         ORDER BY e.occurred_at DESC,e.event_id DESC
         LIMIT p_limit + 1;
    ELSE
        RETURN QUERY
        SELECT e.event_id,e.request_id,e.operation,e.units,e.occurred_at
          FROM public.jas_si_usage_events e
         WHERE e.tenant_id=v_tenant_id
           AND (e.occurred_at,e.event_id) < (p_before,p_before_event_id)
         ORDER BY e.occurred_at DESC,e.event_id DESC
         LIMIT p_limit + 1;
    END IF;
END;
$function$;

ALTER FUNCTION public.customer_usage_summary(bytea,timestamptz)
    OWNER TO jas_si_customer_identity_owner;
ALTER FUNCTION public.customer_usage_events(bytea,integer,timestamptz,uuid)
    OWNER TO jas_si_customer_identity_owner;

REVOKE ALL ON FUNCTION public.customer_usage_summary(bytea,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.customer_usage_events(bytea,integer,timestamptz,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.customer_usage_summary(bytea,timestamptz)
    TO jas_si_customer_runtime;
GRANT EXECUTE ON FUNCTION public.customer_usage_events(bytea,integer,timestamptz,uuid)
    TO jas_si_customer_runtime;
