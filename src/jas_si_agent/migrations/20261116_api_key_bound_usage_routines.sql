-- API-key-bound usage metering routines.
-- Validation uses SELECT-only grants; an in-flight request already authorized at its
-- database statement snapshot may complete if revocation commits concurrently.
-- Additive stage only: existing runtime table grants remain until every API path
-- is cut over and a separately reviewed revocation migration is approved.

DO $body$
DECLARE v_oid oid; v_role record;
BEGIN
    SELECT oid INTO v_oid FROM pg_catalog.pg_roles
     WHERE rolname='jas_si_api_key_usage_owner';
    IF v_oid IS NULL THEN
        CREATE ROLE jas_si_api_key_usage_owner NOLOGIN NOSUPERUSER NOCREATEDB
            NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
        SELECT oid INTO v_oid FROM pg_catalog.pg_roles
         WHERE rolname='jas_si_api_key_usage_owner';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='neondb_owner') THEN
        EXECUTE 'GRANT jas_si_api_key_usage_owner TO neondb_owner WITH ADMIN FALSE, INHERIT FALSE, SET TRUE';
    END IF;
    SELECT * INTO v_role FROM pg_catalog.pg_roles WHERE oid=v_oid;
    IF v_role.rolcanlogin OR v_role.rolsuper OR v_role.rolcreatedb
       OR v_role.rolcreaterole OR v_role.rolreplication
       OR v_role.rolbypassrls OR v_role.rolinherit
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
                  JOIN pg_catalog.pg_roles platform_member ON platform_member.oid=m.member
                  JOIN pg_catalog.pg_roles membership_grantor ON membership_grantor.oid=m.grantor
                  WHERE m.member=v_oid OR (m.roleid=v_oid AND NOT (
                      ((platform_member.rolname='neondb_owner' AND NOT m.admin_option
                      AND NOT m.inherit_option AND m.set_option) OR (platform_member.rolname='neondb_owner' AND membership_grantor.rolname='neondb_owner' AND membership_grantor.rolname='cloud_admin'
                      AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option))))) THEN
        RAISE EXCEPTION 'Unsafe API-key usage owner role configuration';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_runtime') THEN
        RAISE EXCEPTION 'jas_si_runtime role is required for API-key usage routines';
    END IF;
END
$body$;

GRANT USAGE ON SCHEMA public TO jas_si_api_key_usage_owner, jas_si_runtime;
REVOKE CREATE ON SCHEMA public FROM jas_si_runtime;

GRANT SELECT (key_id,tenant_id,secret_digest,pepper_version,scopes,status,expires_at)
    ON public.jas_si_api_keys TO jas_si_api_key_usage_owner;
GRANT SELECT (tenant_id,status)
    ON public.jas_si_tenants TO jas_si_api_key_usage_owner;
GRANT SELECT (event_id,tenant_id,api_key_id,request_id,idempotency_key,
              operation,units,occurred_at,request_fingerprint)
    ON public.jas_si_usage_events TO jas_si_api_key_usage_owner;
GRANT INSERT (event_id,tenant_id,api_key_id,request_id,idempotency_key,
              operation,units,occurred_at,request_fingerprint)
    ON public.jas_si_usage_events TO jas_si_api_key_usage_owner;

ALTER TABLE public.jas_si_api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.jas_si_tenants ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS jas_si_api_keys_usage_owner_select ON public.jas_si_api_keys;
CREATE POLICY jas_si_api_keys_usage_owner_select
    ON public.jas_si_api_keys FOR SELECT TO jas_si_api_key_usage_owner
    USING (true);
DROP POLICY IF EXISTS jas_si_tenants_usage_owner_select ON public.jas_si_tenants;
CREATE POLICY jas_si_tenants_usage_owner_select
    ON public.jas_si_tenants FOR SELECT TO jas_si_api_key_usage_owner
    USING (true);

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

    IF p_operation NOT IN ('authorization.evaluate','outcome.submit','github.evidence.verify')
       OR (p_operation='authorization.evaluate' AND p_required_scope<>'authorization:check')
       OR (p_operation='outcome.submit' AND p_required_scope<>'outcomes:submit')
       OR (p_operation='github.evidence.verify' AND p_required_scope<>'github:evidence:verify') THEN
        RAISE EXCEPTION 'API-key usage operation/scope mismatch' USING ERRCODE='42501';
    END IF;

    SELECT k.tenant_id INTO v_tenant_id
      FROM public.jas_si_api_keys k
      JOIN public.jas_si_tenants t ON t.tenant_id=k.tenant_id
     WHERE k.key_id=p_key_id AND k.secret_digest=p_candidate_digest
       AND k.pepper_version=1 AND k.status='active'
       AND (k.expires_at IS NULL OR k.expires_at>v_now)
       AND t.status='active' AND p_required_scope=ANY(k.scopes)
     ;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Invalid API-key usage authorization' USING ERRCODE='28000';
    END IF;

    v_period_start := pg_catalog.date_trunc('month',v_now AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
    v_period_end := (v_period_start + interval '1 month');
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
            CASE WHEN p_monthly_limit>v_used THEN p_monthly_limit-v_used ELSE 0 END,v_period_start,v_period_end;
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
        v_used+p_units,CASE WHEN p_monthly_limit>v_used+p_units THEN p_monthly_limit-v_used-p_units ELSE 0 END,
        v_period_start,v_period_end;
END;
$function$;

CREATE OR REPLACE FUNCTION public.jas_si_api_key_usage_quota(
    p_key_id uuid,p_candidate_digest bytea,p_required_scope text,p_monthly_limit bigint
) RETURNS TABLE(
    period text,period_start timestamptz,resets_at timestamptz,
    monthly_limit bigint,used_units bigint,remaining_units bigint,exhausted boolean
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE v_tenant_id uuid; v_now timestamptz:=pg_catalog.clock_timestamp();
        v_start timestamptz; v_end timestamptz; v_used bigint;
BEGIN
    IF p_key_id IS NULL OR p_candidate_digest IS NULL
       OR pg_catalog.octet_length(p_candidate_digest)<>32
       OR p_required_scope IS DISTINCT FROM 'usage:read'
       OR p_monthly_limit IS NULL OR p_monthly_limit NOT BETWEEN 1 AND 1000000 THEN
        RAISE EXCEPTION 'Invalid API-key quota request' USING ERRCODE='22023';
    END IF;
    SELECT k.tenant_id INTO v_tenant_id
      FROM public.jas_si_api_keys k JOIN public.jas_si_tenants t ON t.tenant_id=k.tenant_id
     WHERE k.key_id=p_key_id AND k.secret_digest=p_candidate_digest
       AND k.pepper_version=1 AND k.status='active'
       AND (k.expires_at IS NULL OR k.expires_at>v_now)
       AND t.status='active' AND p_required_scope=ANY(k.scopes)
     ;
    IF NOT FOUND THEN RAISE EXCEPTION 'Invalid API-key usage authorization' USING ERRCODE='28000'; END IF;
    v_start:=pg_catalog.date_trunc('month',v_now AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
    v_end:=v_start+interval '1 month';
    SELECT COALESCE(pg_catalog.sum(e.units),0)::bigint INTO v_used
      FROM public.jas_si_usage_events e
     WHERE e.tenant_id=v_tenant_id AND e.occurred_at>=v_start AND e.occurred_at<v_end;
    RETURN QUERY SELECT 'utc_calendar_month'::text,v_start,v_end,p_monthly_limit,
        v_used,CASE WHEN p_monthly_limit>v_used THEN p_monthly_limit-v_used ELSE 0 END,v_used>=p_monthly_limit;
END;
$function$;

CREATE OR REPLACE FUNCTION public.jas_si_api_key_usage_summary(
    p_key_id uuid,p_candidate_digest bytea,p_required_scope text,p_since timestamptz
) RETURNS TABLE(
    operation text,event_count bigint,total_units bigint,last_recorded_at timestamptz
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE v_tenant_id uuid; v_now timestamptz:=pg_catalog.clock_timestamp();
BEGIN
    IF p_key_id IS NULL OR p_candidate_digest IS NULL
       OR pg_catalog.octet_length(p_candidate_digest)<>32
       OR p_required_scope IS DISTINCT FROM 'usage:read' OR p_since IS NULL THEN
        RAISE EXCEPTION 'Invalid API-key usage summary request' USING ERRCODE='22023';
    END IF;
    SELECT k.tenant_id INTO v_tenant_id
      FROM public.jas_si_api_keys k JOIN public.jas_si_tenants t ON t.tenant_id=k.tenant_id
     WHERE k.key_id=p_key_id AND k.secret_digest=p_candidate_digest
       AND k.pepper_version=1 AND k.status='active'
       AND (k.expires_at IS NULL OR k.expires_at>v_now)
       AND t.status='active' AND p_required_scope=ANY(k.scopes)
     ;
    IF NOT FOUND THEN RAISE EXCEPTION 'Invalid API-key usage authorization' USING ERRCODE='28000'; END IF;
    RETURN QUERY
    SELECT e.operation::text,pg_catalog.count(*)::bigint,
           COALESCE(pg_catalog.sum(e.units),0)::bigint,pg_catalog.max(e.occurred_at)
      FROM public.jas_si_usage_events e
     WHERE e.tenant_id=v_tenant_id AND e.occurred_at>=p_since
     GROUP BY e.operation ORDER BY e.operation;
END;
$function$;

CREATE OR REPLACE FUNCTION public.jas_si_api_key_usage_events(
    p_key_id uuid,p_candidate_digest bytea,p_required_scope text,
    p_limit integer,p_before timestamptz,p_before_event_id uuid
) RETURNS TABLE(
    event_id uuid,request_id varchar,operation varchar,units bigint,occurred_at timestamptz
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE v_tenant_id uuid; v_now timestamptz:=pg_catalog.clock_timestamp();
BEGIN
    IF p_key_id IS NULL OR p_candidate_digest IS NULL
       OR pg_catalog.octet_length(p_candidate_digest)<>32
       OR p_required_scope IS DISTINCT FROM 'usage:read'
       OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100
       OR ((p_before IS NULL)<>(p_before_event_id IS NULL)) THEN
        RAISE EXCEPTION 'Invalid API-key usage history request' USING ERRCODE='22023';
    END IF;
    SELECT k.tenant_id INTO v_tenant_id
      FROM public.jas_si_api_keys k JOIN public.jas_si_tenants t ON t.tenant_id=k.tenant_id
     WHERE k.key_id=p_key_id AND k.secret_digest=p_candidate_digest
       AND k.pepper_version=1 AND k.status='active'
       AND (k.expires_at IS NULL OR k.expires_at>v_now)
       AND t.status='active' AND p_required_scope=ANY(k.scopes)
     ;
    IF NOT FOUND THEN RAISE EXCEPTION 'Invalid API-key usage authorization' USING ERRCODE='28000'; END IF;
    IF p_before IS NULL THEN
        RETURN QUERY SELECT e.event_id,e.request_id,e.operation,e.units,e.occurred_at
          FROM public.jas_si_usage_events e WHERE e.tenant_id=v_tenant_id
         ORDER BY e.occurred_at DESC,e.event_id DESC LIMIT p_limit+1;
    ELSE
        RETURN QUERY SELECT e.event_id,e.request_id,e.operation,e.units,e.occurred_at
          FROM public.jas_si_usage_events e WHERE e.tenant_id=v_tenant_id
           AND (e.occurred_at,e.event_id)<(p_before,p_before_event_id)
         ORDER BY e.occurred_at DESC,e.event_id DESC LIMIT p_limit+1;
    END IF;
END;
$function$;

GRANT CREATE ON SCHEMA public TO jas_si_api_key_usage_owner;
ALTER FUNCTION public.jas_si_api_key_usage_reserve(uuid,bytea,text,text,text,text,text,bigint,bigint)
    OWNER TO jas_si_api_key_usage_owner;
ALTER FUNCTION public.jas_si_api_key_usage_quota(uuid,bytea,text,bigint)
    OWNER TO jas_si_api_key_usage_owner;
ALTER FUNCTION public.jas_si_api_key_usage_summary(uuid,bytea,text,timestamptz)
    OWNER TO jas_si_api_key_usage_owner;
ALTER FUNCTION public.jas_si_api_key_usage_events(uuid,bytea,text,integer,timestamptz,uuid)
    OWNER TO jas_si_api_key_usage_owner;
REVOKE CREATE ON SCHEMA public FROM jas_si_api_key_usage_owner;

REVOKE ALL ON FUNCTION public.jas_si_api_key_usage_reserve(uuid,bytea,text,text,text,text,text,bigint,bigint) FROM PUBLIC,jas_si_runtime;
REVOKE ALL ON FUNCTION public.jas_si_api_key_usage_quota(uuid,bytea,text,bigint) FROM PUBLIC,jas_si_runtime;
REVOKE ALL ON FUNCTION public.jas_si_api_key_usage_summary(uuid,bytea,text,timestamptz) FROM PUBLIC,jas_si_runtime;
REVOKE ALL ON FUNCTION public.jas_si_api_key_usage_events(uuid,bytea,text,integer,timestamptz,uuid) FROM PUBLIC,jas_si_runtime;
GRANT EXECUTE ON FUNCTION public.jas_si_api_key_usage_reserve(uuid,bytea,text,text,text,text,text,bigint,bigint) TO jas_si_runtime;
GRANT EXECUTE ON FUNCTION public.jas_si_api_key_usage_quota(uuid,bytea,text,bigint) TO jas_si_runtime;
GRANT EXECUTE ON FUNCTION public.jas_si_api_key_usage_summary(uuid,bytea,text,timestamptz) TO jas_si_runtime;
GRANT EXECUTE ON FUNCTION public.jas_si_api_key_usage_events(uuid,bytea,text,integer,timestamptz,uuid) TO jas_si_runtime;
