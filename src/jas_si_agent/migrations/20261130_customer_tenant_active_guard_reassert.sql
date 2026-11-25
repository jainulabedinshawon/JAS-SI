-- Restore the production tenant-status boundary on customer identity and usage routines.
-- CREATE OR REPLACE preserves existing function ownership and ACLs.
-- These routines are owned by the dedicated NOLOGIN identity owner.
-- Reassert their bodies under that owner; neondb_owner has SET-only membership.
-- CREATE OR REPLACE requires CREATE on the containing schema. Grant it only
-- for this migration window and revoke it immediately after the owner switch.
GRANT CREATE ON SCHEMA public TO jas_si_customer_identity_owner;
SET LOCAL ROLE jas_si_customer_identity_owner;

CREATE OR REPLACE FUNCTION public.customer_authenticate_session(p_session_digest bytea)
RETURNS TABLE(account_id uuid, tenant_id uuid, email text, organization_name text, status text)
LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
AS $function$
    SELECT a.account_id,a.tenant_id,a.email::text,a.organization_name::text,a.status::text
    FROM public.jas_si_customer_sessions s
    JOIN public.jas_si_customer_accounts a ON a.account_id=s.account_id
    JOIN public.jas_si_tenants t ON t.tenant_id=a.tenant_id
    WHERE p_session_digest IS NOT NULL AND pg_catalog.octet_length(p_session_digest)=32
      AND s.token_digest=p_session_digest AND s.revoked_at IS NULL
      AND s.expires_at > pg_catalog.clock_timestamp()
      AND a.status='active' AND t.status='active'
    FOR SHARE OF s,a,t
$function$;

CREATE OR REPLACE FUNCTION public.customer_consume_link(
    p_token_digest bytea,p_purpose text,p_session_id uuid,
    p_session_digest bytea,p_session_expires_at timestamptz
)
RETURNS TABLE(account_id uuid,tenant_id uuid,email text,organization_name text,status text,session_expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO 'pg_catalog'
AS $function$
DECLARE
    v_token public.jas_si_customer_auth_tokens%ROWTYPE;
    v_account public.jas_si_customer_accounts%ROWTYPE;
    v_consumed_at timestamptz := pg_catalog.clock_timestamp();
BEGIN
    IF p_purpose NOT IN ('verify_email','login') OR p_token_digest IS NULL
       OR pg_catalog.octet_length(p_token_digest) <> 32 THEN RETURN; END IF;
    SELECT t.* INTO v_token FROM public.jas_si_customer_auth_tokens t
    WHERE t.token_digest=p_token_digest AND t.purpose=p_purpose
      AND t.consumed_at IS NULL AND t.expires_at > v_consumed_at FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    SELECT a.* INTO v_account
    FROM public.jas_si_customer_accounts a
    JOIN public.jas_si_tenants tenant
      ON tenant.tenant_id=a.tenant_id AND tenant.status='active'
    WHERE a.account_id=v_token.account_id
    FOR UPDATE OF a FOR SHARE OF tenant;
    IF NOT FOUND OR v_account.status='suspended' THEN RETURN; END IF;
    IF p_purpose='verify_email' THEN
        IF v_account.status <> 'pending' OR v_account.email_verified_at IS NOT NULL THEN RETURN; END IF;
        UPDATE public.jas_si_customer_accounts AS a SET status='active',
            email_verified_at=v_consumed_at,updated_at=v_consumed_at
        WHERE a.account_id=v_account.account_id;
        v_account.status := 'active';
    ELSE
        IF v_account.status <> 'active' OR v_account.email_verified_at IS NULL
           OR p_session_id IS NULL OR p_session_digest IS NULL
           OR pg_catalog.octet_length(p_session_digest) <> 32
           OR p_session_expires_at IS NULL OR p_session_expires_at <= v_consumed_at THEN RETURN; END IF;
        INSERT INTO public.jas_si_customer_sessions(session_id,account_id,token_digest,expires_at)
        VALUES(p_session_id,v_account.account_id,p_session_digest,p_session_expires_at);
    END IF;
    UPDATE public.jas_si_customer_auth_tokens AS t
       SET consumed_at=v_consumed_at WHERE t.token_id=v_token.token_id;
    RETURN QUERY SELECT v_account.account_id,v_account.tenant_id,v_account.email::text,
        v_account.organization_name::text,v_account.status::text,
        CASE WHEN p_purpose='login' THEN p_session_expires_at ELSE NULL::timestamptz END;
END;
$function$;

CREATE OR REPLACE FUNCTION public.customer_issue_link(
    p_email_normalized text,p_purpose text,p_token_id uuid,p_token_digest bytea,p_expires_at timestamptz
)
RETURNS TABLE(account_id uuid,email_normalized text,organization_name text,status text,expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO 'pg_catalog'
AS $function$
DECLARE v_account public.jas_si_customer_accounts%ROWTYPE;
BEGIN
    IF p_purpose NOT IN ('verify_email','login') OR p_token_digest IS NULL
       OR pg_catalog.octet_length(p_token_digest) <> 32
       OR p_expires_at <= pg_catalog.clock_timestamp() THEN
        RAISE EXCEPTION 'Invalid customer link input' USING ERRCODE='22023';
    END IF;
    SELECT a.* INTO v_account
    FROM public.jas_si_customer_accounts a
    JOIN public.jas_si_tenants tenant
      ON tenant.tenant_id=a.tenant_id AND tenant.status='active'
    WHERE a.email_normalized=p_email_normalized AND
        ((p_purpose='verify_email' AND a.status='pending') OR
         (p_purpose='login' AND a.status='active'))
    FOR UPDATE OF a FOR SHARE OF tenant;
    IF NOT FOUND THEN RETURN; END IF;
    INSERT INTO public.jas_si_customer_auth_tokens(token_id,account_id,token_digest,purpose,expires_at)
    VALUES(p_token_id,v_account.account_id,p_token_digest,p_purpose,p_expires_at);
    RETURN QUERY SELECT v_account.account_id,v_account.email_normalized::text,
        v_account.organization_name::text,v_account.status::text,p_expires_at;
END;
$function$;

CREATE OR REPLACE FUNCTION public.customer_usage_events(
    p_session_digest bytea,p_limit integer,p_before timestamptz,p_before_event_id uuid
)
RETURNS TABLE(event_id uuid,request_id varchar,operation varchar,units bigint,occurred_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO 'pg_catalog'
AS $function$
DECLARE v_tenant_id uuid; v_now timestamptz:=pg_catalog.clock_timestamp();
BEGIN
    IF p_session_digest IS NULL OR pg_catalog.octet_length(p_session_digest)<>32
       OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100
       OR ((p_before IS NULL)<>(p_before_event_id IS NULL)) THEN
        RAISE EXCEPTION 'Invalid customer usage history request' USING ERRCODE='22023';
    END IF;
    SELECT a.tenant_id INTO v_tenant_id
    FROM public.jas_si_customer_sessions s
    JOIN public.jas_si_customer_accounts a ON a.account_id=s.account_id
    JOIN public.jas_si_tenants t ON t.tenant_id=a.tenant_id
    WHERE s.token_digest=p_session_digest AND s.revoked_at IS NULL
      AND s.expires_at>v_now AND a.status='active' AND t.status='active'
    FOR SHARE OF s,a,t;
    IF NOT FOUND THEN RAISE EXCEPTION 'Invalid customer session' USING ERRCODE='28000'; END IF;
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

CREATE OR REPLACE FUNCTION public.customer_usage_summary(p_session_digest bytea,p_since timestamptz)
RETURNS TABLE(tenant_id uuid,total_units bigint,event_count bigint,by_operation jsonb,current_month_units bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO 'pg_catalog'
AS $function$
DECLARE v_tenant_id uuid; v_now timestamptz:=pg_catalog.clock_timestamp(); v_month_start timestamptz;
BEGIN
    IF p_session_digest IS NULL OR pg_catalog.octet_length(p_session_digest)<>32 OR p_since IS NULL THEN
        RAISE EXCEPTION 'Invalid customer usage request' USING ERRCODE='22023';
    END IF;
    SELECT a.tenant_id INTO v_tenant_id
    FROM public.jas_si_customer_sessions s
    JOIN public.jas_si_customer_accounts a ON a.account_id=s.account_id
    JOIN public.jas_si_tenants t ON t.tenant_id=a.tenant_id
    WHERE s.token_digest=p_session_digest AND s.revoked_at IS NULL
      AND s.expires_at>v_now AND a.status='active' AND t.status='active'
    FOR SHARE OF s,a,t;
    IF NOT FOUND THEN RAISE EXCEPTION 'Invalid customer session' USING ERRCODE='28000'; END IF;
    v_month_start:=pg_catalog.date_trunc('month',v_now AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
    RETURN QUERY SELECT v_tenant_id,
      COALESCE((SELECT pg_catalog.sum(e.units) FROM public.jas_si_usage_events e WHERE e.tenant_id=v_tenant_id AND e.occurred_at>=p_since),0)::bigint,
      COALESCE((SELECT pg_catalog.count(*) FROM public.jas_si_usage_events e WHERE e.tenant_id=v_tenant_id AND e.occurred_at>=p_since),0)::bigint,
      COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'operation',g.operation,'events',g.event_count,'units',g.total_units,'last_recorded_at',g.last_recorded_at
      ) ORDER BY g.operation) FROM (
        SELECT e.operation,pg_catalog.count(*) AS event_count,pg_catalog.sum(e.units) AS total_units,
          pg_catalog.max(e.occurred_at) AS last_recorded_at
        FROM public.jas_si_usage_events e WHERE e.tenant_id=v_tenant_id AND e.occurred_at>=p_since
        GROUP BY e.operation
      ) g),'[]'::jsonb),
      COALESCE((SELECT pg_catalog.sum(e.units) FROM public.jas_si_usage_events e
        WHERE e.tenant_id=v_tenant_id AND e.occurred_at>=v_month_start),0)::bigint;
END;
$function$;

RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_customer_identity_owner;

DO $assert$
DECLARE v_name text; v_def text;
BEGIN
  FOREACH v_name IN ARRAY ARRAY[
    'customer_authenticate_session','customer_consume_link','customer_issue_link',
    'customer_usage_events','customer_usage_summary'
  ] LOOP
    SELECT pg_catalog.pg_get_functiondef(p.oid) INTO v_def
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND p.proname=v_name;
    IF v_def IS NULL OR v_def NOT ILIKE '%jas_si_tenants%'
       OR v_def NOT ILIKE '%status%active%' THEN
      RAISE EXCEPTION 'Tenant active-status guard missing in %',v_name;
    END IF;
  END LOOP;
END;
$assert$;
