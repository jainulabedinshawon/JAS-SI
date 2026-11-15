-- Extend the database-owned customer API-key issuance allowlist for durable agent tasks.
-- This keeps Python validation and the authoritative PostgreSQL boundary aligned.
-- The function owner and runtime-only EXECUTE grant are preserved explicitly.

GRANT CREATE ON SCHEMA public TO jas_si_customer_key_owner;
SET LOCAL ROLE jas_si_customer_key_owner;

CREATE OR REPLACE FUNCTION public.customer_api_key_issue(
    p_session_digest bytea,p_key_id uuid,p_key_name text,p_key_prefix text,
    p_secret_digest bytea,p_pepper_version smallint,p_scopes text[],
    p_expires_at_text text,p_run_id text
) RETURNS TABLE(key_id uuid,key_prefix text,expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE
    v_account_id uuid; v_tenant_id uuid; v_expires_at timestamptz;
    v_scope_count integer; v_creator text;
BEGIN
    IF p_session_digest IS NULL OR pg_catalog.octet_length(p_session_digest)<>32 THEN
        RAISE EXCEPTION 'Invalid customer session' USING ERRCODE='28000';
    END IF;
    IF p_key_id IS NULL OR p_key_name IS NULL OR pg_catalog.length(pg_catalog.btrim(p_key_name)) NOT BETWEEN 1 AND 120
       OR p_key_prefix IS NULL OR p_key_prefix<>'jassi_live_'||pg_catalog.replace(p_key_id::text,'-','')
       OR p_secret_digest IS NULL OR pg_catalog.octet_length(p_secret_digest)<>32
       OR p_pepper_version IS DISTINCT FROM 1 OR p_scopes IS NULL
       OR pg_catalog.array_position(p_scopes,NULL) IS NOT NULL
       OR pg_catalog.cardinality(p_scopes) NOT BETWEEN 1 AND 6
       OR NOT (p_scopes <@ ARRAY[
           'authorization:check','outcomes:submit','github:evidence:verify',
           'usage:read','agent:tasks:read','agent:tasks:write'
       ]::text[])
       OR p_run_id IS NULL OR p_run_id !~ '^[A-Za-z0-9._:-]{1,128}$' THEN
        RAISE EXCEPTION 'Invalid customer API-key request' USING ERRCODE='22023';
    END IF;
    SELECT pg_catalog.count(DISTINCT s.scope) INTO v_scope_count
      FROM pg_catalog.unnest(p_scopes) AS s(scope);
    IF v_scope_count<>pg_catalog.cardinality(p_scopes) THEN
        RAISE EXCEPTION 'Duplicate API-key scopes are not allowed' USING ERRCODE='22023';
    END IF;
    IF p_expires_at_text IS NOT NULL THEN
        v_expires_at := p_expires_at_text::timestamptz;
        IF v_expires_at<=pg_catalog.clock_timestamp()
           OR v_expires_at>pg_catalog.clock_timestamp()+interval '365 days' THEN
            RAISE EXCEPTION 'Invalid API-key expiry' USING ERRCODE='22023';
        END IF;
    END IF;
    SELECT a.account_id,a.tenant_id INTO v_account_id,v_tenant_id
      FROM public.jas_si_customer_sessions s
      JOIN public.jas_si_customer_accounts a ON a.account_id=s.account_id
      JOIN public.jas_si_tenants t ON t.tenant_id=a.tenant_id
     WHERE s.token_digest=p_session_digest AND s.revoked_at IS NULL
       AND s.expires_at>pg_catalog.clock_timestamp()
       AND a.status='active' AND t.status='active'
     FOR SHARE OF s,a,t;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Invalid customer session' USING ERRCODE='28000';
    END IF;
    v_creator := 'customer:'||v_account_id::text;
    INSERT INTO public.jas_si_api_keys
        (key_id,tenant_id,key_name,key_prefix,secret_digest,pepper_version,
         scopes,created_by,expires_at)
    VALUES
        (p_key_id,v_tenant_id,p_key_name,p_key_prefix,p_secret_digest,
         p_pepper_version,p_scopes,v_creator,v_expires_at);
    INSERT INTO public.jas_si_api_key_provisioning_runs(run_id,key_id,tenant_id)
    VALUES(p_run_id,p_key_id,v_tenant_id);
    PERFORM public.jas_si_customer_key_append_audit(pg_catalog.jsonb_build_object(
        'event_type','api_key_issued','tenant_id',v_tenant_id::text,
        'key_id',p_key_id::text,'key_name',p_key_name,'scopes',p_scopes,
        'expires_at',p_expires_at_text,'operator_id',v_creator,
        'provisioning_run_id',p_run_id));
    RETURN QUERY SELECT p_key_id,p_key_prefix,v_expires_at;
END;
$function$;

REVOKE ALL ON FUNCTION public.customer_api_key_issue(bytea,uuid,text,text,bytea,smallint,text[],text,text)
    FROM PUBLIC,jas_si_customer_key_runtime;
GRANT EXECUTE ON FUNCTION public.customer_api_key_issue(bytea,uuid,text,text,bytea,smallint,text[],text,text)
    TO jas_si_customer_key_runtime;

RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_customer_key_owner;

DO $block$
DECLARE v_proc oid;
BEGIN
    SELECT p.oid INTO v_proc
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
     WHERE n.nspname='public'
       AND p.proname='customer_api_key_issue'
       AND p.oid='public.customer_api_key_issue(bytea,uuid,text,text,bytea,smallint,text[],text,text)'::regprocedure;
    IF v_proc IS NULL
       OR pg_catalog.pg_get_userbyid((SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.oid=v_proc))
          <> 'jas_si_customer_key_owner'
       OR NOT (SELECT p.prosecdef FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
       OR NOT (
           COALESCE(
               (SELECT p.proconfig FROM pg_catalog.pg_proc p WHERE p.oid=v_proc),
               ARRAY[]::text[]
           ) @> ARRAY['search_path=pg_catalog']::text[]
       )
       OR NOT pg_catalog.has_function_privilege(
           'jas_si_customer_key_runtime',v_proc,'EXECUTE'
       )
       OR EXISTS (
           SELECT 1 FROM pg_catalog.aclexplode(
               COALESCE((SELECT p.proacl FROM pg_catalog.pg_proc p WHERE p.oid=v_proc),
                        pg_catalog.acldefault('f',(SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)))
           ) acl
           WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'
       ) THEN
        RAISE EXCEPTION 'Customer API-key issue routine security boundary is invalid';
    END IF;
END
$block$;
