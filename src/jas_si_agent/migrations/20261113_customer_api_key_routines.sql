-- Database-owned customer API-key lifecycle. Apply after migrations 007 and 20261112_customer_identity_routines.sql.
-- Customer sessions are revalidated here; no caller-supplied tenant ID or GUC is trusted.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_extension WHERE extname='pgcrypto') THEN
        EXECUTE 'CREATE EXTENSION pgcrypto';
    END IF;
END
$$;

DO $$
DECLARE v_oid oid; v_role record;
BEGIN
    SELECT oid INTO v_oid FROM pg_catalog.pg_roles WHERE rolname='jas_si_customer_key_owner';
    IF v_oid IS NULL THEN
        CREATE ROLE jas_si_customer_key_owner NOLOGIN NOSUPERUSER NOCREATEDB
            NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
        SELECT oid INTO v_oid FROM pg_catalog.pg_roles WHERE rolname='jas_si_customer_key_owner';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='neondb_owner') THEN
        EXECUTE 'GRANT jas_si_customer_key_owner TO neondb_owner WITH ADMIN FALSE, INHERIT FALSE, SET TRUE';
    END IF;
    SELECT * INTO v_role FROM pg_catalog.pg_roles WHERE oid=v_oid;
    IF v_role.rolcanlogin OR v_role.rolsuper OR v_role.rolcreatedb
       OR v_role.rolcreaterole OR v_role.rolreplication OR v_role.rolbypassrls
       OR v_role.rolinherit
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
                  JOIN pg_catalog.pg_roles platform_member ON platform_member.oid=m.member
                  JOIN pg_catalog.pg_roles membership_grantor ON membership_grantor.oid=m.grantor
                  WHERE m.member=v_oid OR (m.roleid=v_oid AND NOT (
                      ((platform_member.rolname='neondb_owner' AND NOT m.admin_option
                      AND NOT m.inherit_option AND m.set_option) OR (platform_member.rolname='neondb_owner' AND membership_grantor.rolname='neondb_owner' AND membership_grantor.rolname='cloud_admin'
                      AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option))))) THEN
        RAISE EXCEPTION 'Unsafe customer API-key owner role configuration';
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO jas_si_customer_key_owner, jas_si_customer_key_runtime;
DO $body$
DECLARE v_schema text;
BEGIN
    SELECT n.nspname INTO v_schema
    FROM pg_catalog.pg_extension e
    JOIN pg_catalog.pg_namespace n ON n.oid=e.extnamespace
    WHERE e.extname='pgcrypto';
    IF v_schema IS NULL THEN
        RAISE EXCEPTION 'pgcrypto extension is not installed';
    END IF;
    EXECUTE pg_catalog.format('GRANT USAGE ON SCHEMA %I TO jas_si_customer_key_owner',v_schema);
END
$body$;
REVOKE CREATE ON SCHEMA public FROM jas_si_customer_key_runtime;

-- The SECURITY DEFINER owner receives only the columns and tables needed by its routines.
GRANT SELECT (tenant_id,status) ON public.jas_si_tenants TO jas_si_customer_key_owner;
GRANT UPDATE (provisioning_lock_version) ON public.jas_si_tenants TO jas_si_customer_key_owner;
GRANT SELECT (account_id,tenant_id,status) ON public.jas_si_customer_accounts TO jas_si_customer_key_owner;
GRANT UPDATE (updated_at) ON public.jas_si_customer_accounts TO jas_si_customer_key_owner;
GRANT SELECT (account_id,token_digest,expires_at,revoked_at) ON public.jas_si_customer_sessions TO jas_si_customer_key_owner;
GRANT UPDATE (revoked_at) ON public.jas_si_customer_sessions TO jas_si_customer_key_owner;
GRANT SELECT,INSERT ON public.jas_si_api_keys TO jas_si_customer_key_owner;
GRANT UPDATE (status,revoked_at) ON public.jas_si_api_keys TO jas_si_customer_key_owner;
GRANT INSERT (run_id,key_id,tenant_id) ON public.jas_si_api_key_provisioning_runs TO jas_si_customer_key_owner;
GRANT INSERT (singleton,last_hash), SELECT (singleton,last_hash), UPDATE (last_hash)
    ON public.jas_si_audit_chain_state TO jas_si_customer_key_owner;
GRANT SELECT (event_id,event_payload,previous_hash,event_hash),
      INSERT (event_payload,previous_hash,event_hash)
    ON public.jas_si_audit_events TO jas_si_customer_key_owner;

-- RLS remains enabled; the non-login function owner receives narrowly scoped policies.
DROP POLICY IF EXISTS jas_si_tenants_customer_key_owner_read ON public.jas_si_tenants;
CREATE POLICY jas_si_tenants_customer_key_owner_read ON public.jas_si_tenants
    FOR ALL TO jas_si_customer_key_owner USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS jas_si_api_keys_customer_key_owner ON public.jas_si_api_keys;
CREATE POLICY jas_si_api_keys_customer_key_owner ON public.jas_si_api_keys
    FOR ALL TO jas_si_customer_key_owner USING (true) WITH CHECK (true);

-- Remove all direct table and column access previously granted to the customer runtime.
DO $$
DECLARE v_table text; v_column text;
BEGIN
    FOREACH v_table IN ARRAY ARRAY[
        'jas_si_tenants','jas_si_api_keys','jas_si_api_key_provisioning_runs',
        'jas_si_audit_chain_state','jas_si_audit_events',
        'jas_si_customer_accounts','jas_si_customer_auth_tokens','jas_si_customer_sessions'
    ] LOOP
        EXECUTE pg_catalog.format('REVOKE ALL PRIVILEGES ON TABLE public.%I FROM jas_si_customer_key_runtime',v_table);
        FOR v_column IN
            SELECT a.attname FROM pg_catalog.pg_attribute a
            WHERE a.attrelid=pg_catalog.to_regclass('public.'||v_table)
              AND a.attnum>0 AND NOT a.attisdropped
        LOOP
            EXECUTE pg_catalog.format('REVOKE ALL PRIVILEGES (%I) ON TABLE public.%I FROM jas_si_customer_key_runtime',v_column,v_table);
        END LOOP;
    END LOOP;
END
$$;

CREATE OR REPLACE FUNCTION public.jas_si_customer_key_canonical_jsonb(p_value jsonb)
RETURNS text LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog AS $function$
DECLARE v_kind text; v_result text;
BEGIN
    v_kind := pg_catalog.jsonb_typeof(p_value);
    IF v_kind='object' THEN
        SELECT '{'||COALESCE(pg_catalog.string_agg(
            pg_catalog.to_jsonb(e.key)::text||':'||public.jas_si_customer_key_canonical_jsonb(e.value),
            ',' ORDER BY e.key COLLATE "C"),'')||'}'
          INTO v_result FROM pg_catalog.jsonb_each(p_value) AS e(key,value);
        RETURN v_result;
    ELSIF v_kind='array' THEN
        SELECT '['||COALESCE(pg_catalog.string_agg(
            public.jas_si_customer_key_canonical_jsonb(e.value),',' ORDER BY e.ordinality),'')||']'
          INTO v_result FROM pg_catalog.jsonb_array_elements(p_value) WITH ORDINALITY AS e(value,ordinality);
        RETURN v_result;
    END IF;
    RETURN p_value::text;
END;
$function$;

CREATE OR REPLACE FUNCTION public.jas_si_customer_key_sha256(p_material bytea)
RETURNS text LANGUAGE plpgsql STABLE STRICT SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE v_schema text; v_hash bytea;
BEGIN
    SELECT n.nspname INTO v_schema FROM pg_catalog.pg_extension e
    JOIN pg_catalog.pg_namespace n ON n.oid=e.extnamespace WHERE e.extname='pgcrypto';
    IF v_schema IS NULL THEN RAISE EXCEPTION 'pgcrypto is required for audit integrity'; END IF;
    EXECUTE pg_catalog.format('SELECT %I.digest($1, %L)',v_schema,'sha256')
       INTO v_hash USING p_material;
    RETURN pg_catalog.encode(v_hash,'hex');
END;
$function$;

CREATE OR REPLACE FUNCTION public.jas_si_customer_key_append_audit(p_event jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE
    v_checkpoint text; v_previous text := pg_catalog.repeat('0',64);
    v_expected text; v_material bytea; v_row record;
BEGIN
    IF p_event IS NULL OR pg_catalog.jsonb_typeof(p_event)<>'object' THEN
        RAISE EXCEPTION 'Audit event must be a JSON object';
    END IF;
    IF pg_catalog.octet_length(pg_catalog.convert_to(
        public.jas_si_customer_key_canonical_jsonb(p_event),'UTF8'))+1024 > 65536 THEN
        RAISE EXCEPTION 'Security event exceeds 64 KiB';
    END IF;
    INSERT INTO public.jas_si_audit_chain_state(singleton,last_hash)
    VALUES(TRUE,pg_catalog.repeat('0',64)) ON CONFLICT(singleton) DO NOTHING;
    SELECT s.last_hash::text INTO v_checkpoint
      FROM public.jas_si_audit_chain_state s WHERE s.singleton=TRUE FOR UPDATE;
    IF v_checkpoint IS NULL OR v_checkpoint !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'Invalid audit checkpoint';
    END IF;
    FOR v_row IN
        SELECT e.event_payload,e.previous_hash::text AS previous_hash,e.event_hash::text AS event_hash
        FROM public.jas_si_audit_events e ORDER BY e.event_id ASC
    LOOP
        IF v_row.previous_hash<>v_previous THEN
            RAISE EXCEPTION 'Audit chain link mismatch';
        END IF;
        v_material := pg_catalog.convert_to(
            '{"event":'||public.jas_si_customer_key_canonical_jsonb(v_row.event_payload)||
            ',"previous_hash":'||pg_catalog.to_jsonb(v_previous)::text||'}','UTF8');
        v_expected := public.jas_si_customer_key_sha256(v_material);
        IF v_row.event_hash<>v_expected THEN RAISE EXCEPTION 'Audit event hash mismatch'; END IF;
        v_previous := v_row.event_hash;
    END LOOP;
    IF v_checkpoint<>v_previous THEN RAISE EXCEPTION 'Audit checkpoint does not match verified chain'; END IF;
    v_material := pg_catalog.convert_to(
        '{"event":'||public.jas_si_customer_key_canonical_jsonb(p_event)||
        ',"previous_hash":'||pg_catalog.to_jsonb(v_previous)::text||'}','UTF8');
    v_expected := public.jas_si_customer_key_sha256(v_material);
    INSERT INTO public.jas_si_audit_events(event_payload,previous_hash,event_hash)
        VALUES(p_event,v_previous,v_expected);
    UPDATE public.jas_si_audit_chain_state SET last_hash=v_expected WHERE singleton=TRUE;
END;
$function$;

CREATE OR REPLACE FUNCTION public.customer_api_key_list(p_session_digest bytea)
RETURNS TABLE(key_id uuid,key_name text,key_prefix text,scopes text[],status text,
    created_at timestamptz,expires_at timestamptz,last_used_at timestamptz,revoked_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE v_account_id uuid; v_tenant_id uuid;
BEGIN
    IF p_session_digest IS NULL OR pg_catalog.octet_length(p_session_digest)<>32 THEN
        RAISE EXCEPTION 'Invalid customer session' USING ERRCODE='28000';
    END IF;
    SELECT a.account_id,a.tenant_id INTO v_account_id,v_tenant_id
    FROM public.jas_si_customer_sessions s
    JOIN public.jas_si_customer_accounts a ON a.account_id=s.account_id
    JOIN public.jas_si_tenants t ON t.tenant_id=a.tenant_id
    WHERE s.token_digest=p_session_digest AND s.revoked_at IS NULL
      AND s.expires_at>pg_catalog.clock_timestamp() AND a.status='active' AND t.status='active'
    FOR SHARE OF s,a,t;
    IF NOT FOUND THEN RAISE EXCEPTION 'Invalid customer session' USING ERRCODE='28000'; END IF;
    RETURN QUERY SELECT k.key_id,k.key_name::text,k.key_prefix::text,k.scopes,
        k.status::text,k.created_at,k.expires_at,k.last_used_at,k.revoked_at
    FROM public.jas_si_api_keys k WHERE k.tenant_id=v_tenant_id
    ORDER BY k.created_at DESC,k.key_id;
END;
$function$;

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
       OR pg_catalog.cardinality(p_scopes) NOT BETWEEN 1 AND 4
       OR NOT (p_scopes <@ ARRAY['authorization:check','outcomes:submit','github:evidence:verify','usage:read']::text[])
       OR p_run_id IS NULL OR p_run_id !~ '^[A-Za-z0-9._:-]{1,128}$' THEN
        RAISE EXCEPTION 'Invalid customer API-key request' USING ERRCODE='22023';
    END IF;
    SELECT pg_catalog.count(DISTINCT s.scope) INTO v_scope_count FROM pg_catalog.unnest(p_scopes) AS s(scope);
    IF v_scope_count<>pg_catalog.cardinality(p_scopes) THEN
        RAISE EXCEPTION 'Duplicate API-key scopes are not allowed' USING ERRCODE='22023';
    END IF;
    IF p_expires_at_text IS NOT NULL THEN
        v_expires_at := p_expires_at_text::timestamptz;
        IF v_expires_at<=pg_catalog.clock_timestamp() OR v_expires_at>pg_catalog.clock_timestamp()+interval '365 days' THEN
            RAISE EXCEPTION 'Invalid API-key expiry' USING ERRCODE='22023';
        END IF;
    END IF;
    SELECT a.account_id,a.tenant_id INTO v_account_id,v_tenant_id
    FROM public.jas_si_customer_sessions s
    JOIN public.jas_si_customer_accounts a ON a.account_id=s.account_id
    JOIN public.jas_si_tenants t ON t.tenant_id=a.tenant_id
    WHERE s.token_digest=p_session_digest AND s.revoked_at IS NULL
      AND s.expires_at>pg_catalog.clock_timestamp() AND a.status='active' AND t.status='active'
    FOR SHARE OF s,a,t;
    IF NOT FOUND THEN RAISE EXCEPTION 'Invalid customer session' USING ERRCODE='28000'; END IF;
    v_creator := 'customer:'||v_account_id::text;
    INSERT INTO public.jas_si_api_keys
        (key_id,tenant_id,key_name,key_prefix,secret_digest,pepper_version,scopes,created_by,expires_at)
    VALUES(p_key_id,v_tenant_id,p_key_name,p_key_prefix,p_secret_digest,p_pepper_version,p_scopes,v_creator,v_expires_at);
    INSERT INTO public.jas_si_api_key_provisioning_runs(run_id,key_id,tenant_id)
    VALUES(p_run_id,p_key_id,v_tenant_id);
    PERFORM public.jas_si_customer_key_append_audit(pg_catalog.jsonb_build_object(
        'event_type','api_key_issued','tenant_id',v_tenant_id::text,'key_id',p_key_id::text,
        'key_name',p_key_name,'scopes',p_scopes,'expires_at',p_expires_at_text,
        'operator_id',v_creator,'provisioning_run_id',p_run_id));
    RETURN QUERY SELECT p_key_id,p_key_prefix,v_expires_at;
END;
$function$;

CREATE OR REPLACE FUNCTION public.customer_api_key_revoke(
    p_session_digest bytea,p_key_id uuid,p_run_id text
) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE v_account_id uuid; v_tenant_id uuid; v_updated_tenant uuid; v_operator text;
BEGIN
    IF p_session_digest IS NULL OR pg_catalog.octet_length(p_session_digest)<>32
       OR p_key_id IS NULL OR p_run_id IS NULL OR p_run_id !~ '^[A-Za-z0-9._:-]{1,128}$' THEN
        RAISE EXCEPTION 'Invalid customer API-key revocation request' USING ERRCODE='22023';
    END IF;
    SELECT a.account_id,a.tenant_id INTO v_account_id,v_tenant_id
    FROM public.jas_si_customer_sessions s
    JOIN public.jas_si_customer_accounts a ON a.account_id=s.account_id
    JOIN public.jas_si_tenants t ON t.tenant_id=a.tenant_id
    WHERE s.token_digest=p_session_digest AND s.revoked_at IS NULL
      AND s.expires_at>pg_catalog.clock_timestamp() AND a.status='active' AND t.status='active'
    FOR SHARE OF s,a,t;
    IF NOT FOUND THEN RAISE EXCEPTION 'Invalid customer session' USING ERRCODE='28000'; END IF;
    UPDATE public.jas_si_api_keys k SET status='revoked',revoked_at=pg_catalog.clock_timestamp()
    WHERE k.key_id=p_key_id AND k.tenant_id=v_tenant_id AND k.status='active'
    RETURNING k.tenant_id INTO v_updated_tenant;
    IF NOT FOUND THEN RETURN false; END IF;
    v_operator := 'customer:'||v_account_id::text;
    PERFORM public.jas_si_customer_key_append_audit(pg_catalog.jsonb_build_object(
        'event_type','api_key_revoked','tenant_id',v_updated_tenant::text,
        'key_id',p_key_id::text,'operator_id',v_operator,'revocation_run_id',p_run_id));
    RETURN true;
END;
$function$;

GRANT CREATE ON SCHEMA public TO jas_si_customer_key_owner;
GRANT CREATE ON SCHEMA public TO jas_si_customer_key_owner;

ALTER FUNCTION public.jas_si_customer_key_canonical_jsonb(jsonb) OWNER TO jas_si_customer_key_owner;
ALTER FUNCTION public.jas_si_customer_key_sha256(bytea) OWNER TO jas_si_customer_key_owner;
ALTER FUNCTION public.jas_si_customer_key_append_audit(jsonb) OWNER TO jas_si_customer_key_owner;
ALTER FUNCTION public.customer_api_key_list(bytea) OWNER TO jas_si_customer_key_owner;
ALTER FUNCTION public.customer_api_key_issue(bytea,uuid,text,text,bytea,smallint,text[],text,text) OWNER TO jas_si_customer_key_owner;
ALTER FUNCTION public.customer_api_key_revoke(bytea,uuid,text) OWNER TO jas_si_customer_key_owner;
REVOKE CREATE ON SCHEMA public FROM jas_si_customer_key_owner;
REVOKE CREATE ON SCHEMA public FROM jas_si_customer_key_owner;

REVOKE ALL ON FUNCTION public.jas_si_customer_key_canonical_jsonb(jsonb) FROM PUBLIC,jas_si_customer_key_runtime;
REVOKE ALL ON FUNCTION public.jas_si_customer_key_sha256(bytea) FROM PUBLIC,jas_si_customer_key_runtime;
REVOKE ALL ON FUNCTION public.jas_si_customer_key_append_audit(jsonb) FROM PUBLIC,jas_si_customer_key_runtime;
REVOKE ALL ON FUNCTION public.customer_api_key_list(bytea) FROM PUBLIC,jas_si_customer_key_runtime;
REVOKE ALL ON FUNCTION public.customer_api_key_issue(bytea,uuid,text,text,bytea,smallint,text[],text,text) FROM PUBLIC,jas_si_customer_key_runtime;
REVOKE ALL ON FUNCTION public.customer_api_key_revoke(bytea,uuid,text) FROM PUBLIC,jas_si_customer_key_runtime;
GRANT EXECUTE ON FUNCTION public.customer_api_key_list(bytea) TO jas_si_customer_key_runtime;
GRANT EXECUTE ON FUNCTION public.customer_api_key_issue(bytea,uuid,text,text,bytea,smallint,text[],text,text) TO jas_si_customer_key_runtime;
GRANT EXECUTE ON FUNCTION public.customer_api_key_revoke(bytea,uuid,text) TO jas_si_customer_key_runtime;
