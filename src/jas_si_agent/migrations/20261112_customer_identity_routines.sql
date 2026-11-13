-- Database-owned customer identity boundary. Apply after the base identity migration
-- and customer API-key self-service migration (007).
DO $$
DECLARE
    v_owner_oid oid;
    v_role record;
    v_table text;
    v_column text;
BEGIN
    SELECT oid INTO v_owner_oid FROM pg_catalog.pg_roles
    WHERE rolname = 'jas_si_customer_identity_owner';
    IF v_owner_oid IS NULL THEN
        CREATE ROLE jas_si_customer_identity_owner NOLOGIN NOSUPERUSER NOCREATEDB
            NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
        SELECT oid INTO v_owner_oid FROM pg_catalog.pg_roles
        WHERE rolname = 'jas_si_customer_identity_owner';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='neondb_owner') THEN
        EXECUTE 'GRANT jas_si_customer_identity_owner TO neondb_owner WITH ADMIN FALSE, INHERIT FALSE, SET TRUE';
    END IF;
    SELECT * INTO v_role FROM pg_catalog.pg_roles WHERE oid = v_owner_oid;
    IF v_role.rolcanlogin OR v_role.rolsuper OR v_role.rolcreatedb
       OR v_role.rolcreaterole OR v_role.rolreplication
       OR v_role.rolbypassrls OR v_role.rolinherit
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
                  JOIN pg_catalog.pg_roles platform_member ON platform_member.oid = m.member
                  JOIN pg_catalog.pg_roles membership_grantor ON membership_grantor.oid = m.grantor
                  WHERE m.member = v_owner_oid OR (m.roleid = v_owner_oid AND NOT (
                      ((platform_member.rolname = 'neondb_owner' AND NOT m.admin_option
                      AND NOT m.inherit_option AND m.set_option) OR (platform_member.rolname = 'neondb_owner' AND membership_grantor.rolname = 'cloud_admin'
                      AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option))))) THEN
        RAISE EXCEPTION 'Unsafe customer identity owner role configuration';
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO jas_si_customer_identity_owner, jas_si_customer_runtime;
GRANT INSERT (tenant_id, tenant_name) ON TABLE public.jas_si_tenants TO jas_si_customer_identity_owner;
GRANT SELECT, INSERT ON TABLE public.jas_si_customer_accounts TO jas_si_customer_identity_owner;
GRANT UPDATE (status, email_verified_at, updated_at) ON TABLE public.jas_si_customer_accounts TO jas_si_customer_identity_owner;
GRANT SELECT, INSERT ON TABLE public.jas_si_customer_auth_tokens TO jas_si_customer_identity_owner;
GRANT UPDATE (consumed_at) ON TABLE public.jas_si_customer_auth_tokens TO jas_si_customer_identity_owner;
GRANT SELECT, INSERT ON TABLE public.jas_si_customer_sessions TO jas_si_customer_identity_owner;
GRANT UPDATE (revoked_at) ON TABLE public.jas_si_customer_sessions TO jas_si_customer_identity_owner;

DROP POLICY IF EXISTS jas_si_tenants_customer_identity_owner_insert ON public.jas_si_tenants;
CREATE POLICY jas_si_tenants_customer_identity_owner_insert ON public.jas_si_tenants
    FOR INSERT TO jas_si_customer_identity_owner WITH CHECK (true);

DO $$
DECLARE
    v_table text;
    v_column text;
BEGIN
    FOREACH v_table IN ARRAY ARRAY['jas_si_tenants','jas_si_customer_accounts',
        'jas_si_customer_auth_tokens','jas_si_customer_sessions'] LOOP
        EXECUTE pg_catalog.format('REVOKE ALL PRIVILEGES ON TABLE public.%I FROM jas_si_customer_runtime', v_table);
        FOR v_column IN
            SELECT a.attname FROM pg_catalog.pg_attribute a
            WHERE a.attrelid = pg_catalog.to_regclass('public.' || v_table)
              AND a.attnum > 0 AND NOT a.attisdropped
        LOOP
            EXECUTE pg_catalog.format('REVOKE ALL PRIVILEGES (%I) ON TABLE public.%I FROM jas_si_customer_runtime', v_column, v_table);
        END LOOP;
    END LOOP;
END
$$;

CREATE OR REPLACE FUNCTION public.customer_register(
    p_email text, p_email_normalized text, p_organization_name text,
    p_account_id uuid, p_tenant_id uuid, p_token_id uuid,
    p_token_digest bytea, p_expires_at timestamptz
) RETURNS TABLE(account_id uuid, tenant_id uuid, email text,
    organization_name text, status text, expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $function$
BEGIN
    IF p_email IS NULL OR p_email_normalized IS NULL
       OR p_email_normalized <> pg_catalog.lower(pg_catalog.btrim(p_email))
       OR pg_catalog.length(p_email_normalized) > 254
       OR p_organization_name IS NULL
       OR pg_catalog.length(pg_catalog.btrim(p_organization_name)) NOT BETWEEN 1 AND 160
       OR p_token_digest IS NULL OR pg_catalog.octet_length(p_token_digest) <> 32
       OR p_expires_at <= pg_catalog.clock_timestamp() THEN
        RAISE EXCEPTION 'Invalid customer registration input' USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.jas_si_tenants (tenant_id, tenant_name)
    VALUES (p_tenant_id, pg_catalog.left(p_organization_name,109) || ' [' ||
        pg_catalog.substr(pg_catalog.replace(p_tenant_id::text,'-',''),1,8) || ']');
    INSERT INTO public.jas_si_customer_accounts
        (account_id,tenant_id,email,email_normalized,organization_name)
    VALUES (p_account_id,p_tenant_id,p_email,p_email_normalized,p_organization_name);
    INSERT INTO public.jas_si_customer_auth_tokens
        (token_id,account_id,token_digest,purpose,expires_at)
    VALUES (p_token_id,p_account_id,p_token_digest,'verify_email',p_expires_at);
    RETURN QUERY SELECT p_account_id,p_tenant_id,p_email,p_organization_name,'pending'::text,p_expires_at;
END;
$function$;

CREATE OR REPLACE FUNCTION public.customer_issue_link(
    p_email_normalized text,p_purpose text,p_token_id uuid,
    p_token_digest bytea,p_expires_at timestamptz
) RETURNS TABLE(account_id uuid,email_normalized text,organization_name text,
    status text,expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $function$
DECLARE v_account public.jas_si_customer_accounts%ROWTYPE;
BEGIN
    IF p_purpose NOT IN ('verify_email','login') OR p_token_digest IS NULL
       OR pg_catalog.octet_length(p_token_digest) <> 32
       OR p_expires_at <= pg_catalog.clock_timestamp() THEN
        RAISE EXCEPTION 'Invalid customer link input' USING ERRCODE = '22023';
    END IF;
    SELECT a.* INTO v_account FROM public.jas_si_customer_accounts a
    WHERE a.email_normalized = p_email_normalized AND
        ((p_purpose='verify_email' AND a.status='pending') OR
         (p_purpose='login' AND a.status='active')) FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    INSERT INTO public.jas_si_customer_auth_tokens
        (token_id,account_id,token_digest,purpose,expires_at)
    VALUES (p_token_id,v_account.account_id,p_token_digest,p_purpose,p_expires_at);
    RETURN QUERY SELECT v_account.account_id,v_account.email_normalized::text,
        v_account.organization_name::text,v_account.status::text,p_expires_at;
END;
$function$;

CREATE OR REPLACE FUNCTION public.customer_consume_link(
    p_token_digest bytea,p_purpose text,p_session_id uuid,
    p_session_digest bytea,p_session_expires_at timestamptz
) RETURNS TABLE(account_id uuid,tenant_id uuid,email text,organization_name text,
    status text,session_expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $function$
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
    SELECT a.* INTO v_account FROM public.jas_si_customer_accounts a
    WHERE a.account_id=v_token.account_id FOR UPDATE;
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
        INSERT INTO public.jas_si_customer_sessions
            (session_id,account_id,token_digest,expires_at)
        VALUES (p_session_id,v_account.account_id,p_session_digest,p_session_expires_at);
    END IF;
    UPDATE public.jas_si_customer_auth_tokens AS t
       SET consumed_at=v_consumed_at WHERE t.token_id=v_token.token_id;
    RETURN QUERY SELECT v_account.account_id,v_account.tenant_id,v_account.email::text,
        v_account.organization_name::text,v_account.status::text,
        CASE WHEN p_purpose='login' THEN p_session_expires_at ELSE NULL::timestamptz END;
END;
$function$;

CREATE OR REPLACE FUNCTION public.customer_authenticate_session(p_session_digest bytea)
RETURNS TABLE(account_id uuid,tenant_id uuid,email text,organization_name text,status text)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog AS $function$
    SELECT a.account_id,a.tenant_id,a.email::text,a.organization_name::text,a.status::text
    FROM public.jas_si_customer_sessions s
    JOIN public.jas_si_customer_accounts a ON a.account_id=s.account_id
    WHERE p_session_digest IS NOT NULL AND pg_catalog.octet_length(p_session_digest)=32
      AND s.token_digest=p_session_digest AND s.revoked_at IS NULL
      AND s.expires_at > pg_catalog.clock_timestamp() AND a.status='active'
$function$;

CREATE OR REPLACE FUNCTION public.customer_revoke_session(p_session_digest bytea)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog AS $function$
BEGIN
    UPDATE public.jas_si_customer_sessions AS s
       SET revoked_at=pg_catalog.clock_timestamp()
     WHERE s.token_digest=p_session_digest AND s.revoked_at IS NULL;
    RETURN FOUND;
END;
$function$;

ALTER FUNCTION public.customer_register(text,text,text,uuid,uuid,uuid,bytea,timestamptz) OWNER TO jas_si_customer_identity_owner;
ALTER FUNCTION public.customer_issue_link(text,text,uuid,bytea,timestamptz) OWNER TO jas_si_customer_identity_owner;
ALTER FUNCTION public.customer_consume_link(bytea,text,uuid,bytea,timestamptz) OWNER TO jas_si_customer_identity_owner;
ALTER FUNCTION public.customer_authenticate_session(bytea) OWNER TO jas_si_customer_identity_owner;
ALTER FUNCTION public.customer_revoke_session(bytea) OWNER TO jas_si_customer_identity_owner;

REVOKE ALL ON FUNCTION public.customer_register(text,text,text,uuid,uuid,uuid,bytea,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.customer_issue_link(text,text,uuid,bytea,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.customer_consume_link(bytea,text,uuid,bytea,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.customer_authenticate_session(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.customer_revoke_session(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.customer_register(text,text,text,uuid,uuid,uuid,bytea,timestamptz) TO jas_si_customer_runtime;
GRANT EXECUTE ON FUNCTION public.customer_issue_link(text,text,uuid,bytea,timestamptz) TO jas_si_customer_runtime;
GRANT EXECUTE ON FUNCTION public.customer_consume_link(bytea,text,uuid,bytea,timestamptz) TO jas_si_customer_runtime;
GRANT EXECUTE ON FUNCTION public.customer_authenticate_session(bytea) TO jas_si_customer_runtime;
GRANT EXECUTE ON FUNCTION public.customer_revoke_session(bytea) TO jas_si_customer_runtime;
