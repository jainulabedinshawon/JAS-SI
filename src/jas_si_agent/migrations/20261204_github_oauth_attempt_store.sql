-- Durable, tenant-bound, single-use GitHub OAuth attempts.
-- The application stores only SHA-256(state), AEAD-encrypted PKCE verifier,
-- key version, and a digest of the configured redirect URI. Raw state and
-- plaintext verifier must never be persisted.
DO $preflight$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_customer_identity_owner')
       OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_customer_runtime') THEN
        RAISE EXCEPTION 'Customer identity owner/runtime roles are required';
    END IF;
END
$preflight$;

GRANT USAGE ON SCHEMA public TO jas_si_customer_identity_owner;
GRANT SELECT (session_id,account_id,token_digest,expires_at,revoked_at)
    ON public.jas_si_customer_sessions TO jas_si_customer_identity_owner;
GRANT SELECT (account_id,tenant_id,status)
    ON public.jas_si_customer_accounts TO jas_si_customer_identity_owner;
GRANT SELECT (tenant_id,status), REFERENCES (tenant_id)
    ON public.jas_si_tenants TO jas_si_customer_identity_owner;
GRANT REFERENCES (account_id)
    ON public.jas_si_customer_accounts TO jas_si_customer_identity_owner;

GRANT CREATE ON SCHEMA public TO jas_si_customer_identity_owner;
SET LOCAL ROLE jas_si_customer_identity_owner;

CREATE TABLE IF NOT EXISTS public.jas_si_github_oauth_attempts (
    attempt_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES public.jas_si_tenants(tenant_id) ON DELETE CASCADE,
    account_id uuid NOT NULL REFERENCES public.jas_si_customer_accounts(account_id) ON DELETE CASCADE,
    state_digest bytea NOT NULL UNIQUE,
    verifier_ciphertext bytea NOT NULL,
    verifier_key_version varchar(32) NOT NULL,
    redirect_uri_digest bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CONSTRAINT jas_si_github_oauth_state_digest_length CHECK (pg_catalog.octet_length(state_digest)=32),
    CONSTRAINT jas_si_github_oauth_verifier_ciphertext_length CHECK (
        pg_catalog.octet_length(verifier_ciphertext) BETWEEN 16 AND 512
    ),
    CONSTRAINT jas_si_github_oauth_key_version_check CHECK (
        verifier_key_version ~ '^[A-Za-z0-9._-]{1,32}$'
    ),
    CONSTRAINT jas_si_github_oauth_redirect_digest_length CHECK (pg_catalog.octet_length(redirect_uri_digest)=32),
    CONSTRAINT jas_si_github_oauth_expiry_check CHECK (
        expires_at > created_at AND expires_at <= created_at + interval '10 minutes'
    )
);
CREATE INDEX IF NOT EXISTS jas_si_github_oauth_attempts_expiry_idx
    ON public.jas_si_github_oauth_attempts(expires_at)
    WHERE consumed_at IS NULL;

REVOKE ALL ON public.jas_si_github_oauth_attempts FROM PUBLIC, jas_si_customer_runtime,
    jas_si_runtime, jas_si_provisioner, jas_si_agent_worker, jas_si_agent_verifier;

CREATE OR REPLACE FUNCTION public.customer_github_oauth_attempt_create(
    p_session_digest bytea,
    p_attempt_id uuid,
    p_state_digest bytea,
    p_verifier_ciphertext bytea,
    p_verifier_key_version text,
    p_redirect_uri_digest bytea,
    p_expires_at timestamptz
) RETURNS TABLE(attempt_id uuid, expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE
    v_account_id uuid;
    v_tenant_id uuid;
    v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_customer_runtime','MEMBER') THEN
        RAISE EXCEPTION 'Customer OAuth service identity is not authorized' USING ERRCODE='42501';
    END IF;
    IF p_session_digest IS NULL OR pg_catalog.octet_length(p_session_digest)<>32
       OR p_attempt_id IS NULL OR p_state_digest IS NULL OR pg_catalog.octet_length(p_state_digest)<>32
       OR p_verifier_ciphertext IS NULL OR pg_catalog.octet_length(p_verifier_ciphertext) NOT BETWEEN 16 AND 512
       OR p_verifier_key_version IS NULL OR p_verifier_key_version !~ '^[A-Za-z0-9._-]{1,32}$'
       OR p_redirect_uri_digest IS NULL OR pg_catalog.octet_length(p_redirect_uri_digest)<>32
       OR p_expires_at IS NULL OR p_expires_at<=v_now
       OR p_expires_at>v_now+interval '10 minutes' THEN
        RAISE EXCEPTION 'Invalid GitHub OAuth attempt input' USING ERRCODE='22023';
    END IF;
    SELECT a.account_id,a.tenant_id INTO v_account_id,v_tenant_id
      FROM public.jas_si_customer_sessions s
      JOIN public.jas_si_customer_accounts a ON a.account_id=s.account_id
      JOIN public.jas_si_tenants t ON t.tenant_id=a.tenant_id
     WHERE s.token_digest=p_session_digest AND s.revoked_at IS NULL
       AND s.expires_at>v_now AND a.status='active' AND t.status='active'
     FOR SHARE OF s,a,t;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Active customer session required' USING ERRCODE='28000';
    END IF;
    INSERT INTO public.jas_si_github_oauth_attempts(
        attempt_id,tenant_id,account_id,state_digest,verifier_ciphertext,
        verifier_key_version,redirect_uri_digest,expires_at
    ) VALUES (
        p_attempt_id,v_tenant_id,v_account_id,p_state_digest,p_verifier_ciphertext,
        p_verifier_key_version,p_redirect_uri_digest,p_expires_at
    );
    RETURN QUERY SELECT p_attempt_id,p_expires_at;
END;
$function$;

CREATE OR REPLACE FUNCTION public.customer_github_oauth_attempt_consume(
    p_session_digest bytea,
    p_state_digest bytea,
    p_redirect_uri_digest bytea
) RETURNS TABLE(attempt_id uuid,tenant_id uuid,account_id uuid,
    verifier_ciphertext bytea,verifier_key_version text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_customer_runtime','MEMBER') THEN
        RAISE EXCEPTION 'Customer OAuth service identity is not authorized' USING ERRCODE='42501';
    END IF;
    IF p_session_digest IS NULL OR pg_catalog.octet_length(p_session_digest)<>32
       OR p_state_digest IS NULL OR pg_catalog.octet_length(p_state_digest)<>32
       OR p_redirect_uri_digest IS NULL OR pg_catalog.octet_length(p_redirect_uri_digest)<>32 THEN
        RAISE EXCEPTION 'Invalid GitHub OAuth callback input' USING ERRCODE='22023';
    END IF;
    RETURN QUERY
    UPDATE public.jas_si_github_oauth_attempts o
       SET consumed_at=v_now
      FROM public.jas_si_customer_sessions s
      JOIN public.jas_si_customer_accounts a ON a.account_id=s.account_id
      JOIN public.jas_si_tenants t ON t.tenant_id=a.tenant_id
     WHERE s.token_digest=p_session_digest AND s.revoked_at IS NULL
       AND s.expires_at>v_now AND a.status='active' AND t.status='active'
       AND o.account_id=a.account_id AND o.tenant_id=a.tenant_id
       AND o.state_digest=p_state_digest AND o.redirect_uri_digest=p_redirect_uri_digest
       AND o.consumed_at IS NULL AND o.expires_at>v_now
    RETURNING o.attempt_id,o.tenant_id,o.account_id,o.verifier_ciphertext,
              o.verifier_key_version;
END;
$function$;

REVOKE ALL ON FUNCTION public.customer_github_oauth_attempt_create(bytea,uuid,bytea,bytea,text,bytea,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.customer_github_oauth_attempt_consume(bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.customer_github_oauth_attempt_create(bytea,uuid,bytea,bytea,text,bytea,timestamptz)
    TO jas_si_customer_runtime;
GRANT EXECUTE ON FUNCTION public.customer_github_oauth_attempt_consume(bytea,bytea,bytea)
    TO jas_si_customer_runtime;

RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_customer_identity_owner;

DO $assert$
DECLARE v_name text;
BEGIN
    IF pg_catalog.has_table_privilege('jas_si_customer_runtime','public.jas_si_github_oauth_attempts','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_customer_runtime','public.jas_si_github_oauth_attempts','INSERT')
       OR pg_catalog.has_table_privilege('jas_si_customer_runtime','public.jas_si_github_oauth_attempts','UPDATE')
       OR pg_catalog.has_any_column_privilege('jas_si_customer_runtime','public.jas_si_github_oauth_attempts','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_agent_worker','public.jas_si_github_oauth_attempts','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_agent_verifier','public.jas_si_github_oauth_attempts','SELECT')
       OR NOT pg_catalog.has_function_privilege('jas_si_customer_runtime',
           'public.customer_github_oauth_attempt_create(bytea,uuid,bytea,bytea,text,bytea,timestamptz)','EXECUTE')
       OR NOT pg_catalog.has_function_privilege('jas_si_customer_runtime',
           'public.customer_github_oauth_attempt_consume(bytea,bytea,bytea)','EXECUTE')
       OR pg_catalog.has_function_privilege('jas_si_runtime',
           'public.customer_github_oauth_attempt_consume(bytea,bytea,bytea)','EXECUTE')
       OR pg_catalog.has_function_privilege('jas_si_agent_worker',
           'public.customer_github_oauth_attempt_consume(bytea,bytea,bytea)','EXECUTE')
       OR pg_catalog.has_function_privilege('jas_si_agent_verifier',
           'public.customer_github_oauth_attempt_consume(bytea,bytea,bytea)','EXECUTE') THEN
        RAISE EXCEPTION 'GitHub OAuth attempt storage ACL boundary is invalid';
    END IF;
    FOREACH v_name IN ARRAY ARRAY[
        'customer_github_oauth_attempt_create(bytea,uuid,bytea,bytea,text,bytea,timestamptz)',
        'customer_github_oauth_attempt_consume(bytea,bytea,bytea)'
    ] LOOP
        IF pg_catalog.pg_get_userbyid((
            SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.oid=('public.'||v_name)::regprocedure
        ))<>'jas_si_customer_identity_owner'
        OR NOT (SELECT p.prosecdef FROM pg_catalog.pg_proc p WHERE p.oid=('public.'||v_name)::regprocedure)
        OR NOT (SELECT COALESCE(p.proconfig,ARRAY[]::text[]) @> ARRAY['search_path=pg_catalog']::text[]
                  FROM pg_catalog.pg_proc p WHERE p.oid=('public.'||v_name)::regprocedure) THEN
            RAISE EXCEPTION 'GitHub OAuth routine owner/SECURITY DEFINER boundary is invalid: %',v_name;
        END IF;
    END LOOP;
END
$assert$;
