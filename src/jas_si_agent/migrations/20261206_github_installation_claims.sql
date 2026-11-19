-- Durable, customer-session-authorized GitHub Installation ownership claims.
-- OAuth proof is recorded as pending; this migration never activates an
-- installation or repository binding. Reconciliation is a separate authority.
DO $preflight$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_customer_identity_owner')
       OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_customer_runtime')
       OR pg_catalog.to_regclass('public.jas_si_customer_sessions') IS NULL
       OR pg_catalog.to_regclass('public.jas_si_customer_accounts') IS NULL
       OR pg_catalog.to_regclass('public.jas_si_tenants') IS NULL THEN
        RAISE EXCEPTION 'Customer identity prerequisites for Installation claims are missing';
    END IF;
END
$preflight$;

GRANT USAGE ON SCHEMA public TO jas_si_customer_identity_owner;
GRANT SELECT (session_id,account_id,token_digest,expires_at,revoked_at)
    ON public.jas_si_customer_sessions TO jas_si_customer_identity_owner;
GRANT SELECT (account_id,tenant_id,status)
    ON public.jas_si_customer_accounts TO jas_si_customer_identity_owner;
GRANT SELECT (tenant_id,status)
    ON public.jas_si_tenants TO jas_si_customer_identity_owner;
GRANT REFERENCES (tenant_id) ON public.jas_si_tenants
    TO jas_si_customer_identity_owner;
GRANT REFERENCES (account_id) ON public.jas_si_customer_accounts
    TO jas_si_customer_identity_owner;

GRANT CREATE ON SCHEMA public TO jas_si_customer_identity_owner;
SET LOCAL ROLE jas_si_customer_identity_owner;

CREATE TABLE IF NOT EXISTS public.jas_si_github_installation_claims (
    claim_id uuid PRIMARY KEY,
    installation_id bigint NOT NULL UNIQUE CHECK (installation_id > 0),
    tenant_id uuid NOT NULL REFERENCES public.jas_si_tenants(tenant_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    customer_account_id uuid NOT NULL REFERENCES public.jas_si_customer_accounts(account_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    github_user_id bigint NOT NULL CHECK (github_user_id > 0),
    github_user_login varchar(39) NOT NULL
        CHECK (github_user_login ~ '^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$'),
    github_account_id bigint NOT NULL CHECK (github_account_id > 0),
    github_account_login varchar(39) NOT NULL
        CHECK (github_account_login ~ '^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$'),
    github_account_type varchar(16) NOT NULL
        CHECK (github_account_type IN ('User','Organization')),
    app_id bigint NOT NULL CHECK (app_id > 0),
    status varchar(32) NOT NULL DEFAULT 'pending_reconciliation'
        CHECK (status='pending_reconciliation'),
    proof_verified_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT jas_si_github_claim_account_tenant_fk
        FOREIGN KEY (customer_account_id,tenant_id)
        REFERENCES public.jas_si_customer_accounts(account_id,tenant_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS jas_si_github_installation_claims_tenant_idx
    ON public.jas_si_github_installation_claims(tenant_id,created_at DESC);

REVOKE ALL PRIVILEGES ON TABLE public.jas_si_github_installation_claims
    FROM PUBLIC,jas_si_customer_runtime,jas_si_runtime,jas_si_provisioner,
         jas_si_agent_worker,jas_si_agent_verifier,
         jas_si_agent_worker_login,jas_si_agent_verifier_login;

ALTER TABLE public.jas_si_github_installation_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.jas_si_github_installation_claims FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS jas_si_github_installation_claims_owner_all
    ON public.jas_si_github_installation_claims;
CREATE POLICY jas_si_github_installation_claims_owner_all
    ON public.jas_si_github_installation_claims
    FOR ALL TO jas_si_customer_identity_owner USING (true) WITH CHECK (true);

CREATE OR REPLACE FUNCTION public.customer_github_installation_claim_record(
    p_session_digest bytea,
    p_claim_id uuid,
    p_installation_id bigint,
    p_github_user_id bigint,
    p_github_user_login text,
    p_github_account_id bigint,
    p_github_account_login text,
    p_github_account_type text,
    p_app_id bigint
) RETURNS TABLE(claim_id uuid,status text,installation_id bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_account_id uuid;
    v_tenant_id uuid;
    v_claim public.jas_si_github_installation_claims%ROWTYPE;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_customer_runtime','MEMBER') THEN
        RAISE EXCEPTION 'Customer GitHub claim service identity is not authorized'
            USING ERRCODE='42501';
    END IF;
    IF p_session_digest IS NULL OR pg_catalog.octet_length(p_session_digest)<>32
       OR p_claim_id IS NULL
       OR p_installation_id IS NULL OR p_installation_id<=0
       OR p_github_user_id IS NULL OR p_github_user_id<=0
       OR p_github_user_login IS NULL
       OR p_github_user_login !~ '^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$'
       OR p_github_account_id IS NULL OR p_github_account_id<=0
       OR p_github_account_login IS NULL
       OR p_github_account_login !~ '^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$'
       OR p_github_account_type NOT IN ('User','Organization')
       OR p_app_id IS NULL OR p_app_id<=0 THEN
        RAISE EXCEPTION 'Invalid verified GitHub Installation claim input'
            USING ERRCODE='22023';
    END IF;

    SELECT a.account_id,a.tenant_id INTO v_account_id,v_tenant_id
      FROM public.jas_si_customer_sessions s
      JOIN public.jas_si_customer_accounts a ON a.account_id=s.account_id
      JOIN public.jas_si_tenants t ON t.tenant_id=a.tenant_id
     WHERE s.token_digest=p_session_digest
       AND s.revoked_at IS NULL AND s.expires_at>v_now
       AND a.status='active' AND t.status='active'
     FOR SHARE OF s,a,t;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Active customer session required'
            USING ERRCODE='28000';
    END IF;

    INSERT INTO public.jas_si_github_installation_claims(
        claim_id,installation_id,tenant_id,customer_account_id,
        github_user_id,github_user_login,github_account_id,
        github_account_login,github_account_type,app_id
    ) VALUES (
        p_claim_id,p_installation_id,v_tenant_id,v_account_id,
        p_github_user_id,p_github_user_login,p_github_account_id,
        p_github_account_login,p_github_account_type,p_app_id
    ) ON CONFLICT (installation_id) DO NOTHING;

    SELECT c.* INTO v_claim
      FROM public.jas_si_github_installation_claims c
     WHERE c.installation_id=p_installation_id
     FOR UPDATE;
    IF NOT FOUND
       OR v_claim.tenant_id IS DISTINCT FROM v_tenant_id
       OR v_claim.customer_account_id IS DISTINCT FROM v_account_id
       OR v_claim.github_user_id IS DISTINCT FROM p_github_user_id
       OR v_claim.github_user_login IS DISTINCT FROM p_github_user_login
       OR v_claim.github_account_id IS DISTINCT FROM p_github_account_id
       OR v_claim.github_account_login IS DISTINCT FROM p_github_account_login
       OR v_claim.github_account_type IS DISTINCT FROM p_github_account_type
       OR v_claim.app_id IS DISTINCT FROM p_app_id THEN
        RAISE EXCEPTION 'GitHub Installation is already claimed by a different identity'
            USING ERRCODE='23505';
    END IF;
    RETURN QUERY SELECT v_claim.claim_id,v_claim.status::text,v_claim.installation_id;
END;
$function$;

RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_customer_identity_owner;

SET LOCAL ROLE jas_si_customer_identity_owner;
REVOKE ALL ON FUNCTION public.customer_github_installation_claim_record(
    bytea,uuid,bigint,bigint,text,bigint,text,text,bigint
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.customer_github_installation_claim_record(
    bytea,uuid,bigint,bigint,text,bigint,text,text,bigint
) TO jas_si_customer_runtime;
RESET ROLE;

DO $assert$
DECLARE v_proc oid;
BEGIN
    SELECT 'public.customer_github_installation_claim_record(bytea,uuid,bigint,bigint,text,bigint,text,text,bigint)'::regprocedure
      INTO v_proc;
    IF pg_catalog.pg_get_userbyid((SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.oid=v_proc))
           <> 'jas_si_customer_identity_owner'
       OR NOT (SELECT p.prosecdef FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
       OR NOT (SELECT COALESCE(p.proconfig,ARRAY[]::text[]) @> ARRAY['search_path=pg_catalog']::text[]
                 FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
       OR NOT pg_catalog.has_function_privilege('jas_si_customer_runtime',v_proc,'EXECUTE')
       OR pg_catalog.has_function_privilege('jas_si_runtime',v_proc,'EXECUTE')
       OR pg_catalog.has_function_privilege('jas_si_agent_worker',v_proc,'EXECUTE')
       OR pg_catalog.has_function_privilege('jas_si_agent_verifier',v_proc,'EXECUTE')
       OR pg_catalog.has_table_privilege('jas_si_customer_runtime',
           'public.jas_si_github_installation_claims','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_customer_runtime',
           'public.jas_si_github_installation_claims','INSERT')
       OR pg_catalog.has_table_privilege('jas_si_agent_worker',
           'public.jas_si_github_installation_claims','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_agent_verifier',
           'public.jas_si_github_installation_claims','SELECT') THEN
        RAISE EXCEPTION 'GitHub Installation claim persistence ACL boundary is invalid';
    END IF;
END
$assert$;
