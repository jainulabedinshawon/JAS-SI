-- Authoritative, database-owned GitHub App Installation reconciliation.
-- Only the dedicated reconciler capability can apply snapshots fetched from the
-- GitHub App API. Webhook JSON is never an authority for tenant or repository
-- bindings; it only wakes the reconciler.
DO $roles$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_github_reconciler') THEN
        CREATE ROLE jas_si_github_reconciler NOLOGIN NOSUPERUSER NOCREATEDB
            NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
    END IF;
END
$roles$;

DO $preflight$
BEGIN
    IF pg_catalog.to_regclass('public.jas_si_github_installation_claims') IS NULL
       OR pg_catalog.to_regclass('public.jas_si_github_app_installations') IS NULL
       OR pg_catalog.to_regclass('public.jas_si_github_app_installation_repositories') IS NULL
       OR pg_catalog.to_regclass('public.jas_si_github_webhook_inbox') IS NULL
       OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_agent_task_owner')
       OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_customer_identity_owner') THEN
        RAISE EXCEPTION 'GitHub reconciliation prerequisites are missing';
    END IF;
END
$preflight$;

-- The claims table is owned by the customer identity capability. Perform
-- its schema and policy changes under that exact owner; do not transfer ownership
-- merely to let the reconciler read/update the non-secret proof.
SET LOCAL ROLE jas_si_customer_identity_owner;

-- Reconciliation is the only authority that advances a pending ownership proof.
ALTER TABLE public.jas_si_github_installation_claims
    DROP CONSTRAINT IF EXISTS jas_si_github_installation_claims_status_check;
ALTER TABLE public.jas_si_github_installation_claims
    ADD CONSTRAINT jas_si_github_installation_claims_status_check
    CHECK (status IN ('pending_reconciliation','active','suspended','revoked','needs_review'));
ALTER TABLE public.jas_si_github_installation_claims
    ADD COLUMN IF NOT EXISTS reconciled_at timestamptz;
ALTER TABLE public.jas_si_github_installation_claims
    ADD COLUMN IF NOT EXISTS reconcile_attempt_count integer NOT NULL DEFAULT 0
        CHECK (reconcile_attempt_count BETWEEN 0 AND 10);
ALTER TABLE public.jas_si_github_installation_claims
    ADD COLUMN IF NOT EXISTS reconcile_next_attempt_at timestamptz NOT NULL
        DEFAULT pg_catalog.clock_timestamp();
ALTER TABLE public.jas_si_github_installation_claims
    ADD COLUMN IF NOT EXISTS reconcile_exhausted_at timestamptz;

-- The reconciliation function is owned by the existing agent task owner. Give
-- it narrowly scoped read/update authority over the non-secret ownership proof.
GRANT SELECT ON public.jas_si_github_installation_claims TO jas_si_agent_task_owner;
GRANT UPDATE (status,reconciled_at,reconcile_attempt_count,reconcile_next_attempt_at,reconcile_exhausted_at)
    ON public.jas_si_github_installation_claims
    TO jas_si_agent_task_owner;
DROP POLICY IF EXISTS jas_si_github_claims_reconciler_select
    ON public.jas_si_github_installation_claims;
CREATE POLICY jas_si_github_claims_reconciler_select
    ON public.jas_si_github_installation_claims
    FOR SELECT TO jas_si_agent_task_owner USING (true);
DROP POLICY IF EXISTS jas_si_github_claims_reconciler_update
    ON public.jas_si_github_installation_claims;
CREATE POLICY jas_si_github_claims_reconciler_update
    ON public.jas_si_github_installation_claims
    FOR UPDATE TO jas_si_agent_task_owner USING (true) WITH CHECK (true);

RESET ROLE;

-- The Installation repository table is owned by the agent task capability.
-- CREATE INDEX also requires schema CREATE; grant it only for this DDL scope.
GRANT CREATE ON SCHEMA public TO jas_si_agent_task_owner;
SET LOCAL ROLE jas_si_agent_task_owner;
ALTER TABLE public.jas_si_github_app_installation_repositories
    ADD COLUMN IF NOT EXISTS github_repository_id bigint
        CHECK (github_repository_id IS NULL OR github_repository_id > 0);
ALTER TABLE public.jas_si_github_app_installation_repositories
    ADD COLUMN IF NOT EXISTS is_private boolean;

-- A repository ID is globally stable within one Installation snapshot. Do not
-- allow malformed/ambiguous snapshots to bind one GitHub ID to multiple names.
CREATE UNIQUE INDEX IF NOT EXISTS jas_si_github_repository_id_per_installation_unique
    ON public.jas_si_github_app_installation_repositories
       (installation_id,github_repository_id)
    WHERE github_repository_id IS NOT NULL;
RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_agent_task_owner;

GRANT CREATE ON SCHEMA public TO jas_si_agent_task_owner;
SET LOCAL ROLE jas_si_agent_task_owner;

CREATE OR REPLACE FUNCTION public.jas_si_github_installation_reconcile_apply(
    p_installation_id bigint,
    p_app_id bigint,
    p_account_id bigint,
    p_account_login text,
    p_account_type text,
    p_suspended boolean,
    p_missing boolean,
    p_repositories jsonb
) RETURNS TABLE(claim_status text,installation_status text,repository_count integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE
    v_claim public.jas_si_github_installation_claims%ROWTYPE;
    v_tenant_active boolean;
    v_repo jsonb;
    v_repo_count integer := 0;
    v_repo_id bigint;
    v_repo_name text;
    v_private boolean;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_github_reconciler','MEMBER') THEN
        RAISE EXCEPTION 'GitHub reconciler identity is not authorized' USING ERRCODE='42501';
    END IF;
    IF p_installation_id IS NULL OR p_installation_id<=0
       OR p_missing IS NULL OR p_suspended IS NULL
       OR (p_missing AND (p_suspended OR p_repositories IS DISTINCT FROM '[]'::jsonb))
       OR (NOT p_missing AND (
           p_app_id IS NULL OR p_app_id<=0
           OR p_account_id IS NULL OR p_account_id<=0
           OR p_account_login IS NULL
           OR p_account_login !~ '^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$'
           OR p_account_type IS NULL
           OR p_account_type NOT IN ('User','Organization')
           OR p_repositories IS NULL
           OR pg_catalog.jsonb_typeof(p_repositories)<>'array'
           OR pg_catalog.jsonb_array_length(p_repositories)>10000
       )) THEN
        RAISE EXCEPTION 'Invalid authoritative GitHub Installation snapshot' USING ERRCODE='22023';
    END IF;

    SELECT c.* INTO v_claim
      FROM public.jas_si_github_installation_claims c
     WHERE c.installation_id=p_installation_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'NO_CLAIM'::text,'UNCHANGED'::text,0;
        RETURN;
    END IF;

    -- A retry-exhausted claim is terminal until an operator explicitly requeues it.
    IF v_claim.status='needs_review' THEN
        RETURN QUERY SELECT 'needs_review'::text,'UNCHANGED'::text,0;
        RETURN;
    END IF;

    IF p_missing THEN
        UPDATE public.jas_si_github_installation_claims
           SET status='revoked',reconciled_at=pg_catalog.clock_timestamp()
         WHERE claim_id=v_claim.claim_id;
        UPDATE public.jas_si_github_app_installations
           SET status='revoked',verified_at=NULL,updated_at=pg_catalog.clock_timestamp()
         WHERE installation_id=p_installation_id;
        UPDATE public.jas_si_github_app_installation_repositories
           SET status='revoked',verified_at=NULL,updated_at=pg_catalog.clock_timestamp()
         WHERE installation_id=p_installation_id;
        RETURN QUERY SELECT 'revoked'::text,'revoked'::text,0;
        RETURN;
    END IF;

    IF v_claim.app_id IS DISTINCT FROM p_app_id
       OR v_claim.github_account_id IS DISTINCT FROM p_account_id
       OR v_claim.github_account_login IS DISTINCT FROM p_account_login
       OR v_claim.github_account_type IS DISTINCT FROM p_account_type THEN
        RAISE EXCEPTION 'GitHub App or account identity differs from pending ownership proof'
            USING ERRCODE='23505';
    END IF;

    IF p_suspended THEN
        UPDATE public.jas_si_github_installation_claims
           SET status='suspended',reconciled_at=pg_catalog.clock_timestamp()
         WHERE claim_id=v_claim.claim_id;
        UPDATE public.jas_si_github_app_installations
           SET status='revoked',verified_at=NULL,updated_at=pg_catalog.clock_timestamp()
         WHERE installation_id=p_installation_id;
        UPDATE public.jas_si_github_app_installation_repositories
           SET status='revoked',verified_at=NULL,updated_at=pg_catalog.clock_timestamp()
         WHERE installation_id=p_installation_id;
        RETURN QUERY SELECT 'suspended'::text,'revoked'::text,0;
        RETURN;
    END IF;

    SELECT (t.status='active') INTO v_tenant_active
      FROM public.jas_si_tenants t
     WHERE t.tenant_id=v_claim.tenant_id;
    IF NOT FOUND OR v_tenant_active IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'Installation claim tenant is not active'
            USING ERRCODE='55000';
    END IF;

    INSERT INTO public.jas_si_github_app_installations(
        installation_id,tenant_id,account_login,status,verified_at,updated_at
    ) VALUES (
        p_installation_id,v_claim.tenant_id,p_account_login,'active',
        pg_catalog.clock_timestamp(),pg_catalog.clock_timestamp()
    ) ON CONFLICT (installation_id) DO UPDATE
      SET account_login=EXCLUDED.account_login,status='active',
          verified_at=EXCLUDED.verified_at,updated_at=EXCLUDED.updated_at
      WHERE public.jas_si_github_app_installations.tenant_id=EXCLUDED.tenant_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'GitHub Installation is already bound to another tenant'
            USING ERRCODE='23505';
    END IF;

    FOR v_repo IN SELECT value FROM pg_catalog.jsonb_array_elements(p_repositories)
    LOOP
        IF pg_catalog.jsonb_typeof(v_repo)<>'object'
           OR (v_repo->>'id') IS NULL
           OR (v_repo->>'id') !~ '^[1-9][0-9]{0,18}$'
           OR (v_repo->>'full_name') IS NULL
           OR (v_repo->>'full_name') !~ '^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9_.-]{1,100}$'
           OR pg_catalog.jsonb_typeof(v_repo->'private')<>'boolean' THEN
            RAISE EXCEPTION 'Invalid repository in authoritative GitHub snapshot'
                USING ERRCODE='22023';
        END IF;
        v_repo_id := (v_repo->>'id')::bigint;
        v_repo_name := v_repo->>'full_name';
        v_private := (v_repo->>'private')::boolean;

        INSERT INTO public.jas_si_github_app_installation_repositories(
            installation_id,tenant_id,repository_full_name,status,verified_at,
            github_repository_id,is_private,updated_at
        ) VALUES (
            p_installation_id,v_claim.tenant_id,v_repo_name,'active',
            pg_catalog.clock_timestamp(),v_repo_id,v_private,pg_catalog.clock_timestamp()
        ) ON CONFLICT (installation_id,repository_full_name) DO UPDATE
          SET status='active',verified_at=EXCLUDED.verified_at,
              github_repository_id=EXCLUDED.github_repository_id,
              is_private=EXCLUDED.is_private,updated_at=EXCLUDED.updated_at
          WHERE public.jas_si_github_app_installation_repositories.tenant_id=EXCLUDED.tenant_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'GitHub repository is already bound to another tenant'
                USING ERRCODE='23505';
        END IF;
        v_repo_count := v_repo_count+1;
    END LOOP;

    UPDATE public.jas_si_github_app_installation_repositories r
       SET status='revoked',verified_at=NULL,updated_at=pg_catalog.clock_timestamp()
     WHERE r.installation_id=p_installation_id
       AND r.status='active'
       AND NOT EXISTS (
           SELECT 1 FROM pg_catalog.jsonb_array_elements(p_repositories) incoming(value)
            WHERE pg_catalog.lower(incoming.value->>'full_name')
                  =pg_catalog.lower(r.repository_full_name)
       );

    UPDATE public.jas_si_github_installation_claims
       SET status='active',reconciled_at=pg_catalog.clock_timestamp()
     WHERE claim_id=v_claim.claim_id;
    RETURN QUERY SELECT 'active'::text,'active'::text,v_repo_count;
END;
$function$;

CREATE OR REPLACE FUNCTION public.jas_si_github_installation_claim_pending(
    p_limit integer DEFAULT 10
) RETURNS TABLE(installation_id bigint,attempt_count integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_github_reconciler','MEMBER') THEN
        RAISE EXCEPTION 'GitHub reconciler identity is not authorized' USING ERRCODE='42501';
    END IF;
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 50 THEN
        RAISE EXCEPTION 'Invalid pending Installation claim limit' USING ERRCODE='22023';
    END IF;
    -- Exhausted claims become an explicit operator-review state instead of
    -- remaining indistinguishably pending forever after their final retry.
    UPDATE public.jas_si_github_installation_claims c
       SET status='needs_review',reconcile_exhausted_at=pg_catalog.clock_timestamp()
     WHERE c.status='pending_reconciliation'
       AND c.reconcile_attempt_count>=10
       AND c.reconcile_next_attempt_at<=pg_catalog.clock_timestamp();

    RETURN QUERY
    WITH candidates AS (
        SELECT c.claim_id
          FROM public.jas_si_github_installation_claims c
          JOIN public.jas_si_tenants t ON t.tenant_id=c.tenant_id
         WHERE c.status='pending_reconciliation'
           AND c.reconcile_attempt_count<10
           AND c.reconcile_next_attempt_at<=pg_catalog.clock_timestamp()
           AND t.status='active'
         ORDER BY c.proof_verified_at,c.claim_id
         LIMIT p_limit
         FOR UPDATE OF c SKIP LOCKED
    )
    UPDATE public.jas_si_github_installation_claims c
       SET reconcile_attempt_count=c.reconcile_attempt_count+1,
           reconcile_next_attempt_at=pg_catalog.clock_timestamp()+interval '60 seconds'
      FROM candidates q
     WHERE c.claim_id=q.claim_id
    RETURNING c.installation_id,c.reconcile_attempt_count;
END;
$function$;

REVOKE ALL ON FUNCTION public.jas_si_github_installation_claim_pending(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.jas_si_github_installation_claim_pending(integer)
    TO jas_si_github_reconciler;

REVOKE ALL ON FUNCTION public.jas_si_github_installation_reconcile_apply(
    bigint,bigint,bigint,text,text,boolean,boolean,jsonb
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.jas_si_github_installation_reconcile_apply(
    bigint,bigint,bigint,text,text,boolean,boolean,jsonb
) TO jas_si_github_reconciler;

RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_agent_task_owner;

-- The dedicated reconciler may claim and finish inbox deliveries, but cannot
-- receive public HTTP events or directly inspect/mutate inbox tables.
GRANT CREATE ON SCHEMA public TO jas_si_agent_task_owner;
SET LOCAL ROLE jas_si_agent_task_owner;

CREATE OR REPLACE FUNCTION public.jas_si_github_webhook_claim(
    p_limit integer DEFAULT 10,
    p_lease_seconds integer DEFAULT 120
) RETURNS TABLE(
    delivery_id text,event_name text,action text,installation_id bigint,
    payload jsonb,attempt_count integer,claim_token uuid
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_runtime','MEMBER')
       AND NOT pg_catalog.pg_has_role(session_user,'jas_si_github_reconciler','MEMBER') THEN
        RAISE EXCEPTION 'Webhook processor identity is not authorized' USING ERRCODE='42501';
    END IF;
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 50
       OR p_lease_seconds IS NULL OR p_lease_seconds NOT BETWEEN 10 AND 600 THEN
        RAISE EXCEPTION 'Invalid GitHub webhook claim bounds' USING ERRCODE='22023';
    END IF;
    RETURN QUERY
    WITH candidates AS (
        SELECT q.delivery_id FROM public.jas_si_github_webhook_inbox q
         WHERE q.attempt_count<10 AND q.next_attempt_at<=pg_catalog.clock_timestamp()
           AND (q.status IN ('RECEIVED','FAILED')
                OR (q.status='PROCESSING' AND q.lease_expires_at<=pg_catalog.clock_timestamp()))
         ORDER BY q.received_at,q.delivery_id
         LIMIT p_limit FOR UPDATE SKIP LOCKED
    )
    UPDATE public.jas_si_github_webhook_inbox q
       SET status='PROCESSING',attempt_count=q.attempt_count+1,
           processing_started_at=pg_catalog.clock_timestamp(),
           lease_expires_at=pg_catalog.clock_timestamp()+pg_catalog.make_interval(secs=>p_lease_seconds),
           lease_token=pg_catalog.gen_random_uuid(),processed_at=NULL,last_error_code=NULL
      FROM candidates c WHERE q.delivery_id=c.delivery_id
    RETURNING q.delivery_id::text,q.event_name::text,q.action::text,
              q.installation_id,q.payload,q.attempt_count,q.lease_token;
END;
$function$;

CREATE OR REPLACE FUNCTION public.jas_si_github_webhook_mark_processed(
    p_delivery_id text,p_claim_token uuid
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_runtime','MEMBER')
       AND NOT pg_catalog.pg_has_role(session_user,'jas_si_github_reconciler','MEMBER') THEN
        RAISE EXCEPTION 'Webhook processor identity is not authorized' USING ERRCODE='42501';
    END IF;
    UPDATE public.jas_si_github_webhook_inbox
       SET status='PROCESSED',processed_at=pg_catalog.clock_timestamp(),
           lease_expires_at=NULL,lease_token=NULL,last_error_code=NULL
     WHERE delivery_id=p_delivery_id AND status='PROCESSING'
       AND lease_token=p_claim_token AND lease_expires_at>pg_catalog.clock_timestamp();
    RETURN FOUND;
END;
$function$;

CREATE OR REPLACE FUNCTION public.jas_si_github_webhook_mark_failed(
    p_delivery_id text,p_error_code text,p_claim_token uuid,
    p_retry_delay_seconds integer DEFAULT 30
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_runtime','MEMBER')
       AND NOT pg_catalog.pg_has_role(session_user,'jas_si_github_reconciler','MEMBER') THEN
        RAISE EXCEPTION 'Webhook processor identity is not authorized' USING ERRCODE='42501';
    END IF;
    IF p_delivery_id IS NULL OR p_error_code IS NULL
       OR p_error_code !~ '^[A-Z0-9_]{1,64}$'
       OR p_retry_delay_seconds IS NULL OR p_retry_delay_seconds NOT BETWEEN 5 AND 3600 THEN
        RAISE EXCEPTION 'Invalid GitHub webhook failure update' USING ERRCODE='22023';
    END IF;
    UPDATE public.jas_si_github_webhook_inbox
       SET status='FAILED',processed_at=NULL,lease_expires_at=NULL,lease_token=NULL,
           last_error_code=p_error_code,
           next_attempt_at=pg_catalog.clock_timestamp()
               +pg_catalog.make_interval(secs=>p_retry_delay_seconds)
     WHERE delivery_id=p_delivery_id AND status='PROCESSING'
       AND lease_token=p_claim_token AND lease_expires_at>pg_catalog.clock_timestamp();
    RETURN FOUND;
END;
$function$;

RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_agent_task_owner;

-- Function ACLs are owner-only. Re-enter the owning capability role after
-- removing its temporary schema CREATE grant, then reset before assertions.
SET LOCAL ROLE jas_si_agent_task_owner;
REVOKE ALL ON FUNCTION public.jas_si_github_webhook_claim(integer,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.jas_si_github_webhook_mark_processed(text,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.jas_si_github_webhook_mark_failed(text,text,uuid,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.jas_si_github_webhook_claim(integer,integer)
    TO jas_si_github_reconciler;
GRANT EXECUTE ON FUNCTION public.jas_si_github_webhook_mark_processed(text,uuid)
    TO jas_si_github_reconciler;
GRANT EXECUTE ON FUNCTION public.jas_si_github_webhook_mark_failed(text,text,uuid,integer)
    TO jas_si_github_reconciler;
RESET ROLE;

DO $assert$
DECLARE v_proc oid;
BEGIN
    SELECT 'public.jas_si_github_installation_reconcile_apply(bigint,bigint,bigint,text,text,boolean,boolean,jsonb)'::regprocedure
      INTO v_proc;
    IF pg_catalog.pg_get_userbyid((SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.oid=v_proc))
           <> 'jas_si_agent_task_owner'
       OR NOT (SELECT p.prosecdef FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
       OR NOT (SELECT COALESCE(p.proconfig,ARRAY[]::text[]) @> ARRAY['search_path=pg_catalog']::text[]
                 FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
       OR NOT pg_catalog.has_function_privilege('jas_si_github_reconciler',v_proc,'EXECUTE')
       OR pg_catalog.has_function_privilege('jas_si_runtime',v_proc,'EXECUTE')
       OR pg_catalog.has_function_privilege('jas_si_agent_worker',v_proc,'EXECUTE')
       OR pg_catalog.has_function_privilege('jas_si_agent_verifier',v_proc,'EXECUTE')
       OR EXISTS (
            SELECT 1
              FROM (VALUES
                ('public.jas_si_github_installation_claims'),
                ('public.jas_si_github_app_installations'),
                ('public.jas_si_github_app_installation_repositories'),
                ('public.jas_si_github_webhook_inbox')
              ) AS protected_table(table_name)
              CROSS JOIN (VALUES
                ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),
                ('TRUNCATE'),('REFERENCES'),('TRIGGER')
              ) AS privilege(privilege_name)
             WHERE pg_catalog.has_table_privilege(
                 'jas_si_github_reconciler',protected_table.table_name,
                 privilege.privilege_name)
       )
       OR EXISTS (
            SELECT 1
              FROM (VALUES
                ('public.jas_si_github_installation_claims'),
                ('public.jas_si_github_app_installations'),
                ('public.jas_si_github_app_installation_repositories'),
                ('public.jas_si_github_webhook_inbox')
              ) AS protected_table(table_name)
              CROSS JOIN (VALUES
                ('SELECT'),('INSERT'),('UPDATE'),('REFERENCES')
              ) AS privilege(privilege_name)
             WHERE pg_catalog.has_any_column_privilege(
                 'jas_si_github_reconciler',protected_table.table_name,
                 privilege.privilege_name)
       )
       OR pg_catalog.has_function_privilege('jas_si_github_reconciler',
            'public.jas_si_github_webhook_receive(text,text,text,bigint,bytea,jsonb)','EXECUTE')
       OR NOT pg_catalog.has_function_privilege('jas_si_github_reconciler',
            'public.jas_si_github_installation_claim_pending(integer)','EXECUTE')
       OR pg_catalog.has_function_privilege('jas_si_runtime',
            'public.jas_si_github_installation_claim_pending(integer)','EXECUTE')
       OR pg_catalog.has_function_privilege('jas_si_agent_worker',
            'public.jas_si_github_installation_claim_pending(integer)','EXECUTE')
       OR pg_catalog.has_function_privilege('jas_si_agent_verifier',
            'public.jas_si_github_installation_claim_pending(integer)','EXECUTE')
       OR pg_catalog.has_function_privilege('jas_si_runtime',
            'public.jas_si_github_installation_reconcile_apply(bigint,bigint,bigint,text,text,boolean,boolean,jsonb)','EXECUTE')
       OR pg_catalog.has_function_privilege('jas_si_agent_worker',
            'public.jas_si_github_installation_reconcile_apply(bigint,bigint,bigint,text,text,boolean,boolean,jsonb)','EXECUTE')
       OR pg_catalog.has_function_privilege('jas_si_agent_verifier',
            'public.jas_si_github_installation_reconcile_apply(bigint,bigint,bigint,text,text,boolean,boolean,jsonb)','EXECUTE')
       OR EXISTS (
            SELECT 1 FROM pg_catalog.aclexplode(COALESCE(
                (SELECT p.proacl FROM pg_catalog.pg_proc p
                  WHERE p.oid='public.jas_si_github_installation_claim_pending(integer)'::regprocedure),
                pg_catalog.acldefault('f',(SELECT p.proowner FROM pg_catalog.pg_proc p
                  WHERE p.oid='public.jas_si_github_installation_claim_pending(integer)'::regprocedure))
            )) acl
            WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'
       ) THEN
        RAISE EXCEPTION 'GitHub reconciler privilege boundary is invalid';
    END IF;
END
$assert$;
