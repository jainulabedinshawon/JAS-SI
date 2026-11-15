-- Durable tenant-scoped task records for the JAS-SI Agent Core.
-- This migration creates persistence only; it does not execute actions.
-- Task payloads are bounded and retained independently of application memory.

DO $block$
DECLARE
    v_owner oid;
BEGIN
    SELECT oid INTO v_owner FROM pg_catalog.pg_roles
     WHERE rolname='jas_si_agent_task_owner';
    IF v_owner IS NULL THEN
        CREATE ROLE jas_si_agent_task_owner
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOREPLICATION NOBYPASSRLS NOINHERIT;
        SELECT oid INTO v_owner FROM pg_catalog.pg_roles
         WHERE rolname='jas_si_agent_task_owner';
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles r
         WHERE r.oid=v_owner AND (
             r.rolcanlogin OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole
             OR r.rolreplication OR r.rolbypassrls OR r.rolinherit
         )
    ) THEN
        RAISE EXCEPTION 'Unsafe JAS-SI agent task owner role';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='neondb_owner') THEN
        GRANT jas_si_agent_task_owner TO neondb_owner
            WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_runtime')
       OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_provisioner')
       OR pg_catalog.to_regclass('public.jas_si_tenants') IS NULL THEN
        RAISE EXCEPTION 'Task store prerequisites are missing';
    END IF;
END
$block$;

CREATE TABLE IF NOT EXISTS public.jas_si_agent_tasks (
    task_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL
        REFERENCES public.jas_si_tenants(tenant_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    api_key_id uuid NOT NULL
        REFERENCES public.jas_si_api_keys(key_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    idempotency_key varchar(128) NOT NULL,
    request_hash bytea NOT NULL,
    task_type varchar(64) NOT NULL,
    status varchar(24) NOT NULL DEFAULT 'queued',
    input_payload jsonb NOT NULL,
    result_payload jsonb,
    error_code varchar(64),
    attempt_count integer NOT NULL DEFAULT 0,
    max_attempts integer NOT NULL DEFAULT 3,
    lease_owner varchar(128),
    lease_expires_at timestamptz,
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    CONSTRAINT jas_si_agent_task_idempotency_unique
        UNIQUE (tenant_id, idempotency_key),
    CONSTRAINT jas_si_agent_task_hash_length
        CHECK (octet_length(request_hash)=32),
    CONSTRAINT jas_si_agent_task_type_nonempty
        CHECK (length(btrim(task_type)) BETWEEN 1 AND 64),
    CONSTRAINT jas_si_agent_task_status_check
        CHECK (status IN ('queued','running','succeeded','failed','cancelled')),
    CONSTRAINT jas_si_agent_task_attempts_check
        CHECK (attempt_count >= 0 AND max_attempts BETWEEN 1 AND 10
               AND attempt_count <= max_attempts),
    CONSTRAINT jas_si_agent_task_input_object
        CHECK (jsonb_typeof(input_payload)='object'
               AND octet_length(input_payload::text) <= 65536),
    CONSTRAINT jas_si_agent_task_result_object
        CHECK (result_payload IS NULL OR
               (jsonb_typeof(result_payload)='object'
                AND octet_length(result_payload::text) <= 65536)),
    CONSTRAINT jas_si_agent_task_error_code
        CHECK (error_code IS NULL OR length(error_code) BETWEEN 1 AND 64),
    CONSTRAINT jas_si_agent_task_lease_consistency
        CHECK ((status='running' AND lease_owner IS NOT NULL
                AND lease_expires_at IS NOT NULL)
            OR (status<>'running' AND lease_owner IS NULL
                AND lease_expires_at IS NULL)),
    CONSTRAINT jas_si_agent_task_completion_consistency
        CHECK ((status IN ('succeeded','failed','cancelled')
                AND completed_at IS NOT NULL)
            OR (status IN ('queued','running') AND completed_at IS NULL))
);

CREATE INDEX IF NOT EXISTS jas_si_agent_tasks_tenant_created_idx
    ON public.jas_si_agent_tasks (tenant_id, created_at DESC, task_id);
CREATE INDEX IF NOT EXISTS jas_si_agent_tasks_claim_idx
    ON public.jas_si_agent_tasks (next_attempt_at, created_at, task_id)
    WHERE status='queued';
CREATE INDEX IF NOT EXISTS jas_si_agent_tasks_lease_idx
    ON public.jas_si_agent_tasks (lease_expires_at, task_id)
    WHERE status='running';

DO $block$
DECLARE v_column text;
BEGIN
    REVOKE ALL PRIVILEGES ON TABLE public.jas_si_agent_tasks
        FROM PUBLIC, jas_si_runtime, jas_si_provisioner;
    FOR v_column IN
        SELECT a.attname FROM pg_catalog.pg_attribute a
         WHERE a.attrelid='public.jas_si_agent_tasks'::regclass
           AND a.attnum>0 AND NOT a.attisdropped
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL PRIVILEGES (%I) ON TABLE public.jas_si_agent_tasks FROM PUBLIC, jas_si_runtime, jas_si_provisioner',
            v_column
        );
    END LOOP;
END
$block$;

GRANT USAGE ON SCHEMA public TO jas_si_agent_task_owner, jas_si_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.jas_si_agent_tasks
    TO jas_si_agent_task_owner;
GRANT SELECT (tenant_id,status) ON public.jas_si_tenants
    TO jas_si_agent_task_owner;
GRANT EXECUTE ON FUNCTION public.jas_si_api_key_authenticate(uuid,bytea)
    TO jas_si_agent_task_owner;

ALTER TABLE public.jas_si_agent_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.jas_si_agent_tasks FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS jas_si_agent_task_owner_all
    ON public.jas_si_agent_tasks;
CREATE POLICY jas_si_agent_task_owner_all
    ON public.jas_si_agent_tasks FOR ALL
    TO jas_si_agent_task_owner USING (true) WITH CHECK (true);

GRANT CREATE ON SCHEMA public TO jas_si_agent_task_owner;
SET LOCAL ROLE jas_si_agent_task_owner;

CREATE OR REPLACE FUNCTION public.jas_si_agent_task_create(
    p_task_id uuid,
    p_api_key_id uuid,
    p_candidate_digest bytea,
    p_idempotency_key text,
    p_request_hash bytea,
    p_task_type text,
    p_input_payload jsonb,
    p_max_attempts integer DEFAULT 3
) RETURNS TABLE(task_id uuid,status text,created boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE
    v_tenant_id uuid;
    v_status text;
    v_existing_hash bytea;
BEGIN
    IF p_task_id IS NULL OR p_api_key_id IS NULL
       OR p_candidate_digest IS NULL OR octet_length(p_candidate_digest)<>32
       OR p_idempotency_key IS NULL
       OR p_idempotency_key !~ '^[A-Za-z0-9._:-]{1,128}$'
       OR p_request_hash IS NULL OR octet_length(p_request_hash)<>32
       OR p_task_type IS NULL OR length(btrim(p_task_type)) NOT BETWEEN 1 AND 64
       OR p_input_payload IS NULL OR jsonb_typeof(p_input_payload)<>'object'
       OR octet_length(p_input_payload::text)>65536
       OR p_max_attempts IS NULL OR p_max_attempts NOT BETWEEN 1 AND 10 THEN
        RAISE EXCEPTION 'Invalid agent task input' USING ERRCODE='22023';
    END IF;

    SELECT auth.auth_tenant_id INTO v_tenant_id
      FROM public.jas_si_api_key_authenticate(p_api_key_id,p_candidate_digest) auth
     WHERE 'agent:tasks:write'=ANY(auth.auth_scopes);
    IF v_tenant_id IS NULL THEN
        RAISE EXCEPTION 'Agent task API key is not authorized' USING ERRCODE='42501';
    END IF;

    INSERT INTO public.jas_si_agent_tasks AS current_task (
        task_id,tenant_id,api_key_id,idempotency_key,request_hash,
        task_type,input_payload,max_attempts
    ) VALUES (
        p_task_id,v_tenant_id,p_api_key_id,p_idempotency_key,p_request_hash,
        btrim(p_task_type),p_input_payload,p_max_attempts
    )
    ON CONFLICT (tenant_id,idempotency_key) DO NOTHING;

    IF FOUND THEN
        RETURN QUERY SELECT p_task_id,'queued'::text,true;
        RETURN;
    END IF;

    SELECT existing_task.task_id,existing_task.status,existing_task.request_hash
      INTO task_id,v_status,v_existing_hash
      FROM public.jas_si_agent_tasks AS existing_task
     WHERE existing_task.tenant_id=v_tenant_id
       AND existing_task.idempotency_key=p_idempotency_key
     FOR SHARE;
    IF task_id IS NULL OR v_existing_hash IS DISTINCT FROM p_request_hash THEN
        RAISE EXCEPTION 'Idempotency key was reused with a different request'
            USING ERRCODE='22023';
    END IF;
    RETURN QUERY SELECT task_id,v_status,false;
END;
$function$;

CREATE OR REPLACE FUNCTION public.jas_si_agent_task_get(
    p_api_key_id uuid,p_candidate_digest bytea,p_task_id uuid
) RETURNS TABLE(
    task_id uuid,task_type text,status text,input_payload jsonb,
    result_payload jsonb,error_code text,attempt_count integer,
    max_attempts integer,created_at timestamptz,updated_at timestamptz,
    completed_at timestamptz
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE v_tenant_id uuid;
BEGIN
    SELECT auth.auth_tenant_id INTO v_tenant_id
      FROM public.jas_si_api_key_authenticate(p_api_key_id,p_candidate_digest) auth
     WHERE 'agent:tasks:read'=ANY(auth.auth_scopes);
    IF v_tenant_id IS NULL THEN
        RAISE EXCEPTION 'Agent task API key is not authorized' USING ERRCODE='42501';
    END IF;
    RETURN QUERY SELECT q.task_id,q.task_type::text,q.status::text,
        q.input_payload,q.result_payload,q.error_code::text,q.attempt_count,
        q.max_attempts,q.created_at,q.updated_at,q.completed_at
      FROM public.jas_si_agent_tasks q
     WHERE q.tenant_id=v_tenant_id AND q.task_id=p_task_id;
END;
$function$;

CREATE OR REPLACE FUNCTION public.jas_si_agent_task_cancel(
    p_api_key_id uuid,p_candidate_digest bytea,p_task_id uuid
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE v_tenant_id uuid; v_updated integer;
BEGIN
    SELECT auth.auth_tenant_id INTO v_tenant_id
      FROM public.jas_si_api_key_authenticate(p_api_key_id,p_candidate_digest) auth
     WHERE p_candidate_digest IS NOT NULL AND octet_length(p_candidate_digest)=32
       AND 'agent:tasks:write'=ANY(auth.auth_scopes);
    IF v_tenant_id IS NULL THEN
        RAISE EXCEPTION 'Agent task API key is not authorized' USING ERRCODE='42501';
    END IF;
    UPDATE public.jas_si_agent_tasks q
       SET status='cancelled',lease_owner=NULL,lease_expires_at=NULL,
           error_code='CANCELLED_BY_TENANT',updated_at=clock_timestamp(),
           completed_at=clock_timestamp()
     WHERE q.tenant_id=v_tenant_id AND q.task_id=p_task_id
       AND q.status IN ('queued','running');
    GET DIAGNOSTICS v_updated=ROW_COUNT;
    RETURN v_updated=1;
END;
$function$;

REVOKE ALL ON FUNCTION public.jas_si_agent_task_create(uuid,uuid,bytea,text,bytea,text,jsonb,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.jas_si_agent_task_get(uuid,bytea,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.jas_si_agent_task_cancel(uuid,bytea,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.jas_si_agent_task_create(uuid,uuid,bytea,text,bytea,text,jsonb,integer) TO jas_si_runtime;
GRANT EXECUTE ON FUNCTION public.jas_si_agent_task_get(uuid,bytea,uuid) TO jas_si_runtime;
GRANT EXECUTE ON FUNCTION public.jas_si_agent_task_cancel(uuid,bytea,uuid) TO jas_si_runtime;

RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_agent_task_owner;

DO $block$
BEGIN
    IF pg_catalog.pg_get_userbyid((
        SELECT p.proowner FROM pg_catalog.pg_proc p
         WHERE p.oid='public.jas_si_agent_task_create(uuid,uuid,bytea,text,bytea,text,jsonb,integer)'::regprocedure
    )) <> 'jas_si_agent_task_owner'
    OR pg_catalog.pg_get_userbyid((
        SELECT p.proowner FROM pg_catalog.pg_proc p
         WHERE p.oid='public.jas_si_agent_task_get(uuid,bytea,uuid)'::regprocedure
    )) <> 'jas_si_agent_task_owner'
    OR pg_catalog.pg_get_userbyid((
        SELECT p.proowner FROM pg_catalog.pg_proc p
         WHERE p.oid='public.jas_si_agent_task_cancel(uuid,bytea,uuid)'::regprocedure
    )) <> 'jas_si_agent_task_owner' THEN
        RAISE EXCEPTION 'Agent task SECURITY DEFINER ownership is invalid';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles r
         WHERE r.rolname IN ('jas_si_runtime','jas_si_provisioner')
           AND (pg_catalog.has_table_privilege(r.rolname,'public.jas_si_agent_tasks','SELECT')
             OR pg_catalog.has_table_privilege(r.rolname,'public.jas_si_agent_tasks','INSERT')
             OR pg_catalog.has_table_privilege(r.rolname,'public.jas_si_agent_tasks','UPDATE')
             OR pg_catalog.has_table_privilege(r.rolname,'public.jas_si_agent_tasks','DELETE')
             OR pg_catalog.has_any_column_privilege(r.rolname,'public.jas_si_agent_tasks','SELECT')
             OR pg_catalog.has_any_column_privilege(r.rolname,'public.jas_si_agent_tasks','INSERT')
             OR pg_catalog.has_any_column_privilege(r.rolname,'public.jas_si_agent_tasks','UPDATE')) THEN
        RAISE EXCEPTION 'Application role retains direct agent task table access';
    END IF;
END
$block$;
