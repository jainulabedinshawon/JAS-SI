-- Durable, tenant-neutral GitHub webhook inbox.
-- Webhook payloads are signals only; no tenant or repository binding is created
-- here. The trusted application verifies the raw-body HMAC before calling the
-- runtime routines. Reconciliation against GitHub's API is a separate step.

DO $preflight$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_agent_task_owner')
       OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_runtime') THEN
        RAISE EXCEPTION 'GitHub webhook inbox prerequisite roles are missing';
    END IF;
END
$preflight$;

GRANT CREATE ON SCHEMA public TO jas_si_agent_task_owner;
SET LOCAL ROLE jas_si_agent_task_owner;

CREATE TABLE IF NOT EXISTS public.jas_si_github_webhook_inbox (
    delivery_id varchar(128) PRIMARY KEY
        CHECK (delivery_id ~ '^[A-Za-z0-9-]{1,128}$'),
    event_name varchar(64) NOT NULL
        CHECK (event_name IN ('installation','installation_repositories')),
    action varchar(64) NOT NULL
        CHECK (action IN ('created','deleted','suspend','unsuspend',
                          'new_permissions_accepted','added','removed')),
    installation_id bigint NOT NULL CHECK (installation_id > 0),
    raw_body_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(raw_body_sha256)=32),
    payload jsonb NOT NULL
        CHECK (pg_catalog.jsonb_typeof(payload)='object'
               AND pg_catalog.octet_length(payload::text)<=262144),
    status varchar(16) NOT NULL DEFAULT 'RECEIVED'
        CHECK (status IN ('RECEIVED','PROCESSING','PROCESSED','FAILED')),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 10),
    received_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    processing_started_at timestamptz,
    processed_at timestamptz,
    next_attempt_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    last_error_code varchar(64),
    CONSTRAINT jas_si_github_webhook_state_consistency CHECK (
        (status='RECEIVED' AND processing_started_at IS NULL AND processed_at IS NULL)
        OR (status='PROCESSING' AND processing_started_at IS NOT NULL AND processed_at IS NULL)
        OR (status='PROCESSED' AND processing_started_at IS NOT NULL AND processed_at IS NOT NULL
            AND last_error_code IS NULL)
        OR (status='FAILED' AND processed_at IS NULL AND last_error_code IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS jas_si_github_webhook_claim_idx
    ON public.jas_si_github_webhook_inbox(next_attempt_at,received_at)
    WHERE status IN ('RECEIVED','FAILED','PROCESSING');

REVOKE ALL PRIVILEGES ON TABLE public.jas_si_github_webhook_inbox
    FROM PUBLIC,jas_si_runtime,jas_si_provisioner,
         jas_si_agent_worker,jas_si_agent_verifier,
         jas_si_agent_worker_login,jas_si_agent_verifier_login;

ALTER TABLE public.jas_si_github_webhook_inbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.jas_si_github_webhook_inbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS jas_si_github_webhook_inbox_owner_all
    ON public.jas_si_github_webhook_inbox;
CREATE POLICY jas_si_github_webhook_inbox_owner_all
    ON public.jas_si_github_webhook_inbox
    FOR ALL TO jas_si_agent_task_owner USING (true) WITH CHECK (true);

CREATE OR REPLACE FUNCTION public.jas_si_github_webhook_receive(
    p_delivery_id text,
    p_event_name text,
    p_action text,
    p_installation_id bigint,
    p_raw_body_sha256 bytea,
    p_payload jsonb
) RETURNS TABLE(delivery_id text,status text,attempt_count integer,inserted boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE v_row public.jas_si_github_webhook_inbox%ROWTYPE;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_runtime','MEMBER') THEN
        RAISE EXCEPTION 'Webhook service identity is not authorized' USING ERRCODE='42501';
    END IF;
    IF p_delivery_id IS NULL OR p_delivery_id !~ '^[A-Za-z0-9-]{1,128}$'
       OR p_event_name NOT IN ('installation','installation_repositories')
       OR p_action NOT IN ('created','deleted','suspend','unsuspend',
                           'new_permissions_accepted','added','removed')
       OR (p_event_name='installation' AND p_action NOT IN
           ('created','deleted','suspend','unsuspend','new_permissions_accepted'))
       OR (p_event_name='installation_repositories' AND p_action NOT IN ('added','removed'))
       OR p_installation_id IS NULL OR p_installation_id<=0
       OR p_raw_body_sha256 IS NULL OR pg_catalog.octet_length(p_raw_body_sha256)<>32
       OR p_payload IS NULL OR pg_catalog.jsonb_typeof(p_payload)<>'object'
       OR pg_catalog.octet_length(p_payload::text)>262144
       OR (p_payload->'installation'->>'id') IS DISTINCT FROM p_installation_id::text
       OR p_payload->>'action' IS DISTINCT FROM p_action THEN
        RAISE EXCEPTION 'Invalid GitHub webhook inbox input' USING ERRCODE='22023';
    END IF;

    INSERT INTO public.jas_si_github_webhook_inbox(
        delivery_id,event_name,action,installation_id,raw_body_sha256,payload
    ) VALUES (
        p_delivery_id,p_event_name,p_action,p_installation_id,p_raw_body_sha256,p_payload
    ) ON CONFLICT (delivery_id) DO NOTHING;

    SELECT q.* INTO v_row
      FROM public.jas_si_github_webhook_inbox q
     WHERE q.delivery_id=p_delivery_id
     FOR UPDATE;
    IF v_row.raw_body_sha256 IS DISTINCT FROM p_raw_body_sha256
       OR v_row.event_name IS DISTINCT FROM p_event_name
       OR v_row.action IS DISTINCT FROM p_action
       OR v_row.installation_id IS DISTINCT FROM p_installation_id THEN
        RAISE EXCEPTION 'GitHub delivery ID was reused with different content'
            USING ERRCODE='22023';
    END IF;
    RETURN QUERY SELECT v_row.delivery_id::text,v_row.status::text,
        v_row.attempt_count,(v_row.attempt_count=0 AND v_row.status='RECEIVED'
            AND v_row.received_at >= pg_catalog.transaction_timestamp()) ;
END;
$function$;

CREATE OR REPLACE FUNCTION public.jas_si_github_webhook_claim(
    p_limit integer DEFAULT 10,
    p_lease_seconds integer DEFAULT 120
) RETURNS TABLE(
    delivery_id text,event_name text,action text,installation_id bigint,
    payload jsonb,attempt_count integer
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_runtime','MEMBER') THEN
        RAISE EXCEPTION 'Webhook service identity is not authorized' USING ERRCODE='42501';
    END IF;
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 50
       OR p_lease_seconds IS NULL OR p_lease_seconds NOT BETWEEN 10 AND 600 THEN
        RAISE EXCEPTION 'Invalid GitHub webhook claim bounds' USING ERRCODE='22023';
    END IF;
    RETURN QUERY
    WITH candidates AS (
        SELECT q.delivery_id
          FROM public.jas_si_github_webhook_inbox q
         WHERE q.attempt_count<10
           AND q.next_attempt_at<=pg_catalog.clock_timestamp()
           AND (q.status IN ('RECEIVED','FAILED')
                OR (q.status='PROCESSING'
                    AND q.processing_started_at<=pg_catalog.clock_timestamp()
                        -pg_catalog.make_interval(secs=>p_lease_seconds)))
         ORDER BY q.received_at,q.delivery_id
         LIMIT p_limit
         FOR UPDATE SKIP LOCKED
    )
    UPDATE public.jas_si_github_webhook_inbox q
       SET status='PROCESSING',
           attempt_count=q.attempt_count+1,
           processing_started_at=pg_catalog.clock_timestamp(),
           processed_at=NULL,
           last_error_code=NULL
      FROM candidates c
     WHERE q.delivery_id=c.delivery_id
    RETURNING q.delivery_id::text,q.event_name::text,q.action::text,
              q.installation_id,q.payload,q.attempt_count;
END;
$function$;

CREATE OR REPLACE FUNCTION public.jas_si_github_webhook_mark_processed(
    p_delivery_id text
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_runtime','MEMBER') THEN
        RAISE EXCEPTION 'Webhook service identity is not authorized' USING ERRCODE='42501';
    END IF;
    UPDATE public.jas_si_github_webhook_inbox
       SET status='PROCESSED',processed_at=pg_catalog.clock_timestamp(),
           last_error_code=NULL
     WHERE delivery_id=p_delivery_id AND status='PROCESSING';
    RETURN FOUND;
END;
$function$;

CREATE OR REPLACE FUNCTION public.jas_si_github_webhook_mark_failed(
    p_delivery_id text,
    p_error_code text,
    p_retry_delay_seconds integer DEFAULT 30
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_runtime','MEMBER') THEN
        RAISE EXCEPTION 'Webhook service identity is not authorized' USING ERRCODE='42501';
    END IF;
    IF p_delivery_id IS NULL OR p_error_code IS NULL
       OR p_error_code !~ '^[A-Z0-9_]{1,64}$'
       OR p_retry_delay_seconds IS NULL OR p_retry_delay_seconds NOT BETWEEN 5 AND 3600 THEN
        RAISE EXCEPTION 'Invalid GitHub webhook failure update' USING ERRCODE='22023';
    END IF;
    UPDATE public.jas_si_github_webhook_inbox
       SET status='FAILED',processed_at=NULL,last_error_code=p_error_code,
           next_attempt_at=pg_catalog.clock_timestamp()
               +pg_catalog.make_interval(secs=>p_retry_delay_seconds)
     WHERE delivery_id=p_delivery_id AND status='PROCESSING';
    RETURN FOUND;
END;
$function$;

REVOKE ALL ON FUNCTION public.jas_si_github_webhook_receive(text,text,text,bigint,bytea,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.jas_si_github_webhook_claim(integer,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.jas_si_github_webhook_mark_processed(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.jas_si_github_webhook_mark_failed(text,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.jas_si_github_webhook_receive(text,text,text,bigint,bytea,jsonb) TO jas_si_runtime;
GRANT EXECUTE ON FUNCTION public.jas_si_github_webhook_claim(integer,integer) TO jas_si_runtime;
GRANT EXECUTE ON FUNCTION public.jas_si_github_webhook_mark_processed(text) TO jas_si_runtime;
GRANT EXECUTE ON FUNCTION public.jas_si_github_webhook_mark_failed(text,text,integer) TO jas_si_runtime;

RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_agent_task_owner;

DO $assert$
DECLARE v_name text;
BEGIN
    FOREACH v_name IN ARRAY ARRAY[
        'jas_si_github_webhook_receive(text,text,text,bigint,bytea,jsonb)',
        'jas_si_github_webhook_claim(integer,integer)',
        'jas_si_github_webhook_mark_processed(text)',
        'jas_si_github_webhook_mark_failed(text,text,integer)'
    ] LOOP
        IF pg_catalog.pg_get_userbyid((
            SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.oid=v_name::regprocedure
        ))<>'jas_si_agent_task_owner'
        OR NOT (SELECT p.prosecdef FROM pg_catalog.pg_proc p WHERE p.oid=v_name::regprocedure)
        OR NOT (SELECT COALESCE(p.proconfig,ARRAY[]::text[]) @> ARRAY['search_path=pg_catalog']::text[]
                  FROM pg_catalog.pg_proc p WHERE p.oid=v_name::regprocedure)
        OR EXISTS (
            SELECT 1 FROM pg_catalog.aclexplode(COALESCE(
                (SELECT p.proacl FROM pg_catalog.pg_proc p WHERE p.oid=v_name::regprocedure),
                pg_catalog.acldefault('f',(SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.oid=v_name::regprocedure))
            )) acl WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'
        ) THEN
            RAISE EXCEPTION 'GitHub webhook inbox routine security boundary invalid: %',v_name;
        END IF;
    END LOOP;
    IF pg_catalog.has_table_privilege('jas_si_runtime','public.jas_si_github_webhook_inbox','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_runtime','public.jas_si_github_webhook_inbox','INSERT')
       OR pg_catalog.has_table_privilege('jas_si_runtime','public.jas_si_github_webhook_inbox','UPDATE')
       OR pg_catalog.has_table_privilege('jas_si_runtime','public.jas_si_github_webhook_inbox','DELETE')
       OR pg_catalog.has_table_privilege('jas_si_agent_worker','public.jas_si_github_webhook_inbox','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_agent_verifier','public.jas_si_github_webhook_inbox','SELECT') THEN
        RAISE EXCEPTION 'Application or agent host role has direct webhook inbox table access';
    END IF;
END
$assert$;
