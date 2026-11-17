-- Tenant-owner decisions for tasks that exhausted independent verification.
-- Customer identity is authenticated by the API against the separate customer DB;
-- only the derived account_id + tenant_id cross this boundary.
-- Review events are owned by a separate NOLOGIN role, not the task routine owner.

DO $block$
DECLARE v_role oid;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_agent_task_owner')
       OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_runtime')
       OR pg_catalog.to_regclass('public.jas_si_agent_tasks') IS NULL THEN
        RAISE EXCEPTION 'Durable agent task store prerequisites are missing';
    END IF;

    SELECT oid INTO v_role FROM pg_catalog.pg_roles
     WHERE rolname='jas_si_agent_review_audit_owner';
    IF v_role IS NULL THEN
        CREATE ROLE jas_si_agent_review_audit_owner
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOREPLICATION NOBYPASSRLS NOINHERIT;
        SELECT oid INTO v_role FROM pg_catalog.pg_roles
         WHERE rolname='jas_si_agent_review_audit_owner';
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles r
         WHERE r.oid=v_role AND (
             r.rolcanlogin OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole
             OR r.rolreplication OR r.rolbypassrls OR r.rolinherit
         )
    ) OR EXISTS (
        SELECT 1
          FROM pg_catalog.pg_auth_members m
          JOIN pg_catalog.pg_roles member_role ON member_role.oid=m.member
          JOIN pg_catalog.pg_roles grantor_role ON grantor_role.oid=m.grantor
         WHERE m.member=v_role OR (m.roleid=v_role AND NOT (
             (member_role.rolname='neondb_owner'
              AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option)
             OR
             (member_role.rolname='neondb_owner'
              AND grantor_role.rolname='cloud_admin'
              AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option)
         ))
    ) THEN
        RAISE EXCEPTION 'Unsafe JAS-SI review audit owner role';
    END IF;

    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='neondb_owner') THEN
        EXECUTE 'GRANT jas_si_agent_review_audit_owner TO neondb_owner WITH ADMIN FALSE, INHERIT FALSE, SET TRUE';
    END IF;
END
$block$;

ALTER TABLE public.jas_si_agent_tasks
    DROP CONSTRAINT IF EXISTS jas_si_agent_task_status_check;
ALTER TABLE public.jas_si_agent_tasks
    ADD CONSTRAINT jas_si_agent_task_status_check
    CHECK (status IN (
        'queued','running','cancel_requested','awaiting_verification',
        'human_review_required','closed_unverified',
        'succeeded','failed','cancelled'
    ));

ALTER TABLE public.jas_si_agent_tasks
    DROP CONSTRAINT IF EXISTS jas_si_agent_task_completion_consistency;
ALTER TABLE public.jas_si_agent_tasks
    ADD CONSTRAINT jas_si_agent_task_completion_consistency
    CHECK (
        (status IN ('succeeded','failed','cancelled','closed_unverified')
         AND completed_at IS NOT NULL)
        OR
        (status IN ('queued','running','cancel_requested',
                    'awaiting_verification','human_review_required')
         AND completed_at IS NULL)
    );

GRANT USAGE ON SCHEMA public TO jas_si_agent_review_audit_owner;
GRANT CREATE ON SCHEMA public TO jas_si_agent_review_audit_owner;
GRANT REFERENCES (task_id) ON TABLE public.jas_si_agent_tasks
    TO jas_si_agent_review_audit_owner;
SET LOCAL ROLE jas_si_agent_review_audit_owner;

CREATE TABLE IF NOT EXISTS public.jas_si_agent_task_review_events (
    decision_event_id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
    task_id uuid NOT NULL
        REFERENCES public.jas_si_agent_tasks(task_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    tenant_id uuid NOT NULL,
    reviewer_account_id uuid NOT NULL,
    idempotency_key varchar(128) NOT NULL,
    decision varchar(32) NOT NULL,
    reason_code varchar(64) NOT NULL,
    previous_status varchar(32) NOT NULL,
    resulting_status varchar(32) NOT NULL,
    decided_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT jas_si_agent_task_review_decision_check
        CHECK (decision IN ('request_more_evidence','close_unverified')),
    CONSTRAINT jas_si_agent_task_review_reason_check
        CHECK (reason_code ~ '^[A-Z0-9_]{1,64}$'),
    CONSTRAINT jas_si_agent_task_review_idempotency_check
        CHECK (idempotency_key ~ '^[A-Za-z0-9._:-]{1,128}$'),
    CONSTRAINT jas_si_agent_task_review_transition_check
        CHECK (
            (decision='request_more_evidence'
             AND previous_status='human_review_required'
             AND resulting_status='human_review_required')
            OR
            (decision='close_unverified'
             AND previous_status='human_review_required'
             AND resulting_status='closed_unverified')
        ),
    CONSTRAINT jas_si_agent_task_review_idempotency_unique
        UNIQUE (tenant_id,task_id,idempotency_key)
);

CREATE INDEX IF NOT EXISTS jas_si_agent_task_review_events_history_idx
    ON public.jas_si_agent_task_review_events(tenant_id,task_id,decided_at,decision_event_id);

ALTER TABLE public.jas_si_agent_task_review_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.jas_si_agent_task_review_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS jas_si_agent_task_review_owner_all
    ON public.jas_si_agent_task_review_events;
CREATE POLICY jas_si_agent_task_review_owner_all
    ON public.jas_si_agent_task_review_events
    FOR ALL TO jas_si_agent_review_audit_owner
    USING (true) WITH CHECK (true);
RESET ROLE;

REVOKE ALL ON TABLE public.jas_si_agent_task_review_events
    FROM PUBLIC,jas_si_runtime,jas_si_provisioner;
GRANT SELECT,INSERT,TRIGGER ON TABLE public.jas_si_agent_task_review_events
    TO jas_si_agent_task_owner;
REVOKE UPDATE,DELETE,TRUNCATE ON TABLE public.jas_si_agent_task_review_events
    FROM jas_si_agent_task_owner;

CREATE POLICY jas_si_agent_task_review_routine_all
    ON public.jas_si_agent_task_review_events
    FOR ALL TO jas_si_agent_task_owner
    USING (true) WITH CHECK (true);

GRANT CREATE ON SCHEMA public TO jas_si_agent_task_owner;
SET LOCAL ROLE jas_si_agent_task_owner;

CREATE OR REPLACE FUNCTION public.jas_si_agent_task_review_event_immutable()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog
AS $function$
BEGIN
    RAISE EXCEPTION 'Agent task review events are append-only'
        USING ERRCODE='55000';
END;
$function$;

REVOKE ALL ON FUNCTION public.jas_si_agent_task_review_event_immutable() FROM PUBLIC;
DROP TRIGGER IF EXISTS jas_si_agent_task_review_events_immutable
    ON public.jas_si_agent_task_review_events;
CREATE TRIGGER jas_si_agent_task_review_events_immutable
    BEFORE UPDATE OR DELETE ON public.jas_si_agent_task_review_events
    FOR EACH ROW EXECUTE FUNCTION public.jas_si_agent_task_review_event_immutable();
DROP TRIGGER IF EXISTS jas_si_agent_task_review_events_no_truncate
    ON public.jas_si_agent_task_review_events;
CREATE TRIGGER jas_si_agent_task_review_events_no_truncate
    BEFORE TRUNCATE ON public.jas_si_agent_task_review_events
    FOR EACH STATEMENT EXECUTE FUNCTION public.jas_si_agent_task_review_event_immutable();

CREATE OR REPLACE FUNCTION public.jas_si_agent_task_human_review_decide(
    p_task_id uuid,
    p_tenant_id uuid,
    p_reviewer_account_id uuid,
    p_decision text,
    p_reason_code text,
    p_idempotency_key text
) RETURNS TABLE(
    decision_event_id uuid,
    task_status text,
    created boolean,
    decided_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog
AS $function$
DECLARE
    v_status text;
    v_next_status text;
    v_existing public.jas_si_agent_task_review_events%ROWTYPE;
    v_event_id uuid;
    v_decided_at timestamptz;
    v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_runtime','MEMBER') THEN
        RAISE EXCEPTION 'Customer review runtime identity is not authorized'
            USING ERRCODE='42501';
    END IF;
    IF p_task_id IS NULL OR p_tenant_id IS NULL
       OR p_reviewer_account_id IS NULL OR p_decision IS NULL
       OR p_decision NOT IN ('request_more_evidence','close_unverified')
       OR p_reason_code IS NULL OR p_reason_code !~ '^[A-Z0-9_]{1,64}$'
       OR p_idempotency_key IS NULL
       OR p_idempotency_key !~ '^[A-Za-z0-9._:-]{1,128}$' THEN
        RAISE EXCEPTION 'Invalid human review decision'
            USING ERRCODE='22023';
    END IF;

    SELECT q.status INTO v_status
      FROM public.jas_si_agent_tasks q
     WHERE q.task_id=p_task_id AND q.tenant_id=p_tenant_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT e.* INTO v_existing
      FROM public.jas_si_agent_task_review_events e
     WHERE e.tenant_id=p_tenant_id
       AND e.task_id=p_task_id
       AND e.idempotency_key=p_idempotency_key;
    IF FOUND THEN
        IF v_existing.reviewer_account_id<>p_reviewer_account_id
           OR v_existing.decision<>p_decision
           OR v_existing.reason_code<>p_reason_code THEN
            RAISE EXCEPTION 'Review idempotency key conflicts with a different decision'
                USING ERRCODE='22023';
        END IF;
        RETURN QUERY SELECT v_existing.decision_event_id,
                             v_existing.resulting_status::text,
                             false,
                             v_existing.decided_at;
        RETURN;
    END IF;

    IF v_status<>'human_review_required' THEN
        RAISE EXCEPTION 'Task is not awaiting human review'
            USING ERRCODE='55000';
    END IF;

    v_next_status := 'human_review_required';
    IF p_decision='close_unverified' THEN
        v_next_status := 'closed_unverified';
        UPDATE public.jas_si_agent_tasks
           SET status=v_next_status,
               completed_at=v_now,
               updated_at=v_now,
               error_code='HUMAN_REVIEW_CLOSED_UNVERIFIED'
         WHERE task_id=p_task_id AND tenant_id=p_tenant_id
           AND status='human_review_required';
        IF NOT FOUND THEN
            RAISE EXCEPTION 'Task review state changed concurrently'
                USING ERRCODE='40001';
        END IF;
    ELSE
        UPDATE public.jas_si_agent_tasks
           SET updated_at=v_now
         WHERE task_id=p_task_id AND tenant_id=p_tenant_id
           AND status='human_review_required';
    END IF;

    INSERT INTO public.jas_si_agent_task_review_events(
        task_id,tenant_id,reviewer_account_id,idempotency_key,
        decision,reason_code,previous_status,resulting_status,decided_at
    ) VALUES (
        p_task_id,p_tenant_id,p_reviewer_account_id,p_idempotency_key,
        p_decision,p_reason_code,'human_review_required',v_next_status,v_now
    )
    RETURNING public.jas_si_agent_task_review_events.decision_event_id,
              public.jas_si_agent_task_review_events.decided_at
         INTO v_event_id,v_decided_at;

    RETURN QUERY SELECT v_event_id,v_next_status,true,v_decided_at;
END;
$function$;

REVOKE ALL ON FUNCTION public.jas_si_agent_task_human_review_decide(
    uuid,uuid,uuid,text,text,text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.jas_si_agent_task_human_review_decide(
    uuid,uuid,uuid,text,text,text
) TO jas_si_runtime;

RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_agent_task_owner;

DO $block$
DECLARE
    v_proc oid := 'public.jas_si_agent_task_human_review_decide(uuid,uuid,uuid,text,text,text)'::regprocedure::oid;
    v_owner text;
BEGIN
    SELECT pg_catalog.pg_get_userbyid(p.proowner) INTO v_owner
      FROM pg_catalog.pg_proc p WHERE p.oid=v_proc;
    IF v_owner<>'jas_si_agent_task_owner'
       OR NOT (SELECT p.prosecdef FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
       OR NOT (SELECT COALESCE(p.proconfig,ARRAY[]::text[])
                  @> ARRAY['search_path=pg_catalog']::text[]
                 FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
       OR NOT pg_catalog.has_function_privilege(
            'jas_si_runtime',v_proc,'EXECUTE')
       OR EXISTS (
           SELECT 1 FROM pg_catalog.aclexplode(
               COALESCE((SELECT p.proacl FROM pg_catalog.pg_proc p WHERE p.oid=v_proc),
                        pg_catalog.acldefault('f',(SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)))
           ) acl WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'
       ) THEN
        RAISE EXCEPTION 'Human review decision routine security boundary invalid';
    END IF;

    IF pg_catalog.has_table_privilege('jas_si_runtime',
           'public.jas_si_agent_task_review_events','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_runtime',
           'public.jas_si_agent_task_review_events','INSERT')
       OR pg_catalog.has_table_privilege('jas_si_runtime',
           'public.jas_si_agent_task_review_events','UPDATE')
       OR pg_catalog.has_table_privilege('jas_si_runtime',
           'public.jas_si_agent_task_review_events','DELETE')
       OR pg_catalog.has_table_privilege('jas_si_runtime',
           'public.jas_si_agent_task_review_events','TRUNCATE')
       OR pg_catalog.has_table_privilege('jas_si_agent_task_owner',
           'public.jas_si_agent_task_review_events','UPDATE')
       OR pg_catalog.has_table_privilege('jas_si_agent_task_owner',
           'public.jas_si_agent_task_review_events','DELETE')
       OR pg_catalog.has_table_privilege('jas_si_agent_task_owner',
           'public.jas_si_agent_task_review_events','TRUNCATE')
       OR NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_trigger t
            WHERE t.tgrelid='public.jas_si_agent_task_review_events'::regclass
              AND t.tgname='jas_si_agent_task_review_events_immutable'
              AND t.tgenabled='O'
       )
       OR NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_trigger t
            WHERE t.tgrelid='public.jas_si_agent_task_review_events'::regclass
              AND t.tgname='jas_si_agent_task_review_events_no_truncate'
              AND t.tgenabled='O'
       ) THEN
        RAISE EXCEPTION 'Human review append-only audit boundary invalid';
    END IF;
END
$block$;
