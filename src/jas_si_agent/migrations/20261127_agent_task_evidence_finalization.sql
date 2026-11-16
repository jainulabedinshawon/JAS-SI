-- Persist independent verifier evidence and atomically finalize verified success.
-- This migration adds a narrow verifier capability. It does not create a login,
-- grant application roles direct table access, or alter existing production data.

DO $block$
DECLARE v_role oid;
BEGIN
    SELECT oid INTO v_role FROM pg_catalog.pg_roles
     WHERE rolname='jas_si_agent_verifier';
    IF v_role IS NULL THEN
        CREATE ROLE jas_si_agent_verifier
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOREPLICATION NOBYPASSRLS NOINHERIT;
        SELECT oid INTO v_role FROM pg_catalog.pg_roles
         WHERE rolname='jas_si_agent_verifier';
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
        RAISE EXCEPTION 'Unsafe JAS-SI verifier capability role';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='neondb_owner') THEN
        EXECUTE 'GRANT jas_si_agent_verifier TO neondb_owner WITH ADMIN FALSE, INHERIT FALSE, SET TRUE';
    END IF;
    IF pg_catalog.to_regclass('public.jas_si_agent_tasks') IS NULL
       OR NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_agent_task_owner'
       ) THEN
        RAISE EXCEPTION 'Durable agent task store migration is required first';
    END IF;
END
$block$;

ALTER TABLE public.jas_si_agent_tasks
    ADD COLUMN IF NOT EXISTS verifier_evidence_id uuid;

CREATE TABLE IF NOT EXISTS public.jas_si_agent_evidence_records (
    evidence_id uuid PRIMARY KEY,
    task_id uuid NOT NULL
        REFERENCES public.jas_si_agent_tasks(task_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    tenant_id uuid NOT NULL
        REFERENCES public.jas_si_tenants(tenant_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    collector_id varchar(128) NOT NULL,
    verification_status varchar(32) NOT NULL,
    evidence_digest bytea NOT NULL,
    evidence_payload jsonb NOT NULL,
    collected_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT jas_si_agent_evidence_digest_length
        CHECK (octet_length(evidence_digest)=32),
    CONSTRAINT jas_si_agent_evidence_collector_nonempty
        CHECK (length(btrim(collector_id)) BETWEEN 1 AND 128),
    CONSTRAINT jas_si_agent_evidence_status_check
        CHECK (verification_status IN ('VERIFIED_SUCCESS')),
    CONSTRAINT jas_si_agent_evidence_payload_object
        CHECK (jsonb_typeof(evidence_payload)='object'
               AND octet_length(evidence_payload::text)<=65536),
    CONSTRAINT jas_si_agent_evidence_task_digest_unique
        UNIQUE (task_id,evidence_digest),
    CONSTRAINT jas_si_agent_evidence_binding_unique
        UNIQUE (evidence_id,task_id,tenant_id)
);

CREATE INDEX IF NOT EXISTS jas_si_agent_evidence_tenant_created_idx
    ON public.jas_si_agent_evidence_records(tenant_id,created_at DESC,evidence_id);

DO $block$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE conname='jas_si_agent_task_verifier_evidence_fk'
           AND conrelid='public.jas_si_agent_tasks'::regclass
    ) THEN
        ALTER TABLE public.jas_si_agent_tasks
            ADD CONSTRAINT jas_si_agent_task_verifier_evidence_fk
            FOREIGN KEY (verifier_evidence_id,task_id,tenant_id)
            REFERENCES public.jas_si_agent_evidence_records(evidence_id,task_id,tenant_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT;
    END IF;
END
$block$;

REVOKE ALL PRIVILEGES ON TABLE public.jas_si_agent_evidence_records
    FROM PUBLIC,jas_si_runtime,jas_si_provisioner,jas_si_agent_worker,jas_si_agent_verifier;
REVOKE ALL PRIVILEGES ON TABLE public.jas_si_agent_tasks
    FROM jas_si_agent_verifier;
GRANT USAGE ON SCHEMA public TO jas_si_agent_task_owner,jas_si_agent_verifier;
GRANT SELECT,INSERT,UPDATE,DELETE ON public.jas_si_agent_evidence_records
    TO jas_si_agent_task_owner;

ALTER TABLE public.jas_si_agent_evidence_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.jas_si_agent_evidence_records FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS jas_si_agent_evidence_owner_all
    ON public.jas_si_agent_evidence_records;
CREATE POLICY jas_si_agent_evidence_owner_all
    ON public.jas_si_agent_evidence_records FOR ALL
    TO jas_si_agent_task_owner USING (true) WITH CHECK (true);

GRANT CREATE ON SCHEMA public TO jas_si_agent_task_owner;
SET LOCAL ROLE jas_si_agent_task_owner;

CREATE OR REPLACE FUNCTION public.jas_si_agent_task_verification_list(
    p_limit integer DEFAULT 10
) RETURNS TABLE(
    task_id uuid,tenant_id uuid,task_type text,input_payload jsonb,
    result_payload jsonb,reported_at timestamptz
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_agent_verifier','MEMBER') THEN
        RAISE EXCEPTION 'Verifier identity is not authorized' USING ERRCODE='42501';
    END IF;
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 20 THEN
        RAISE EXCEPTION 'Invalid verification batch limit' USING ERRCODE='22023';
    END IF;
    RETURN QUERY
    SELECT q.task_id,q.tenant_id,q.task_type::text,q.input_payload,
           q.result_payload,q.reported_at
      FROM public.jas_si_agent_tasks q
     WHERE q.status='awaiting_verification'
       AND q.task_type='github.read_repository'
       AND q.result_payload IS NOT NULL
       AND q.reported_at IS NOT NULL
     ORDER BY q.reported_at,q.task_id
     LIMIT p_limit;
END;
$function$;

CREATE OR REPLACE FUNCTION public.jas_si_agent_task_finalize_success(
    p_evidence_id uuid,
    p_task_id uuid,
    p_tenant_id uuid,
    p_collector_id text,
    p_evidence_digest bytea,
    p_evidence_payload jsonb,
    p_collected_at timestamptz
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE
    v_task public.jas_si_agent_tasks%ROWTYPE;
    v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'jas_si_agent_verifier','MEMBER') THEN
        RAISE EXCEPTION 'Verifier identity is not authorized' USING ERRCODE='42501';
    END IF;
    IF p_evidence_id IS NULL OR p_task_id IS NULL OR p_tenant_id IS NULL
       OR p_collector_id IS NULL OR length(btrim(p_collector_id)) NOT BETWEEN 1 AND 128
       OR p_evidence_digest IS NULL OR octet_length(p_evidence_digest)<>32
       OR p_evidence_payload IS NULL OR pg_catalog.jsonb_typeof(p_evidence_payload)<>'object'
       OR pg_catalog.octet_length(p_evidence_payload::text)>65536
       OR p_collected_at IS NULL OR p_collected_at>v_now THEN
        RAISE EXCEPTION 'Invalid independent evidence finalization request'
            USING ERRCODE='22023';
    END IF;

    SELECT q.* INTO v_task
      FROM public.jas_si_agent_tasks q
     WHERE q.task_id=p_task_id AND q.tenant_id=p_tenant_id
     FOR UPDATE;
    IF NOT FOUND OR v_task.status<>'awaiting_verification'
       OR v_task.task_type<>'github.read_repository' THEN
        RETURN false;
    END IF;

    IF p_evidence_payload->>'collector_id' IS DISTINCT FROM p_collector_id
       OR p_evidence_payload->>'verification_status' IS DISTINCT FROM 'VERIFIED_SUCCESS'
       OR p_evidence_payload->>'task_id' IS DISTINCT FROM p_task_id::text
       OR p_evidence_payload->>'tenant_id' IS DISTINCT FROM p_tenant_id::text
       OR p_evidence_payload->>'repository' IS DISTINCT FROM v_task.input_payload->>'repository'
       OR p_evidence_payload->>'commit_sha' IS DISTINCT FROM v_task.input_payload->>'commit_sha'
       OR p_evidence_payload->>'evidence_digest' IS DISTINCT FROM pg_catalog.encode(p_evidence_digest,'hex') THEN
        RAISE EXCEPTION 'Independent evidence is not bound to the persisted task'
            USING ERRCODE='22023';
    END IF;

    INSERT INTO public.jas_si_agent_evidence_records(
        evidence_id,task_id,tenant_id,collector_id,verification_status,
        evidence_digest,evidence_payload,collected_at
    ) VALUES (
        p_evidence_id,p_task_id,p_tenant_id,p_collector_id,'VERIFIED_SUCCESS',
        p_evidence_digest,p_evidence_payload,p_collected_at
    );

    UPDATE public.jas_si_agent_tasks
       SET status='succeeded',
           verifier_evidence_id=p_evidence_id,
           completed_at=v_now,
           updated_at=v_now,
           error_code=NULL
     WHERE task_id=p_task_id AND tenant_id=p_tenant_id
       AND status='awaiting_verification';
    RETURN FOUND;
END;
$function$;

REVOKE ALL ON FUNCTION public.jas_si_agent_task_finalize_success(
    uuid,uuid,uuid,text,bytea,jsonb,timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.jas_si_agent_task_verification_list(integer)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.jas_si_agent_task_verification_list(integer)
    TO jas_si_agent_verifier;
GRANT EXECUTE ON FUNCTION public.jas_si_agent_task_finalize_success(
    uuid,uuid,uuid,text,bytea,jsonb,timestamptz
) TO jas_si_agent_verifier;

RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_agent_task_owner;

DO $block$
DECLARE v_proc oid; v_owner text;
BEGIN
    v_proc := 'public.jas_si_agent_task_verification_list(integer)'::regprocedure;
    SELECT pg_catalog.pg_get_userbyid(p.proowner) INTO v_owner
      FROM pg_catalog.pg_proc p WHERE p.oid=v_proc;
    IF v_owner<>'jas_si_agent_task_owner'
       OR NOT (SELECT p.prosecdef FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
       OR NOT (SELECT COALESCE(p.proconfig,ARRAY[]::text[])
                  @> ARRAY['search_path=pg_catalog']::text[]
                 FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
       OR EXISTS (
           SELECT 1 FROM pg_catalog.aclexplode(
               COALESCE((SELECT p.proacl FROM pg_catalog.pg_proc p WHERE p.oid=v_proc),
                        pg_catalog.acldefault('f',(SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)))
           ) acl WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'
       ) THEN
        RAISE EXCEPTION 'Verifier queue routine security boundary invalid';
    END IF;
    v_proc := 'public.jas_si_agent_task_finalize_success(uuid,uuid,uuid,text,bytea,jsonb,timestamptz)'::regprocedure;
    SELECT pg_catalog.pg_get_userbyid(p.proowner) INTO v_owner
      FROM pg_catalog.pg_proc p WHERE p.oid=v_proc;
    IF v_owner<>'jas_si_agent_task_owner'
       OR NOT (SELECT p.prosecdef FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
       OR NOT (SELECT COALESCE(p.proconfig,ARRAY[]::text[])
                  @> ARRAY['search_path=pg_catalog']::text[]
                 FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)
       OR EXISTS (
           SELECT 1 FROM pg_catalog.aclexplode(
               COALESCE((SELECT p.proacl FROM pg_catalog.pg_proc p WHERE p.oid=v_proc),
                        pg_catalog.acldefault('f',(SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.oid=v_proc)))
           ) acl WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'
       ) THEN
        RAISE EXCEPTION 'Verifier finalization routine security boundary invalid';
    END IF;
    IF pg_catalog.has_table_privilege('jas_si_agent_verifier','public.jas_si_agent_tasks','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_agent_verifier','public.jas_si_agent_tasks','UPDATE')
       OR pg_catalog.has_table_privilege('jas_si_agent_verifier','public.jas_si_agent_evidence_records','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_agent_verifier','public.jas_si_agent_evidence_records','INSERT')
       OR pg_catalog.has_table_privilege('jas_si_agent_worker','public.jas_si_agent_evidence_records','SELECT')
       OR pg_catalog.has_table_privilege('jas_si_agent_worker','public.jas_si_agent_evidence_records','INSERT') THEN
        RAISE EXCEPTION 'Verifier or worker capability role has direct table access';
    END IF;
END
$block$;
