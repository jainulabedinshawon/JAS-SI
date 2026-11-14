-- Move PostgreSQL audit-chain mutation behind one dedicated database-owned routine.
-- Runtime/provisioner may append and verify, but cannot directly rewrite history.
-- The customer-key audit wrapper delegates to this same writer so the audit
-- tables have exactly one controlled mutation boundary.

DO $$
DECLARE
    v_oid oid;
    v_role record;
BEGIN
    SELECT oid INTO v_oid
      FROM pg_catalog.pg_roles
     WHERE rolname='jas_si_audit_writer_owner';

    IF v_oid IS NULL THEN
        CREATE ROLE jas_si_audit_writer_owner
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOREPLICATION NOBYPASSRLS NOINHERIT;
        SELECT oid INTO v_oid
          FROM pg_catalog.pg_roles
         WHERE rolname='jas_si_audit_writer_owner';
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='neondb_owner'
    ) THEN
        EXECUTE
            'GRANT jas_si_audit_writer_owner TO neondb_owner '
            'WITH ADMIN FALSE, INHERIT FALSE, SET TRUE';
    END IF;

    SELECT * INTO v_role FROM pg_catalog.pg_roles WHERE oid=v_oid;
    IF v_role.rolcanlogin OR v_role.rolsuper OR v_role.rolcreatedb
       OR v_role.rolcreaterole OR v_role.rolreplication
       OR v_role.rolbypassrls OR v_role.rolinherit
       OR EXISTS (
           SELECT 1
             FROM pg_catalog.pg_auth_members m
             JOIN pg_catalog.pg_roles member_role ON member_role.oid=m.member
             JOIN pg_catalog.pg_roles grantor_role ON grantor_role.oid=m.grantor
            WHERE m.member=v_oid OR (m.roleid=v_oid AND NOT (
                (member_role.rolname='neondb_owner'
                 AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option)
                OR
                (member_role.rolname='neondb_owner'
                 AND grantor_role.rolname='cloud_admin'
                 AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option)
            ))
       ) THEN
        RAISE EXCEPTION 'Unsafe audit writer owner role configuration';
    END IF;

    IF pg_catalog.to_regclass('public.jas_si_audit_chain_state') IS NULL
       OR pg_catalog.to_regclass('public.jas_si_audit_events') IS NULL
       OR pg_catalog.to_regprocedure('public.jas_si_customer_key_canonical_jsonb(jsonb)') IS NULL
       OR pg_catalog.to_regprocedure('public.jas_si_customer_key_sha256(bytea)') IS NULL THEN
        RAISE EXCEPTION 'Audit tables and canonical hash helpers must exist first';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_runtime')
       OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_provisioner')
       OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_customer_key_owner') THEN
        RAISE EXCEPTION 'Runtime, provisioner, and customer-key owner roles are required';
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public
    TO jas_si_audit_writer_owner, jas_si_runtime, jas_si_provisioner,
       jas_si_customer_key_owner;

-- The audit owner receives only the columns required for append and verification.
GRANT SELECT (singleton,last_hash), INSERT (singleton,last_hash),
      UPDATE (last_hash)
    ON public.jas_si_audit_chain_state TO jas_si_audit_writer_owner;
GRANT SELECT (event_id,event_payload,previous_hash,event_hash),
      INSERT (event_payload,previous_hash,event_hash)
    ON public.jas_si_audit_events TO jas_si_audit_writer_owner;

-- These helper routines are owned by jas_si_customer_key_owner.
-- Grant their narrowly scoped execution rights as that owner, not as the
-- migration login (which may be neondb_owner and lack grant option).
SET LOCAL ROLE jas_si_customer_key_owner;
GRANT EXECUTE ON FUNCTION public.jas_si_customer_key_canonical_jsonb(jsonb)
    TO jas_si_audit_writer_owner, jas_si_runtime, jas_si_provisioner;
GRANT EXECUTE ON FUNCTION public.jas_si_customer_key_sha256(bytea)
    TO jas_si_audit_writer_owner;
RESET ROLE;

ALTER TABLE public.jas_si_audit_chain_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.jas_si_audit_events ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS jas_si_audit_writer_state_select
    ON public.jas_si_audit_chain_state;
CREATE POLICY jas_si_audit_writer_state_select
    ON public.jas_si_audit_chain_state FOR SELECT
    TO jas_si_audit_writer_owner USING (true);
DROP POLICY IF EXISTS jas_si_audit_writer_state_insert
    ON public.jas_si_audit_chain_state;
CREATE POLICY jas_si_audit_writer_state_insert
    ON public.jas_si_audit_chain_state FOR INSERT
    TO jas_si_audit_writer_owner WITH CHECK (true);
DROP POLICY IF EXISTS jas_si_audit_writer_state_update
    ON public.jas_si_audit_chain_state;
CREATE POLICY jas_si_audit_writer_state_update
    ON public.jas_si_audit_chain_state FOR UPDATE
    TO jas_si_audit_writer_owner USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS jas_si_audit_writer_events_select
    ON public.jas_si_audit_events;
CREATE POLICY jas_si_audit_writer_events_select
    ON public.jas_si_audit_events FOR SELECT
    TO jas_si_audit_writer_owner USING (true);
DROP POLICY IF EXISTS jas_si_audit_writer_events_insert
    ON public.jas_si_audit_events;
CREATE POLICY jas_si_audit_writer_events_insert
    ON public.jas_si_audit_events FOR INSERT
    TO jas_si_audit_writer_owner WITH CHECK (true);

DROP POLICY IF EXISTS jas_si_audit_runtime_read
    ON public.jas_si_audit_chain_state;
CREATE POLICY jas_si_audit_runtime_read
    ON public.jas_si_audit_chain_state FOR SELECT
    TO jas_si_runtime, jas_si_provisioner USING (true);
DROP POLICY IF EXISTS jas_si_audit_events_runtime_read
    ON public.jas_si_audit_events;
CREATE POLICY jas_si_audit_events_runtime_read
    ON public.jas_si_audit_events FOR SELECT
    TO jas_si_runtime, jas_si_provisioner USING (true);

GRANT SELECT ON public.jas_si_audit_chain_state, public.jas_si_audit_events
    TO jas_si_runtime, jas_si_provisioner;

GRANT CREATE ON SCHEMA public TO jas_si_audit_writer_owner;
SET LOCAL ROLE jas_si_audit_writer_owner;

CREATE OR REPLACE FUNCTION public.jas_si_audit_append_event(p_event jsonb)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog
AS $function$
DECLARE
    v_checkpoint text;
    v_previous text := pg_catalog.repeat('0',64);
    v_expected text;
    v_material bytea;
    v_row record;
BEGIN
    IF p_event IS NULL OR pg_catalog.jsonb_typeof(p_event)<>'object' THEN
        RAISE EXCEPTION 'Audit event must be a JSON object';
    END IF;

    IF pg_catalog.octet_length(pg_catalog.convert_to(
        public.jas_si_customer_key_canonical_jsonb(p_event),'UTF8'))+1024 > 65536 THEN
        RAISE EXCEPTION 'Security event exceeds 64 KiB';
    END IF;

    INSERT INTO public.jas_si_audit_chain_state(singleton,last_hash)
    VALUES(TRUE,pg_catalog.repeat('0',64))
    ON CONFLICT(singleton) DO NOTHING;

    SELECT s.last_hash::text INTO v_checkpoint
      FROM public.jas_si_audit_chain_state s
     WHERE s.singleton=TRUE
     FOR UPDATE;

    IF v_checkpoint IS NULL OR v_checkpoint !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'Invalid audit checkpoint';
    END IF;

    FOR v_row IN
        SELECT e.event_payload,
               e.previous_hash::text AS previous_hash,
               e.event_hash::text AS event_hash
          FROM public.jas_si_audit_events e
         ORDER BY e.event_id ASC
    LOOP
        IF v_row.previous_hash<>v_previous THEN
            RAISE EXCEPTION 'Audit chain link mismatch';
        END IF;

        v_material := pg_catalog.convert_to(
            '{"event":'||public.jas_si_customer_key_canonical_jsonb(v_row.event_payload)||
            ',"previous_hash":'||pg_catalog.to_jsonb(v_previous)::text||'}',
            'UTF8'
        );
        v_expected := public.jas_si_customer_key_sha256(v_material);

        IF v_row.event_hash<>v_expected THEN
            RAISE EXCEPTION 'Audit event hash mismatch';
        END IF;
        v_previous := v_row.event_hash;
    END LOOP;

    IF v_checkpoint<>v_previous THEN
        RAISE EXCEPTION 'Audit checkpoint does not match verified chain';
    END IF;

    v_material := pg_catalog.convert_to(
        '{"event":'||public.jas_si_customer_key_canonical_jsonb(p_event)||
        ',"previous_hash":'||pg_catalog.to_jsonb(v_previous)::text||'}',
        'UTF8'
    );
    v_expected := public.jas_si_customer_key_sha256(v_material);

    INSERT INTO public.jas_si_audit_events(event_payload,previous_hash,event_hash)
    VALUES(p_event,v_previous,v_expected);

    UPDATE public.jas_si_audit_chain_state
       SET last_hash=v_expected
     WHERE singleton=TRUE;
END;
$function$;

RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_audit_writer_owner;
GRANT EXECUTE ON FUNCTION public.jas_si_audit_append_event(jsonb)
    TO jas_si_runtime, jas_si_provisioner, jas_si_customer_key_owner;
REVOKE ALL ON FUNCTION public.jas_si_audit_append_event(jsonb) FROM PUBLIC;

-- Replace the customer-key-specific writer with a delegating wrapper so its
-- owner no longer needs direct mutation privileges on global audit tables.
GRANT CREATE ON SCHEMA public TO jas_si_customer_key_owner;
SET LOCAL ROLE jas_si_customer_key_owner;
CREATE OR REPLACE FUNCTION public.jas_si_customer_key_append_audit(p_event jsonb)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog
AS $function$
BEGIN
    PERFORM public.jas_si_audit_append_event(p_event);
END;
$function$;
RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_customer_key_owner;

-- Remove both table-level and column-level mutation paths, including inherited
-- grants, from all application-side writers and the former customer-key owner.
DO $$
DECLARE
    v_role text;
    v_table text;
    v_column text;
BEGIN
    FOREACH v_role IN ARRAY ARRAY[
        'jas_si_runtime','jas_si_provisioner','jas_si_customer_key_owner'
    ] LOOP
        FOREACH v_table IN ARRAY ARRAY[
            'jas_si_audit_chain_state','jas_si_audit_events'
        ] LOOP
            EXECUTE pg_catalog.format(
                'REVOKE ALL PRIVILEGES ON TABLE public.%I FROM %I',
                v_table,v_role
            );

            FOR v_column IN
                SELECT a.attname
                  FROM pg_catalog.pg_attribute a
                 WHERE a.attrelid=pg_catalog.to_regclass('public.'||v_table)
                   AND a.attnum>0 AND NOT a.attisdropped
            LOOP
                EXECUTE pg_catalog.format(
                    'REVOKE ALL PRIVILEGES (%I) ON TABLE public.%I FROM %I',
                    v_column,v_table,v_role
                );
            END LOOP;
        END LOOP;
    END LOOP;
END
$$;

-- Read-only access remains available to runtime/provisioner for independent
-- chain verification; all writes must go through the SECURITY DEFINER routine.
GRANT SELECT ON public.jas_si_audit_chain_state, public.jas_si_audit_events
    TO jas_si_runtime, jas_si_provisioner;

DO $$
DECLARE
    v_owner text;
BEGIN
    SELECT owner.rolname INTO v_owner
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
      JOIN pg_catalog.pg_roles owner ON owner.oid=p.proowner
     WHERE n.nspname='public'
       AND p.proname='jas_si_audit_append_event'
       AND pg_catalog.oidvectortypes(p.proargtypes)='jsonb'
       AND p.prosecdef
       AND p.proconfig=ARRAY['search_path=pg_catalog'];

    IF v_owner IS DISTINCT FROM 'jas_si_audit_writer_owner' THEN
        RAISE EXCEPTION 'Audit append routine owner/configuration is invalid';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM pg_catalog.pg_roles r
         WHERE r.rolname IN ('jas_si_runtime','jas_si_provisioner','jas_si_customer_key_owner')
           AND (
               pg_catalog.has_table_privilege(r.rolname,'public.jas_si_audit_chain_state','INSERT')
               OR pg_catalog.has_table_privilege(r.rolname,'public.jas_si_audit_chain_state','UPDATE')
               OR pg_catalog.has_table_privilege(r.rolname,'public.jas_si_audit_chain_state','DELETE')
               OR pg_catalog.has_table_privilege(r.rolname,'public.jas_si_audit_events','INSERT')
               OR pg_catalog.has_table_privilege(r.rolname,'public.jas_si_audit_events','UPDATE')
               OR pg_catalog.has_table_privilege(r.rolname,'public.jas_si_audit_events','DELETE')
               OR pg_catalog.has_any_column_privilege(r.rolname,'public.jas_si_audit_chain_state','INSERT')
               OR pg_catalog.has_any_column_privilege(r.rolname,'public.jas_si_audit_chain_state','UPDATE')
               OR pg_catalog.has_any_column_privilege(r.rolname,'public.jas_si_audit_events','INSERT')
               OR pg_catalog.has_any_column_privilege(r.rolname,'public.jas_si_audit_events','UPDATE')
           )
    ) THEN
        RAISE EXCEPTION 'An application role retains direct audit-chain mutation privileges';
    END IF;

    IF NOT pg_catalog.has_function_privilege(
        'jas_si_runtime','public.jas_si_audit_append_event(jsonb)','EXECUTE'
    ) OR NOT pg_catalog.has_function_privilege(
        'jas_si_provisioner','public.jas_si_audit_append_event(jsonb)','EXECUTE'
    ) THEN
        RAISE EXCEPTION 'Runtime/provisioner audit append execution grant is missing';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM pg_catalog.pg_proc p
          JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
          CROSS JOIN LATERAL pg_catalog.aclexplode(
              COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))
          ) a
         WHERE n.nspname='public'
           AND p.proname='jas_si_audit_append_event'
           AND a.grantee=0
           AND a.privilege_type='EXECUTE'
    ) THEN
        RAISE EXCEPTION 'Audit append routine must not be executable by PUBLIC';
    END IF;
END
$$;
