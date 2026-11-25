-- Put customer email rate-limit state behind a dedicated database-owned routine.
-- The runtime may request a decision but cannot read, rewrite, or delete buckets.
-- Expired keyed-IP buckets are removed in bounded batches to cap table growth.

DO $block$
DECLARE
    v_owner oid;
BEGIN
    SELECT oid INTO v_owner FROM pg_catalog.pg_roles
     WHERE rolname='jas_si_customer_rate_limit_owner';
    IF v_owner IS NULL THEN
        CREATE ROLE jas_si_customer_rate_limit_owner
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOREPLICATION NOBYPASSRLS NOINHERIT;
        SELECT oid INTO v_owner FROM pg_catalog.pg_roles
         WHERE rolname='jas_si_customer_rate_limit_owner';
    END IF;

    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='neondb_owner') THEN
        GRANT jas_si_customer_rate_limit_owner TO neondb_owner
            WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles r
         WHERE r.oid=v_owner AND (
             r.rolcanlogin OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole
             OR r.rolreplication OR r.rolbypassrls OR r.rolinherit
         )
    ) OR EXISTS (
        SELECT 1
          FROM pg_catalog.pg_auth_members m
          JOIN pg_catalog.pg_roles member_role ON member_role.oid=m.member
          JOIN pg_catalog.pg_roles grantor ON grantor.oid=m.grantor
         WHERE m.member=v_owner OR (m.roleid=v_owner AND NOT (
             (member_role.rolname='neondb_owner'
              AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option)
             OR
             (member_role.rolname='neondb_owner'
              AND grantor.rolname='cloud_admin'
              AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option)
         ))
    ) THEN
        RAISE EXCEPTION 'Unsafe customer rate-limit owner role configuration';
    END IF;

    IF pg_catalog.to_regclass('public.jas_si_customer_rate_limits') IS NULL
       OR NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_customer_runtime'
       )
       OR NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_runtime'
       )
       OR NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_provisioner'
       ) THEN
        RAISE EXCEPTION 'Customer rate-limit table and all runtime roles are required';
    END IF;
END
$block$;

GRANT USAGE ON SCHEMA public
    TO jas_si_customer_rate_limit_owner, jas_si_customer_runtime;

-- PostgreSQL requires the new owner to have CREATE on the containing
-- schema before ownership can be transferred. Grant it temporarily, then
-- revoke it after the owner-bound SECURITY DEFINER routine is installed.
GRANT CREATE ON SCHEMA public TO jas_si_customer_rate_limit_owner;

-- Preserve existing rate-limit buckets while transferring ownership.
ALTER TABLE public.jas_si_customer_rate_limits
    OWNER TO jas_si_customer_rate_limit_owner;

SET LOCAL ROLE jas_si_customer_rate_limit_owner;

CREATE OR REPLACE FUNCTION public.jas_si_customer_rate_limit_check(
    p_bucket_key bytea, p_limit integer, p_window_seconds integer
) RETURNS TABLE(allowed boolean, retry_after_seconds integer)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog
AS $function$
DECLARE
    v_window_started_at timestamptz;
    v_request_count integer;
    v_now timestamptz;
    v_created boolean := false;
BEGIN
    IF p_bucket_key IS NULL OR pg_catalog.octet_length(p_bucket_key)<>32
       OR p_limit IS NULL OR p_limit<1
       OR p_window_seconds IS NULL OR p_window_seconds<1
       OR p_window_seconds>604800 THEN
        RAISE EXCEPTION 'Invalid customer rate-limit input' USING ERRCODE='22023';
    END IF;

    INSERT INTO public.jas_si_customer_rate_limits
        (bucket_key,window_started_at,request_count,updated_at)
    VALUES (p_bucket_key,pg_catalog.clock_timestamp(),1,pg_catalog.clock_timestamp())
    ON CONFLICT (bucket_key) DO NOTHING
    RETURNING true INTO v_created;

    v_now := pg_catalog.clock_timestamp();
    IF v_created THEN
        -- The INSERT already counted this request; do not increment it again.
        v_window_started_at := v_now;
        v_request_count := 1;
    ELSE
        SELECT r.window_started_at,r.request_count
          INTO v_window_started_at,v_request_count
          FROM public.jas_si_customer_rate_limits r
         WHERE r.bucket_key=p_bucket_key
         FOR UPDATE;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'Customer rate-limit bucket unavailable';
        END IF;

        -- Decide only after obtaining the per-IP row lock.
        v_now := pg_catalog.clock_timestamp();
        IF v_window_started_at <= v_now-(p_window_seconds*interval '1 second') THEN
            v_window_started_at := v_now;
            v_request_count := 1;
        ELSE
            v_request_count := v_request_count+1;
        END IF;

        UPDATE public.jas_si_customer_rate_limits
           SET window_started_at=v_window_started_at,
               request_count=v_request_count,
               updated_at=v_now
         WHERE bucket_key=p_bucket_key;
    END IF;

    allowed := v_request_count<=p_limit;
    retry_after_seconds := CASE
        WHEN allowed THEN 0
        ELSE GREATEST(1,CEIL(EXTRACT(EPOCH FROM (
            v_window_started_at+(p_window_seconds*interval '1 second')-v_now
        )))::integer)
    END;

    -- Match the API limiter's 14-day retention and cap each request's cleanup.
    DELETE FROM public.jas_si_customer_rate_limits
     WHERE bucket_key IN (
         SELECT r.bucket_key
           FROM public.jas_si_customer_rate_limits r
          WHERE r.updated_at < v_now-interval '14 days'
            AND r.bucket_key<>p_bucket_key
          ORDER BY r.updated_at
          LIMIT 32
     );

    RETURN NEXT;
END;
$function$;

REVOKE ALL ON FUNCTION public.jas_si_customer_rate_limit_check(bytea,integer,integer)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.jas_si_customer_rate_limit_check(bytea,integer,integer)
    TO jas_si_customer_runtime;

RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM jas_si_customer_rate_limit_owner;

-- No application role may inspect or mutate bucket state directly. The
-- database-owned routine is the only permitted access path. Revoke legacy
-- table and column grants from all application roles, including inherited
-- PUBLIC-effective grants, before asserting the effective boundary.
REVOKE ALL PRIVILEGES ON TABLE public.jas_si_customer_rate_limits
    FROM PUBLIC, jas_si_customer_runtime, jas_si_runtime, jas_si_provisioner;
DO $revoke_columns$
DECLARE
    v_column text;
BEGIN
    FOR v_column IN
        SELECT a.attname
          FROM pg_catalog.pg_attribute a
         WHERE a.attrelid='public.jas_si_customer_rate_limits'::regclass
           AND a.attnum>0 AND NOT a.attisdropped
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL PRIVILEGES (%I) ON TABLE public.jas_si_customer_rate_limits FROM PUBLIC, jas_si_customer_runtime, jas_si_runtime, jas_si_provisioner',
            v_column
        );
    END LOOP;
END
$revoke_columns$;

DO $assert_runtime_acl$
DECLARE
    v_role text;
BEGIN
    FOREACH v_role IN ARRAY ARRAY[
        'jas_si_customer_runtime','jas_si_runtime','jas_si_provisioner'
    ] LOOP
        IF pg_catalog.has_table_privilege(v_role,'public.jas_si_customer_rate_limits','SELECT')
           OR pg_catalog.has_table_privilege(v_role,'public.jas_si_customer_rate_limits','INSERT')
           OR pg_catalog.has_table_privilege(v_role,'public.jas_si_customer_rate_limits','UPDATE')
           OR pg_catalog.has_table_privilege(v_role,'public.jas_si_customer_rate_limits','DELETE')
           OR pg_catalog.has_table_privilege(v_role,'public.jas_si_customer_rate_limits','TRUNCATE')
           OR pg_catalog.has_table_privilege(v_role,'public.jas_si_customer_rate_limits','REFERENCES')
           OR pg_catalog.has_table_privilege(v_role,'public.jas_si_customer_rate_limits','TRIGGER')
           OR pg_catalog.has_any_column_privilege(v_role,'public.jas_si_customer_rate_limits','SELECT')
           OR pg_catalog.has_any_column_privilege(v_role,'public.jas_si_customer_rate_limits','INSERT')
           OR pg_catalog.has_any_column_privilege(v_role,'public.jas_si_customer_rate_limits','UPDATE')
           OR pg_catalog.has_any_column_privilege(v_role,'public.jas_si_customer_rate_limits','REFERENCES') THEN
            RAISE EXCEPTION '% retains direct customer rate-limit table privileges',v_role;
        END IF;
    END LOOP;
END
$assert_runtime_acl$;
