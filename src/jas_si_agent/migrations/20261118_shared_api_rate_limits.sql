-- Shared strict sliding-window limiter for all /v1/* API requests.
-- Raw IP addresses are never persisted; only a separately peppered digest is stored.
DO $block$
DECLARE v_owner oid;
BEGIN
    SELECT oid INTO v_owner FROM pg_catalog.pg_roles
    WHERE rolname='jas_si_api_rate_limit_owner';
    IF v_owner IS NULL THEN
        CREATE ROLE jas_si_api_rate_limit_owner NOLOGIN NOSUPERUSER NOCREATEDB
            NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
        SELECT oid INTO v_owner FROM pg_catalog.pg_roles
        WHERE rolname='jas_si_api_rate_limit_owner';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='neondb_owner') THEN
        GRANT jas_si_api_rate_limit_owner TO neondb_owner
            WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles r
        WHERE r.oid=v_owner AND (r.rolcanlogin OR r.rolsuper OR r.rolcreatedb
          OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR r.rolinherit)
    ) OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_auth_members m
        JOIN pg_catalog.pg_roles member_role ON member_role.oid=m.member
        JOIN pg_catalog.pg_roles grantor ON grantor.oid=m.grantor
        WHERE m.member=v_owner OR (m.roleid=v_owner AND NOT (
          (member_role.rolname='neondb_owner' AND NOT m.admin_option
            AND NOT m.inherit_option AND m.set_option)
          OR (member_role.rolname='neondb_owner' AND grantor.rolname='cloud_admin'
            AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option)
        ))
    ) THEN
        RAISE EXCEPTION 'Unsafe API rate-limit owner role configuration';
    END IF;
END
$block$;

GRANT USAGE ON SCHEMA public TO jas_si_api_rate_limit_owner, jas_si_runtime;
SET LOCAL ROLE jas_si_api_rate_limit_owner;
CREATE TABLE IF NOT EXISTS public.jas_si_api_rate_limits (
    bucket_key bytea PRIMARY KEY CHECK (octet_length(bucket_key)=32),
    request_times timestamptz[] NOT NULL DEFAULT ARRAY[]::timestamptz[],
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS jas_si_api_rate_limits_updated_at_idx
    ON public.jas_si_api_rate_limits(updated_at);

CREATE OR REPLACE FUNCTION public.jas_si_api_rate_limit_check(
    p_bucket_key bytea, p_limit integer, p_window_seconds integer
) RETURNS TABLE(allowed boolean, remaining integer, retry_after_seconds integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE
    v_times timestamptz[];
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_cutoff timestamptz;
    v_count integer;
    v_retry integer := 0;
BEGIN
    IF p_bucket_key IS NULL OR pg_catalog.octet_length(p_bucket_key) <> 32
       OR p_limit IS NULL OR p_limit < 1
       OR p_window_seconds IS NULL OR p_window_seconds < 1
       OR p_window_seconds > 604800 THEN
        RAISE EXCEPTION 'Invalid API rate-limit input' USING ERRCODE='22023';
    END IF;
    v_cutoff := v_now - (p_window_seconds * interval '1 second');

    INSERT INTO public.jas_si_api_rate_limits(bucket_key,request_times,updated_at)
    VALUES(p_bucket_key,ARRAY[]::timestamptz[],v_now)
    ON CONFLICT(bucket_key) DO NOTHING;

    SELECT request_times INTO v_times
      FROM public.jas_si_api_rate_limits
     WHERE bucket_key=p_bucket_key FOR UPDATE;

    SELECT COALESCE(array_agg(item ORDER BY item),ARRAY[]::timestamptz[])
      INTO v_times
      FROM pg_catalog.unnest(v_times) AS item
     WHERE item > v_cutoff;
    v_count := pg_catalog.cardinality(v_times);

    IF v_count >= p_limit THEN
        v_retry := GREATEST(1,CEIL(EXTRACT(EPOCH FROM (v_times[1] +
            (p_window_seconds * interval '1 second') - v_now)))::integer);
        allowed := false;
        remaining := 0;
        retry_after_seconds := v_retry;
    ELSE
        v_times := pg_catalog.array_append(v_times,v_now);
        allowed := true;
        remaining := GREATEST(0,p_limit-v_count-1);
        retry_after_seconds := 0;
    END IF;

    UPDATE public.jas_si_api_rate_limits
       SET request_times=v_times,updated_at=v_now
     WHERE bucket_key=p_bucket_key;

    -- Bound cleanup work per request; indexed and capped to 32 rows.
    DELETE FROM public.jas_si_api_rate_limits
     WHERE bucket_key IN (
       SELECT bucket_key FROM public.jas_si_api_rate_limits
        WHERE updated_at < v_now - GREATEST(p_window_seconds * 2,3600) * interval '1 second'
          AND bucket_key <> p_bucket_key
        ORDER BY updated_at
        LIMIT 32
     );
    RETURN NEXT;
END;
$function$;
REVOKE ALL ON TABLE public.jas_si_api_rate_limits FROM PUBLIC, jas_si_runtime;
REVOKE ALL ON FUNCTION public.jas_si_api_rate_limit_check(bytea,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.jas_si_api_rate_limit_check(bytea,integer,integer) TO jas_si_runtime;
RESET ROLE;
