-- Shared serverless-safe abuse limiter for public customer email endpoints.
-- Apply after 20261110_customer_identity.sql. Raw IP addresses are never stored.
CREATE TABLE IF NOT EXISTS jas_si_customer_rate_limits (
    bucket_key BYTEA PRIMARY KEY,
    window_started_at TIMESTAMPTZ NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT jas_si_customer_rate_bucket_digest_length CHECK (octet_length(bucket_key) = 32),
    CONSTRAINT jas_si_customer_rate_count_positive CHECK (request_count > 0)
);

-- This baseline migration runs before the dedicated-owner migration on
-- first install, and is replayed after that ownership transfer in clean-chain
-- idempotency tests. Skip DDL once the dedicated owner owns the relation.
DO $migration$
DECLARE
    v_table_owner text;
BEGIN
    SELECT pg_catalog.pg_get_userbyid(c.relowner)
      INTO v_table_owner
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
     WHERE n.nspname='public' AND c.relname='jas_si_customer_rate_limits';

    IF v_table_owner = 'jas_si_customer_rate_limit_owner' THEN
        RETURN;
    END IF;

    IF v_table_owner IS DISTINCT FROM current_user THEN
        RAISE EXCEPTION 'Unexpected owner % for customer rate-limit table during baseline migration', v_table_owner;
    END IF;

    EXECUTE 'CREATE INDEX IF NOT EXISTS jas_si_customer_rate_limits_updated_idx ON public.jas_si_customer_rate_limits (updated_at)';

    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'jas_si_customer_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON TABLE public.jas_si_customer_rate_limits TO jas_si_customer_runtime';
        EXECUTE 'REVOKE DELETE, TRUNCATE ON TABLE public.jas_si_customer_rate_limits FROM jas_si_customer_runtime';
    END IF;
END
$migration$;
