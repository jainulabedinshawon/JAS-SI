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

CREATE INDEX IF NOT EXISTS jas_si_customer_rate_limits_updated_idx
    ON jas_si_customer_rate_limits (updated_at);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jas_si_customer_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON TABLE public.jas_si_customer_rate_limits TO jas_si_customer_runtime';
        EXECUTE 'REVOKE DELETE, TRUNCATE ON TABLE public.jas_si_customer_rate_limits FROM jas_si_customer_runtime';
    END IF;
END
$$;
