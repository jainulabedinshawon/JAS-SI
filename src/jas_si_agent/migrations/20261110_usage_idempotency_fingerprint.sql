-- Bind each tenant idempotency key to the exact request body and API key.
-- Existing rows remain NULL and cannot be replayed as if their payload were known.
ALTER TABLE jas_si_usage_events
    ADD COLUMN IF NOT EXISTS request_fingerprint CHAR(64);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'jas_si_usage_events_request_fingerprint_format'
          AND conrelid = 'jas_si_usage_events'::regclass
    ) THEN
        ALTER TABLE jas_si_usage_events
            ADD CONSTRAINT jas_si_usage_events_request_fingerprint_format
            CHECK (
                request_fingerprint IS NULL
                OR request_fingerprint ~ '^[0-9a-f]{64}$'
            );
    END IF;
END;
$$;
