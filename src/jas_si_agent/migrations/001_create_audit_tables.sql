CREATE TABLE IF NOT EXISTS jas_si_audit_chain_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE,
    last_hash CHAR(64) NOT NULL,

    CONSTRAINT jas_si_audit_singleton_check
        CHECK (singleton = TRUE),

    CONSTRAINT jas_si_audit_hash_check
        CHECK (last_hash ~ '^[0-9a-f]{64}$')
);

CREATE TABLE IF NOT EXISTS jas_si_audit_events (
    event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    event_payload JSONB NOT NULL,

    previous_hash CHAR(64) NOT NULL,
    event_hash CHAR(64) NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT jas_si_previous_hash_check
        CHECK (previous_hash ~ '^[0-9a-f]{64}$'),

    CONSTRAINT jas_si_event_hash_check
        CHECK (event_hash ~ '^[0-9a-f]{64}$')
);

CREATE INDEX IF NOT EXISTS
    idx_jas_si_audit_events_created_at
ON jas_si_audit_events (created_at);
