-- Tenant-scoped append-only usage events. JAS-SI records technical units only;
-- JAS Platform remains authoritative for entitlement and monetary balances.
CREATE TABLE IF NOT EXISTS jas_si_usage_events (
    event_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES jas_si_tenants(tenant_id),
    api_key_id UUID NOT NULL REFERENCES jas_si_api_keys(key_id),
    request_id VARCHAR(64) NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    operation VARCHAR(64) NOT NULL CHECK (operation IN (
        'authorization.evaluate', 'outcome.submit', 'github.evidence.verify'
    )),
    units BIGINT NOT NULL CHECK (units > 0),
    occurred_at TIMESTAMPTZ NOT NULL,
    schema_version SMALLINT NOT NULL DEFAULT 1,
    UNIQUE (tenant_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS jas_si_usage_events_tenant_time_idx
    ON jas_si_usage_events (tenant_id, occurred_at DESC);
