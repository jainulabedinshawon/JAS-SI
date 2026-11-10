-- Tenant-scoped append-only usage events. JAS-SI records technical units only;
-- JAS Platform remains authoritative for entitlement and monetary balances.
-- The composite key relationship prevents attaching another tenant's API key.
CREATE UNIQUE INDEX IF NOT EXISTS jas_si_api_keys_key_tenant_uidx
    ON jas_si_api_keys (key_id, tenant_id);

CREATE TABLE IF NOT EXISTS jas_si_usage_events (
    event_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES jas_si_tenants(tenant_id),
    api_key_id UUID NOT NULL,
    request_id VARCHAR(64) NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    operation VARCHAR(64) NOT NULL CHECK (operation IN (
        'authorization.evaluate', 'outcome.submit', 'github.evidence.verify'
    )),
    units BIGINT NOT NULL CHECK (units > 0),
    occurred_at TIMESTAMPTZ NOT NULL,
    schema_version SMALLINT NOT NULL DEFAULT 1,
    UNIQUE (tenant_id, idempotency_key),
    CONSTRAINT jas_si_usage_events_key_tenant_fk
        FOREIGN KEY (api_key_id, tenant_id)
        REFERENCES jas_si_api_keys (key_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS jas_si_usage_events_tenant_time_idx
    ON jas_si_usage_events (tenant_id, occurred_at DESC);

-- Protect against accidental row mutation, including by application roles.
CREATE OR REPLACE FUNCTION jas_si_reject_usage_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'JAS-SI usage events are append-only';
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'jas_si_usage_events_immutable'
          AND tgrelid = 'jas_si_usage_events'::regclass
          AND NOT tgisinternal
    ) THEN
        CREATE TRIGGER jas_si_usage_events_immutable
        BEFORE UPDATE OR DELETE ON jas_si_usage_events
        FOR EACH ROW EXECUTE FUNCTION jas_si_reject_usage_event_mutation();
    END IF;
END;
$$;

REVOKE UPDATE, DELETE, TRUNCATE ON jas_si_usage_events FROM PUBLIC;

-- The API process connects with the least-privilege runtime role. It needs
-- to append usage events and read the tenant's aggregate; it must never
-- mutate or delete historical usage records.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = 'jas_si_runtime'
    ) THEN
        GRANT SELECT, INSERT ON TABLE public.jas_si_usage_events TO jas_si_runtime;
        REVOKE UPDATE, DELETE, TRUNCATE ON TABLE public.jas_si_usage_events FROM jas_si_runtime;
    END IF;
END;
$$;
