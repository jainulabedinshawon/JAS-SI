-- Idempotency ledger for atomic API-key provisioning.
-- Contains identifiers only; never store raw tokens, token fragments, digests,
-- peppers, database URLs, or other credentials here.

CREATE TABLE IF NOT EXISTS jas_si_api_key_provisioning_runs (
    run_id VARCHAR(128) PRIMARY KEY,
    key_id UUID NOT NULL UNIQUE
        REFERENCES jas_si_api_keys(key_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,
    tenant_id UUID NOT NULL
        REFERENCES jas_si_tenants(tenant_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT jas_si_provisioning_run_id_nonempty
        CHECK (length(btrim(run_id)) BETWEEN 1 AND 128)
);

CREATE INDEX IF NOT EXISTS idx_jas_si_provisioning_runs_tenant_created
    ON jas_si_api_key_provisioning_runs (tenant_id, created_at);

-- Only the operator role may read/append provisioning idempotency metadata.
-- The runtime role has no need to access this table.
DO $
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = 'jas_si_provisioner'
    ) THEN
        GRANT SELECT, INSERT ON jas_si_api_key_provisioning_runs
            TO jas_si_provisioner;
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = 'jas_si_runtime'
    ) THEN
        REVOKE ALL ON jas_si_api_key_provisioning_runs
            FROM jas_si_runtime;
    END IF;
END
$;
