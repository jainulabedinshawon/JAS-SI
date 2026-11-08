-- JAS-SI API key registry and tenant foundation.
-- API keys are provisioned by an operator-only command, never by a public endpoint.
-- secret_digest stores HMAC-SHA256(pepper, random_secret), never the raw secret.

CREATE TABLE IF NOT EXISTS jas_si_tenants (
    tenant_id UUID PRIMARY KEY,
    tenant_name VARCHAR(120) NOT NULL UNIQUE,
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT jas_si_tenant_status_check
        CHECK (status IN ('active', 'suspended')),
    CONSTRAINT jas_si_tenant_name_nonempty
        CHECK (length(btrim(tenant_name)) BETWEEN 1 AND 120)
);

CREATE TABLE IF NOT EXISTS jas_si_api_keys (
    key_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL
        REFERENCES jas_si_tenants(tenant_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,
    key_name VARCHAR(120) NOT NULL,
    key_prefix VARCHAR(48) NOT NULL,
    secret_digest BYTEA NOT NULL,
    pepper_version SMALLINT NOT NULL DEFAULT 1,
    scopes TEXT[] NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    created_by VARCHAR(120) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,

    CONSTRAINT jas_si_api_key_digest_length
        CHECK (octet_length(secret_digest) = 32),
    CONSTRAINT jas_si_api_key_pepper_version
        CHECK (pepper_version > 0),
    CONSTRAINT jas_si_api_key_scopes_nonempty
        CHECK (cardinality(scopes) > 0),
    CONSTRAINT jas_si_api_key_status_check
        CHECK (status IN ('active', 'revoked')),
    CONSTRAINT jas_si_api_key_name_nonempty
        CHECK (length(btrim(key_name)) BETWEEN 1 AND 120),
    CONSTRAINT jas_si_api_key_creator_nonempty
        CHECK (length(btrim(created_by)) BETWEEN 1 AND 120),
    CONSTRAINT jas_si_api_key_revocation_consistency
        CHECK (
            (status = 'active' AND revoked_at IS NULL)
            OR (status = 'revoked' AND revoked_at IS NOT NULL)
        ),
    CONSTRAINT jas_si_api_key_expiry_after_creation
        CHECK (expires_at IS NULL OR expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS idx_jas_si_api_keys_tenant_status
    ON jas_si_api_keys (tenant_id, status);

CREATE INDEX IF NOT EXISTS idx_jas_si_api_keys_active_expiry
    ON jas_si_api_keys (expires_at)
    WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_jas_si_api_keys_prefix
    ON jas_si_api_keys (key_prefix);

-- Prevent accidental duplicate display prefixes while retaining a fast lookup.
CREATE UNIQUE INDEX IF NOT EXISTS idx_jas_si_api_keys_unique_prefix
    ON jas_si_api_keys (key_prefix);
