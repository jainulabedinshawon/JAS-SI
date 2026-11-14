-- Standalone JAS-SI customer identity and magic-link sessions.
-- JAS-SI owns this schema; it has no JAS Platform dependency.

CREATE TABLE IF NOT EXISTS jas_si_customer_accounts (
    account_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL UNIQUE REFERENCES jas_si_tenants(tenant_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    email VARCHAR(254) NOT NULL,
    email_normalized VARCHAR(254) NOT NULL UNIQUE,
    organization_name VARCHAR(160) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'pending',
    email_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT jas_si_customer_email_nonempty CHECK (length(btrim(email_normalized)) BETWEEN 3 AND 254),
    CONSTRAINT jas_si_customer_org_nonempty CHECK (length(btrim(organization_name)) BETWEEN 1 AND 160),
    CONSTRAINT jas_si_customer_status_check CHECK (status IN ('pending', 'active', 'suspended')),
    CONSTRAINT jas_si_customer_verified_status_check CHECK (
        (status = 'pending' AND email_verified_at IS NULL)
        OR (status IN ('active', 'suspended') AND email_verified_at IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS jas_si_customer_auth_tokens (
    token_id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES jas_si_customer_accounts(account_id) ON UPDATE RESTRICT ON DELETE CASCADE,
    token_digest BYTEA NOT NULL UNIQUE,
    purpose VARCHAR(24) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CONSTRAINT jas_si_customer_token_digest_length CHECK (octet_length(token_digest) = 32),
    CONSTRAINT jas_si_customer_token_purpose_check CHECK (purpose IN ('verify_email', 'login')),
    CONSTRAINT jas_si_customer_token_expiry_check CHECK (expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS jas_si_customer_tokens_account_purpose_idx ON jas_si_customer_auth_tokens (account_id, purpose, expires_at DESC);

CREATE TABLE IF NOT EXISTS jas_si_customer_sessions (
    session_id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES jas_si_customer_accounts(account_id) ON UPDATE RESTRICT ON DELETE CASCADE,
    token_digest BYTEA NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT jas_si_customer_session_digest_length CHECK (octet_length(token_digest) = 32),
    CONSTRAINT jas_si_customer_session_expiry_check CHECK (expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS jas_si_customer_sessions_account_idx ON jas_si_customer_sessions (account_id, expires_at DESC) WHERE revoked_at IS NULL;
REVOKE UPDATE, DELETE, TRUNCATE ON jas_si_customer_auth_tokens FROM PUBLIC;

-- Bootstrap a non-login group role. Deployment credentials must be a separate
-- LOGIN role granted membership in this role; the app DSN must SET ROLE to it.
DO $body$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jas_si_customer_runtime') THEN
        CREATE ROLE jas_si_customer_runtime NOLOGIN NOINHERIT;
    END IF;
    -- The runtime group has no role memberships and must never inherit
    -- privileges if a membership is accidentally introduced later.
    ALTER ROLE jas_si_customer_runtime NOLOGIN NOINHERIT;
END
$body$;

-- Customer identity creates tenant rows during signup but does not need to
-- enumerate or read other tenants. The tenant INSERT policy is installed by
-- migration 007 after tenant RLS is enabled.
REVOKE SELECT, UPDATE, DELETE, TRUNCATE ON TABLE public.jas_si_tenants FROM jas_si_customer_runtime;
GRANT INSERT (tenant_id, tenant_name) ON TABLE public.jas_si_tenants TO jas_si_customer_runtime;

GRANT SELECT ON TABLE public.jas_si_customer_accounts TO jas_si_customer_runtime;
GRANT INSERT (account_id, tenant_id, email, email_normalized, organization_name) ON TABLE public.jas_si_customer_accounts TO jas_si_customer_runtime;
GRANT UPDATE (status, email_verified_at, updated_at) ON TABLE public.jas_si_customer_accounts TO jas_si_customer_runtime;
GRANT SELECT ON TABLE public.jas_si_customer_auth_tokens TO jas_si_customer_runtime;
GRANT INSERT (token_id, account_id, token_digest, purpose, expires_at) ON TABLE public.jas_si_customer_auth_tokens TO jas_si_customer_runtime;
GRANT UPDATE (consumed_at) ON TABLE public.jas_si_customer_auth_tokens TO jas_si_customer_runtime;
GRANT SELECT ON TABLE public.jas_si_customer_sessions TO jas_si_customer_runtime;
GRANT INSERT (session_id, account_id, token_digest, expires_at) ON TABLE public.jas_si_customer_sessions TO jas_si_customer_runtime;
GRANT UPDATE (revoked_at) ON TABLE public.jas_si_customer_sessions TO jas_si_customer_runtime;
REVOKE DELETE, TRUNCATE ON TABLE public.jas_si_customer_accounts, public.jas_si_customer_auth_tokens, public.jas_si_customer_sessions FROM jas_si_customer_runtime;
