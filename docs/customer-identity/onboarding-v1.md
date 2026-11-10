# Standalone customer identity and onboarding v1

**Status:** Implementation branch; not deployed. Production database migration and secrets remain separate approval/configuration gates.

## Customer journey implemented in this phase

1. Customer opens `/customer`.
2. Registration creates a pending tenant/account and sends a one-time email verification link.
3. Verification link is single-use and expires after 24 hours.
4. Customer requests a sign-in link; unknown and pending accounts receive the same public response.
5. Sign-in link is single-use and expires after 15 minutes.
6. Successful sign-in creates a seven-day server-side session. The session token is stored only as an HMAC digest in PostgreSQL and returned only as an HttpOnly cookie.
7. Logout revokes the session. Mutating session action requires the same-site CSRF token.

Tokens are placed in the URL fragment, not query parameters, so browsers do not send them in HTTP requests or Referer headers. Public API responses never contain one-time tokens. Email delivery failures are recorded without exposing account existence or SMTP details.

## Required isolated configuration

- `JAS_SI_CUSTOMER_DATABASE_URL`: connection URL for the dedicated `jas_si_customer_runtime` database role. Do not reuse the general application or API-key provisioner role.
- `JAS_SI_CUSTOMER_API_KEY_DATABASE_URL`: connection URL for the separate `jas_si_customer_key_runtime` role. This role is only for tenant-scoped API-key self-service; it must not be reused by the API-key authenticator or operator provisioner.
- `JAS_SI_CUSTOMER_TOKEN_PEPPER`: independent random secret with at least 32 UTF-8 bytes.
- `JAS_SI_CUSTOMER_SMTP_HOST`, `JAS_SI_CUSTOMER_SMTP_PORT`, `JAS_SI_CUSTOMER_SMTP_SENDER`.
- `JAS_SI_CUSTOMER_SMTP_USERNAME` and `JAS_SI_CUSTOMER_SMTP_PASSWORD`: both set or both omitted, according to provider requirements.
- `JAS_SI_CUSTOMER_PUBLIC_URL`: HTTPS origin of the deployed customer portal. Defaults to `https://jas-si.vercel.app`.

The SMTP adapter uses STARTTLS on normal SMTP ports and SMTP-over-TLS on port 465. Credentials and peppers must be stored in the deployment secret manager, never in source control.

## Database migration order and role

The identity migration depends on the tenant table from `002_create_tenant_api_keys.sql`. Create the dedicated login role before applying `20261110_customer_identity.sql`, so its conditional least-privilege grants are applied:

```sql
CREATE ROLE jas_si_customer_runtime LOGIN PASSWORD '<managed-secret>';
GRANT CONNECT ON DATABASE <database_name> TO jas_si_customer_runtime;
GRANT USAGE ON SCHEMA public TO jas_si_customer_runtime;
```

Apply the existing tenant and audit migrations in the repository's documented order, then apply `20261110_customer_identity.sql` followed by `20261110_customer_rate_limits.sql`, using a migration/admin role. The shared rate-limit migration depends on the identity migration and grants the customer identity runtime only SELECT, INSERT and UPDATE on its bucket table. Before applying `007_customer_api_key_self_service.sql`, create the dedicated key-management login role and grant only database connection/schema usage:

```sql
CREATE ROLE jas_si_customer_key_runtime LOGIN PASSWORD '<managed-secret>';
GRANT CONNECT ON DATABASE <database_name> TO jas_si_customer_key_runtime;
GRANT USAGE ON SCHEMA public TO jas_si_customer_key_runtime;
```

The customer identity role receives only tenant insert/select and customer account/token/session operations. The separate customer key role receives tenant-scoped key metadata and audited issue/revoke privileges; PostgreSQL row-level security restricts its key operations to the transaction-local `jas_si.tenant_id`. It receives no usage-event, tenant-status, or general audit mutation privileges. Do not use the key-management role for API-key authentication or operator provisioning.

Do not run these commands against Production until the user explicitly approves the migration and the database owner has reviewed the target role and grants.

## API

- `GET /customer`: customer portal.
- `POST /v1/customer/register`: email + organization registration; generic 202 response.
- `POST /v1/customer/verify-email`: consume verification token.
- `POST /v1/customer/login`: request a sign-in email; generic 202 response.
- `POST /v1/customer/session`: consume one-time login token and set cookies.
- `GET /v1/customer/me`: current customer session.
- `POST /v1/customer/logout`: revoke session; CSRF header required.
- `GET /plans`: public plan catalogue; paid plans remain preview-only.
- `GET /v1/customer/usage`: read the signed-in tenant's last-30-day technical usage and current Free quota; no monetary balance is inferred.
- `GET /v1/customer/api-keys`: list the signed-in tenant's non-secret API-key metadata.
- `POST /v1/customer/api-keys`: issue a scoped API key; token is returned once and expires within 1–365 days.
- `POST /v1/customer/api-keys/{key_id}/revoke`: revoke only a key belonging to the signed-in tenant; CSRF header required.

Registration and login email-triggering endpoints use a shared PostgreSQL-backed abuse limiter. It stores an HMAC-SHA256 digest of the client IP (not the raw address), coordinates requests across serverless instances, and fails closed when its database table or connection is unavailable. On Vercel, it trusts the platform-preserved `x-vercel-forwarded-for` header first and the Vercel-edge-overwritten `x-forwarded-for` header second; malformed preferred values and missing trusted proxy headers in Preview/Production fail closed. The shared limiter migration must be applied before these endpoints are enabled. Other `/v1/` routes continue to use the API's general rate limiter. The rate-limit table retains one row per observed IP digest; retention cleanup is operator-managed because the application role has no DELETE privilege.

## Explicitly not included yet

The API-key self-service endpoints, PostgreSQL RLS migration, customer usage endpoint and portal controls are implemented on this branch, but remain unmerged and not deployed. Billing plan changes, checkout, manual TrxID intake/reconciliation, payment gateway, invoices, and JAS Platform linking are not implemented by this phase. Customer API-key self-service remains disabled until the dedicated database role, migration and pepper are configured and reviewed. Customer registration/login also remain unavailable until the dedicated identity role, identity + shared rate-limit migrations, token pepper and SMTP delivery are configured and verified.
