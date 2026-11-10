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

Apply the existing tenant foundation migration first, then `20261110_customer_identity.sql`, using a migration/admin role. The dedicated customer role receives only the tenant insert/select and customer account/token/session operations required by this flow. It receives no API-key, usage-event, audit-event, or tenant-status mutation privileges.

Do not run these commands against Production until the user explicitly approves the migration and the database owner has reviewed the target role and grants.

## API

- `GET /customer`: customer portal.
- `POST /v1/customer/register`: email + organization registration; generic 202 response.
- `POST /v1/customer/verify-email`: consume verification token.
- `POST /v1/customer/login`: request a sign-in email; generic 202 response.
- `POST /v1/customer/session`: consume one-time login token and set cookies.
- `GET /v1/customer/me`: current customer session.
- `POST /v1/customer/logout`: revoke session; CSRF header required.

All customer endpoints are covered by the existing per-IP `/v1/` rate limiter. A distributed limiter and abuse monitoring remain follow-up hardening before broad public launch.

## Explicitly not included yet

Self-service API-key listing/creation/revocation, customer usage dashboard, billing plan changes, checkout, payment gateway, invoices, and JAS Platform linking are not implemented by this phase. API-key provisioning remains operator-controlled until a separately reviewed tenant-scoped provisioning design is ready.
