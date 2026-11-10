# Customer API-key runtime database setup

The customer portal API-key endpoints use `JAS_SI_CUSTOMER_API_KEY_DATABASE_URL`. This DSN is intentionally separate from the general API registry and customer identity DSNs.

## Required connection identity

The connection must assume PostgreSQL role `jas_si_customer_key_runtime` for every request. The role must remain:

- `NOLOGIN` (the application connects through a separately managed login role that is explicitly granted membership)
- not a superuser
- not `BYPASSRLS`
- restricted by the policies in `007_customer_api_key_self_service.sql`

The application checks `current_user`, `rolsuper`, and `rolbypassrls` at runtime and fails closed if the effective role is not exactly `jas_si_customer_key_runtime`. Do not point this DSN at the database owner, migration role, general API runtime, or a superuser connection. PostgreSQL RLS is not a security boundary for superusers, BYPASSRLS roles, or table owners unless FORCE ROW LEVEL SECURITY is configured; therefore those identities are explicitly rejected.

## Provisioning outline (operator-controlled)

1. Apply migrations 001–007 and the customer/usage migrations in the documented migration order through the normal migration process. Do not apply them from an HTTP request or application startup.
2. Create a dedicated LOGIN role for the customer API-key connection using the organization's secret-management process.
3. Grant that login role membership in `jas_si_customer_key_runtime` only; do not grant membership in `jas_si_provisioner`, `jas_si_runtime`, or any owner role.
4. Configure `JAS_SI_CUSTOMER_API_KEY_DATABASE_URL` with a connection option that assumes the customer role (for example, PostgreSQL `options=-c role=jas_si_customer_key_runtime` encoded appropriately in the DSN).
5. Store credentials only in deployment secret storage. Never commit the DSN or print it in logs.
6. Run the PostgreSQL RLS integration suite before enabling the customer API-key routes.

## Security behavior

- Customer session determines the tenant UUID; clients cannot submit tenant IDs. The HTTP API derives this value only from the server-validated session record.
- Create, list, and revoke use the dedicated DSN and transaction-local RLS context. The RLS policy is defense-in-depth for this trusted server-derived context.
- **Important boundary:** PostgreSQL custom settings such as `jas_si.tenant_id` are settable by a database role. RLS based on this setting does not independently authenticate a tenant against arbitrary SQL executed with the customer role. Never expose this DSN or SQL execution to customers, never accept tenant IDs from request payloads, and keep SQL parameterized. Stronger isolation against a compromised application role would require a database-verifiable signed tenant claim or per-tenant database principals; this phase does not claim that stronger guarantee.
- Key secrets are shown only once; list responses contain metadata and never the raw secret/digest.
- Create and revoke require the session CSRF cookie/header pair.
- Audit event and key lifecycle changes are transactionally coupled in the registry.
- The API rejects a database connection that can bypass RLS.

## Current status

This is deployment guidance, not evidence that a production database role, secret, migration or customer journey is configured. No production database operation is authorized or performed by this document.


## Shared customer email abuse protection

The public registration and login endpoints use the PostgreSQL table
`jas_si_customer_rate_limits` through the customer identity database role.
The migration creates the table and grants only SELECT, INSERT and UPDATE to
`jas_si_customer_runtime`; it does not grant DELETE or TRUNCATE. Apply the
new `20261110_customer_rate_limits.sql` migration before enabling these
endpoints. The limiter fails closed with HTTP 503 if the database or schema is
unavailable; it does not fall back to per-process memory.

Vercel documents that its edge overwrites `x-forwarded-for` with the
public client IP to prevent spoofing. It also documents
`x-vercel-forwarded-for` as the preserved client address when another proxy
may overwrite the generic header. The API prefers `x-vercel-forwarded-for`
and falls back to Vercel's edge-overwritten `x-forwarded-for`; it strictly
parses one IP literal and stores only an HMAC-SHA256 digest using the customer
token pepper, never the raw address. Requests that provide a malformed
preferred Vercel header fail closed rather than falling back to a different
caller-controlled header. This trust assumption is specific to requests
served through Vercel; if the application is moved behind another proxy or
exposed directly, the proxy must be configured to overwrite the forwarding
header before this IP-based control is relied upon. See
https://vercel.com/docs/headers/request-headers for the provider contract.

The table retains one row per observed client-IP digest. An operator-managed
retention cleanup should delete rows whose `updated_at` is older than the
chosen retention window; do not grant DELETE to the application runtime role.
