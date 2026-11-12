# Customer API-key runtime database setup

The customer portal API-key endpoints use `JAS_SI_CUSTOMER_API_KEY_DATABASE_URL`. This DSN is intentionally separate from the general API registry and customer identity DSNs.

## Required connection identity

The connection must assume PostgreSQL role `jas_si_customer_key_runtime` for every request. The role must remain:

- `NOLOGIN` (the application connects through a separately managed login role that is explicitly granted membership)
- not a superuser
- not `BYPASSRLS`
- restricted by the policies in `007_customer_api_key_self_service.sql`

The application checks both `current_user` and `session_user`: the effective role must be exactly `jas_si_customer_key_runtime`; the separate LOGIN principal must be NOINHERIT, non-superuser, non-BYPASSRLS, without CREATEDB/CREATEROLE/REPLICATION, and have exactly one direct membership in the runtime role with SET allowed and ADMIN OPTION disabled. The runtime role itself must have no role memberships. Readiness fails closed if any condition is not met. The LOGIN principal can RESET ROLE only to itself and cannot assume operator or owner roles. Do not point this DSN at the database owner, migration role, general API runtime, or a superuser connection. PostgreSQL RLS is not a security boundary for superusers, BYPASSRLS roles, or table owners unless FORCE ROW LEVEL SECURITY is configured; therefore those identities are explicitly rejected.

## Provisioning outline (operator-controlled)

1. Apply the schema migrations in dependency order through the normal migration process; do not apply them from an HTTP request or application startup:
   - First, apply the existing core tenant/API-key/audit migrations 001–006 in their repository-defined order.
   - Next, apply `20261110_customer_identity.sql` (creates the NOLOGIN identity group role and customer identity tables).
   - Then apply `20261110_customer_rate_limits.sql` (depends on the identity role and grants its shared limiter access).
   - Apply `007_customer_api_key_self_service.sql` only after the tenant, API-key, audit-chain, and provisioning-run tables/columns from the core migrations exist. It creates the NOLOGIN key-management group role and its RLS policies.
   - Apply the usage-metering/idempotency migrations only after their own prerequisites, then `20261111_usage_append_only_role_grants.sql` after the usage-events table exists (the latter safely no-ops if that table is absent).
   - Review the SQL and actual schema before every target environment; migration filenames alone are not evidence that a migration was applied.
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

For requests served by Vercel, the API prefers the platform-preserved
`x-vercel-forwarded-for` client address. If absent, it falls back to
Vercel-edge-overwritten `x-forwarded-for`. It strictly parses the first value
as an IP literal; a malformed preferred header fails closed rather than
falling through to a different caller-controlled value. In preview and
production, missing trusted proxy headers return HTTP 503; only local/test
environments may fall back to the direct peer address. The limiter stores
only an HMAC-SHA256 digest using the customer token pepper, never the raw IP.
This trust assumption is specific to Vercel; if the application moves behind
another proxy or is exposed directly, configure and test that proxy's
overwrite behavior before relying on IP-based abuse controls.

The table retains one row per observed client-IP digest. An operator-managed
retention cleanup should delete rows whose `updated_at` is older than the
chosen retention window; do not grant DELETE to the application runtime role.
