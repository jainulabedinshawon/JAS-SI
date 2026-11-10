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

- Customer session determines the tenant UUID; clients cannot submit tenant IDs.
- Create, list, and revoke use the dedicated DSN and tenant transaction-local RLS context.
- Key secrets are shown only once; list responses contain metadata and never the raw secret/digest.
- Create and revoke require the session CSRF cookie/header pair.
- Audit event and key lifecycle changes are transactionally coupled in the registry.
- The API rejects a database connection that can bypass RLS.

## Current status

This is deployment guidance, not evidence that a production database role, secret, migration or customer journey is configured. No production database operation is authorized or performed by this document.
