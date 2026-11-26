# GitHub App Tenant Installation Binding

## Purpose

Bind a tenant to a GitHub App installation and an explicitly verified repository allowlist. The database resolver is the authority for whether a Worker or Verifier may request a repository-scoped credential.

## Implemented on the Main-based consolidation branch

- A PostgreSQL migration creates tenant-owned installation and repository records.
- New records default to `pending`; no installation or repository is activated automatically.
- Active resolution requires an active tenant, active installation, active repository row, and non-null verification timestamps.
- Worker and Verifier receive EXECUTE on one SECURITY DEFINER resolver; they do not receive direct table access.
- The resolver uses a fixed `search_path=pg_catalog`, checks the authenticated session login's membership in an approved host capability role, validates repository syntax, and returns no row for a cross-tenant or inactive binding.
- A Python adapter calls only the database resolver. It does not read installation tables.
- The GitHub App issuer retains least privilege: one repository and `contents:read` (plus GitHub's implicit `metadata:read` only). The App private key is not wired into Worker or Verifier supervisors.
- The existing PostgreSQL 16 clean migration replay workflow includes the migration and tests own-tenant resolution, cross-tenant denial, and direct table-read denial for both host roles.

## Security and operational limits

- This migration is not applied to Neon by this change.
- The migration does not implement trusted GitHub App onboarding or prove installation ownership. Rows must remain pending until a separately authenticated callback/reconciliation process verifies ownership and repository membership.
- No installation token is minted by this database migration.
- Worker and Verifier supervisors remain public-repository-only. Private-repository execution stays disabled until an authenticated, task-bound capability Broker is implemented and independently tested.
- No App private key, DSN, or other secret is provisioned by this change.
- PostgreSQL CI proves behavior on an ephemeral PostgreSQL 16 instance; it is not Neon staging or production evidence.

## Completion status

- Migration and resolver source: implemented on this branch.
- Python unit tests: added; CI pending.
- PostgreSQL role/RLS replay tests: added to the existing clean replay workflow; CI pending.
- Neon staging: not applied / not verified.
- Production: not applied / not verified.
- Trusted onboarding and Broker-mediated private repository access: not implemented by this change.
