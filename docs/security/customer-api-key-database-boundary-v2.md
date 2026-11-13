# Customer API-Key Database Boundary v2 — Implementation and Verification

**Status:** Implemented on PR #36's Draft branch; PostgreSQL 16 integration tests pass. Not merged or deployed. No staging or production migration has been applied.

## Threat model

The previous customer-key role trusted the mutable `jas_si.tenant_id` GUC and had direct privileges on global audit tables. A database credential holder could change the GUC, read audit history, or attempt to manipulate the audit checkpoint. RLS based on a caller-settable GUC is not an independent tenant authorization boundary.

## Implemented role separation

- `jas_si_customer_key_runtime` is a NOLOGIN group role. It has no direct table/column privileges on tenant, API-key, provisioning-run, audit-event, audit-checkpoint, or customer identity tables.
- `jas_si_customer_key_owner` is NOLOGIN, NOSUPERUSER, NOBYPASSRLS, NOINHERIT, and has no role memberships. It owns the SECURITY DEFINER routines and receives only required table/column privileges and constrained RLS policies.
- The existing customer identity boundary uses its separate `jas_si_customer_identity_owner` and `jas_si_customer_runtime` roles.
- Customer key runtime receives EXECUTE only on the three customer API-key entry points. PUBLIC receives no EXECUTE on these routines or the internal audit helpers.
- SECURITY DEFINER routines use `search_path=pg_catalog` and schema-qualified object references. The owner role's temporary CREATE privilege on `public` is revoked after function ownership is transferred.

## Session-derived tenant authorization

Every customer key operation passes only the HMAC-SHA256 digest of the browser session token, calculated with `JAS_SI_CUSTOMER_TOKEN_PEPPER`. The database independently joins the session, customer account, and tenant, requiring:

- a matching 32-byte session digest;
- session not revoked and not expired;
- active, verified customer account;
- active tenant.

The routine derives `account_id` and `tenant_id` from those records. The caller cannot supply a tenant UUID. It ignores `jas_si.tenant_id` for authorization. Issue, list, and revoke are constrained to the derived tenant; revoke also predicates on that tenant.

## Customer routines

Migration `20261113_customer_api_key_routines.sql` installs:

- `customer_api_key_issue`: validates the live session, key prefix, 32-byte digest, pepper version, allowed/unique scopes, expiry, and run ID; inserts the key and idempotency row; appends the audit event and advances the checkpoint in the same transaction.
- `customer_api_key_list`: validates the live session and returns non-secret metadata for the derived tenant.
- `customer_api_key_revoke`: validates the live session and revokes only an active key belonging to the derived tenant, with an atomic audit append.

The API generates the random secret and stores only its HMAC digest. The raw key is returned once and never persisted. The API's customer endpoints use these new methods; the older operator provisioning methods remain separate.

## Audit-chain compatibility and verification

The database append routine serializes JSONB recursively with sorted object keys, compact separators, UTF-8, and JSON string escaping; it builds the same `{"event": ..., "previous_hash": ...}` material and SHA-256 digest as the existing Python implementation. It locks the singleton checkpoint, re-verifies the complete historical event chain before appending, and updates the checkpoint atomically. It does not replace full-chain verification with a last-row/checkpoint-only comparison.

The PostgreSQL integration suite exercises an existing Python-written Unicode/nested/decimal event followed by a SQL-routine append and verifies the resulting chain with the independent Python verifier. This is a compatibility fixture, not a claim that every possible PostgreSQL JSONB numeric edge case has been exhaustively tested.

## Verification evidence

The latest PR head at the time of this document is `b0254610589af4c77fb4acf1e1ab527994e9bb5e`.

- PostgreSQL 16 integration: 91 tests passed, including session-derived tenant isolation, forged/expired session rejection, GUC spoofing resistance, direct table access denial, and Python/SQL audit-chain compatibility.
- Separate PostgreSQL audit integration: 50 tests passed.
- Agent authorization, core package, dependency lock, Docker, Vercel Python 3.12 compatibility, live console, security event persistence, and post-merge security verification workflows passed.
- The full API-key registry integration workflow and all ten standard CI workflows completed successfully on this head.

These results establish branch-level CI evidence only. They do not prove the production/staging schema has been migrated or that the live customer journey is enabled.

## Migration order and operational gates

Apply only through an operator-controlled migration process, after checking the actual target schema and roles:

1. Core migrations `001`–`006`.
2. `007_customer_api_key_self_service.sql` after tenant, API-key, audit, and provisioning tables exist.
3. `20261110_customer_identity.sql`.
4. `20261112_customer_identity_routines.sql` after the base identity migration and migration 007.
5. `20261113_customer_api_key_routines.sql` after migrations 007 and 20261112.
6. Customer rate-limit and usage migrations in their documented dependency order.

The customer key DSN must use a separately managed LOGIN principal that is a member only of `jas_si_customer_key_runtime`, with `NOINHERIT` and the connection configured to assume the group role. Configure `JAS_SI_CUSTOMER_API_KEY_DATABASE_URL`, `JAS_SI_API_KEY_PEPPER`, and `JAS_SI_CUSTOMER_TOKEN_PEPPER` through secret management. Never reuse the database owner, migration role, general API runtime, identity login, or provisioner credentials.

Do not apply these migrations at application startup. Production migration, deployment, billing, and financial operations require separate explicit approval. PR #36 remains Draft and unmerged; this document is not deployment authorization.
