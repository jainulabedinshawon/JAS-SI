# API-key-bound usage metering security design v1

**Status:** Design proposal; not production-ready and not an applied migration.
**Scope:** Replace shared-runtime direct access to `jas_si_usage_events` for API-key-authenticated usage writes and reads.
**Non-goals:** Payment processing, monetary balances, invoices, paid entitlements, or changes to JAS Platform authority.

## 1. Confirmed current boundary

The current `PostgresUsageMeter` accepts `tenant_id` and `api_key_id` from its caller and connects through the shared database DSN. The `jas_si_runtime` role has direct `SELECT, INSERT` on `public.jas_si_usage_events`. The API's tenant filtering is therefore application-enforced, not an independent database authorization boundary. A compromised runtime credential or arbitrary SQL execution under that role can read usage rows across tenants and can attempt writes with caller-selected tenant context, subject to foreign keys and constraints.

The customer-browser usage read path is separate: `customer_usage_summary` and `customer_usage_events` validate a live customer-session digest and derive tenant identity inside PostgreSQL. Do not weaken or conflate that boundary with API-key authentication.

## 2. Required target architecture

1. The HTTP layer authenticates the presented API key and computes its peppered digest using the configured secret pepper. It must not pass a caller-selected tenant ID as authority.
2. The application calls a narrow PostgreSQL routine with the key identifier, candidate digest, required scope, operation, server-generated request ID, idempotency key, request fingerprint, and server-calculated unit count.
3. The routine, running under a dedicated non-login owner, validates the key identifier + digest against the registry, checks active key and tenant state, expiry/revocation, and required scope, then derives tenant ID from the matched registry row.
4. In one transaction, the routine takes a tenant-scoped transaction lock, handles exact idempotency replay/conflict, calculates the UTC calendar-month usage, enforces the configured technical quota, and appends the immutable event. It returns only the event and quota metadata needed by the API.
5. API-key usage reads call a separate narrow routine that validates the key digest and `usage:read` scope internally, derives tenant ID from the key registry, and returns only the caller tenant's aggregate or keyset page.
6. Customer-session routines remain separate and continue deriving tenant identity from a live session inside PostgreSQL.

## 3. Database role and privilege requirements

- Create a dedicated `NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT` owner role for API-key usage routines.
- At readiness time, verify every role attribute and reject memberships in both directions. Reject unsafe owner drift.
- Grant the owner only the exact column/table privileges required by its routines; no broad schema CREATE privilege.
- Grant `jas_si_runtime` EXECUTE only on the exact approved routines. Revoke all table-level and column-level privileges on `jas_si_usage_events`, tenant registry, API-key registry, and other protected tables from the runtime role and PUBLIC.
- Revoke PUBLIC EXECUTE on every SECURITY DEFINER routine; pin `search_path` to `pg_catalog`; schema-qualify application objects; verify owner, signature, EXECUTE grants, and fixed configuration at startup/readiness.
- Do not trust a freely settable tenant GUC, request parameter, header, or application-supplied tenant UUID as authorization.
- Preserve append-only behavior and existing composite foreign-key consistency between API key and tenant.
- Review RLS policies for the dedicated routine owner and ensure they cannot broaden access for runtime or public roles.

## 4. Routine contract (proposal)

### Write/reserve routine

Inputs:
- API key UUID and candidate peppered digest (32 bytes)
- Required scope (fixed allow-list; never caller-selected beyond the endpoint's server mapping)
- Server-generated request UUID
- bounded idempotency key
- fixed operation enum
- SHA-256 request fingerprint
- server-calculated units (currently exactly one)
- configured monthly technical quota

Database behavior:
- Reject malformed input before any write.
- Resolve and validate API key + tenant in the database; reject inactive, expired, revoked, wrong-scope, or mismatched key material.
- Derive tenant ID only from the validated key row.
- Serialize quota reservation per tenant in the same transaction.
- Return the original event for an exact retry without consuming another unit.
- Reject reuse of an idempotency key with a different API key, operation, units, or fingerprint.
- Reject a new event that exceeds quota.
- Append exactly one immutable event and return event ID + technical quota metadata.
- Fail closed on missing schema, unavailable storage, or invalid role state.

### Read routines

- Summary and event-history routines independently validate the API-key digest and `usage:read` scope.
- Derive tenant from the matched active API key; do not accept tenant ID as input.
- Return only allow-listed non-secret fields.
- Keep stable keyset pagination ordered by `(occurred_at DESC, event_id DESC)`.
- Customer-session read routines remain independent and unchanged.

## 5. Migration and rollout sequencing

1. Implement additive routines and dedicated owner role in a new migration; do not change existing production grants in-place without a reviewed rollout plan.
2. Add role-owner, routine-signature, privilege, RLS, fixed-search-path, and direct-table-denial readiness checks.
3. Add PostgreSQL integration tests using at least two tenants and distinct API keys.
4. Update the application to use the routines only after readiness verifies all required objects and privileges; fail closed if not ready.
5. In the same reviewed migration plan, revoke direct usage-table and protected registry access from `jas_si_runtime` only after all deployed code paths have moved to routines.
6. Verify browser-session reads, API-key reads, API-key writes, metered operation admission, and append-only guarantees independently.
7. Stage first. Production migration and deployment require separate explicit approval. Provide rollback as a forward-fix/disablement plan; do not drop usage history, roles, or routines as an automatic rollback.

No production migration, role change, deployment, or data mutation is authorized by this design document.

## 6. Required regression and adversarial tests

- Key A cannot read or write tenant B events, even when the caller supplies tenant B's UUID in HTTP/query/body input.
- A key ID paired with the wrong digest is rejected.
- Revoked, expired, suspended-tenant, inactive, and wrong-scope keys are rejected.
- Runtime role cannot SELECT/INSERT/UPDATE/DELETE/TRUNCATE the usage table directly, including column-level grants and inherited membership.
- Runtime role can EXECUTE only the intended routines; PUBLIC cannot execute them.
- Unsafe owner role attributes or role memberships cause readiness failure.
- Exact idempotent replay returns the original event; changed digest/key/operation/fingerprint conflicts.
- Concurrent distinct requests cannot overspend quota; concurrent duplicate submissions create one event.
- Transaction failure rolls back both quota reservation and event insertion.
- Storage outage fails closed; no operation handler executes when metering cannot be durably reserved.
- Usage reads are tenant-scoped and keyset pagination has no duplicate/omitted rows across tied timestamps.
- No API key, digest, request body, prompt, evidence payload, or payment data appears in returned usage metadata or logs.
- Existing customer-session usage routines continue to pass their own cross-tenant and revoked/expired-session tests.

## 7. Acceptance gate

The API-key path is not production-ready until the database itself validates API-key identity, derives tenant identity, enforces scope and quota atomically, and denies direct shared-runtime table access. A green unit suite alone is insufficient; PostgreSQL integration evidence and a reviewed staging journey are required.


## 8. Implementation integration findings (source audit at PR head e17140c)

The source-level integration points were inspected before writing a migration:

- `api_key_registry.py` exposes `parse_token(token)`, which returns the UUID key ID and 32-byte secret, and `_digest(secret, pepper)`, which computes HMAC-SHA256. `authenticate()` currently performs the registry lookup and last-used update through the shared DSN.
- The authenticated API-key object currently carries key ID, tenant ID, tenant name, and scopes, but not the candidate digest. The request authentication path must retain a non-logged, request-local candidate digest (or derive it again from the presented token) for the database routine call. Never persist or log the raw token.
- `PostgresUsageMeter.record()` currently accepts caller-provided `tenant_id` and `api_key_id`, then directly selects/inserts `jas_si_usage_events`. `events()`, `quota_status()`, and `summary()` also query the table directly using caller-provided tenant IDs.
- The usage table's idempotency uniqueness is `(tenant_id,idempotency_key)`; it stores `request_fingerprint` as a nullable 64-character SHA-256 string for legacy rows. Exact replay semantics must preserve the existing behavior for legacy NULL fingerprints: a legacy row cannot be treated as a verified exact replay.
- The customer-browser usage routines in migration `20261114_customer_usage_read_routines.sql` are a separate session-digest boundary and currently grant the customer identity owner read access to the usage table. Preserve that path; do not repurpose its session routines for API-key auth.
- Existing API middleware authenticates the API key before calling `_record_usage_for_authenticated_tenant()`. The latter currently passes only tenant ID and key ID to the meter. The implementation must thread a 32-byte digest and a server-mapped scope into the meter without accepting tenant ID as database authority.
- The API key registry's existing scope vocabulary and endpoint-to-scope mapping must be confirmed from the API route dependencies before the database routine signature is frozen. Do not invent a new scope name or infer scope from the request body.

### Revised safe implementation order

1. Add a dedicated owner role and additive SECURITY DEFINER routine migration, using the exact existing registry and usage column names. Routine input includes key ID + candidate HMAC digest; tenant ID is deliberately absent.
2. Add owner/routine readiness checks to the usage meter. Check the full owner role attributes and membership in both directions, exact routine owner/signature/configuration, no PUBLIC EXECUTE, and no direct runtime table/column grants.
3. Add PostgreSQL integration fixtures with two tenants and two keys. Verify correct digest, wrong digest, revoked/expired key, suspended tenant, wrong scope, cross-tenant isolation, exact replay, conflicting replay, quota concurrency, and transaction rollback.
4. Refactor the API authentication context to carry the candidate digest only in request-local memory; ensure logs, exception messages, tracing, and response bodies never include it.
5. Refactor all four meter paths (record, events, quota_status, summary) to use database routines. Do not leave a direct-table fallback for runtime credentials.
6. Only after code and staging verification, prepare a separate migration step to revoke runtime direct table and column grants. Do not revoke those grants in the initial additive migration while deployed code still depends on them.
7. The runtime direct-access revocation and production migration/deployment remain separate approval gates.

This source audit is not a migration, test run, or production readiness claim. No database was contacted and no privileges were changed.


## 9. Authentication-path dependency discovered in follow-up audit

A further source audit of `api_key_registry.py` and `api.py` found an important dependency that changes the rollout design:

- `PostgresApiKeyRegistry.authenticate()` currently performs a direct SELECT joining `jas_si_api_keys` and `jas_si_tenants`, validates the HMAC digest in Python, and directly updates `last_used_at`.
- The API route maps exact scopes as follows:
  - `/v1/authorize` → `authorization:check`
  - `/v1/verify` → `outcomes:submit`
  - `/v1/github/evidence` → `github:evidence:verify`
  - `/v1/usage` → `usage:read`
- Therefore, revoking runtime access to the API-key registry before moving authentication into a database-owned routine would break all API-key authentication, not merely usage metering.
- The authenticated request context currently stores key ID, tenant ID, and scopes, but not the candidate digest. `parse_token()` already returns the 32-byte secret, and `_digest(secret, pepper)` computes the 32-byte HMAC-SHA256 candidate digest.

### Required revised architecture

1. Add a narrowly scoped SECURITY DEFINER API-key authentication routine. It accepts key ID + candidate digest, validates active key, expiry, tenant status, and pepper version, checks a server-mapped required scope, updates `last_used_at` atomically, and returns only key ID, derived tenant ID, tenant display name, and allowed scopes. It must not return the stored digest.
2. Change `PostgresApiKeyRegistry.authenticate()` to call that routine and retain the candidate digest in the request-local authenticated context only as needed by the metering call. The digest must never enter logs, tracing, exception text, or API responses.
3. Implement API-key-bound usage write/read routines that independently validate key ID + candidate digest and scope, then derive tenant identity from the registry. Tenant ID is never an input.
4. Migrate the API runtime away from direct SELECT/UPDATE access to `jas_si_api_keys`, `jas_si_tenants`, and direct usage-event table access. Preserve only EXECUTE grants on reviewed routines.
5. Customer API-key self-service remains on its separate customer-session digest routines and customer runtime role. The API runtime and customer runtime are distinct trust boundaries and must not share role ownership or credentials.
6. Add a readiness check that proves all required authentication and usage routines are owned by the dedicated non-login owner, have fixed `search_path=pg_catalog`, have no PUBLIC EXECUTE, and that the runtime role has no direct table/column privileges or unsafe role memberships.
7. Only after the application uses both the authentication and metering routines, stage the privilege-revocation migration. This migration must account for every API path that still legitimately needs other tables; do not revoke unrelated application access blindly.

This dependency means the earlier proposal to revoke direct usage-table access alone is insufficient. The full registry authentication and usage call chain must be migrated together before the runtime privilege boundary can be tightened.
