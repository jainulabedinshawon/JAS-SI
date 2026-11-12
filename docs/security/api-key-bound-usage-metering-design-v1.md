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
