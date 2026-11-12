# Customer Identity Database Boundary v1

Status: design specification only. No migration or production change is authorized by this document.

## 1. Security objective

The customer-facing identity runtime must not read or mutate customer account, authentication-token, or session tables directly. PostgreSQL must validate the presented opaque session token digest and derive the account and tenant inside a trusted database routine. Caller-supplied tenant IDs and mutable custom GUCs are never authorization evidence.

## 2. Required trust boundaries

- `jas_si_customer_runtime`: NOLOGIN application group role; no direct table privileges on accounts, auth tokens, sessions, or global audit tables.
- A separately controlled deployment LOGIN principal may assume only the identity runtime role. It must be NOINHERIT, non-superuser, non-BYPASSRLS, without CREATEDB/CREATEROLE/REPLICATION, and have exactly one direct membership in the identity runtime role with INHERIT disabled, SET allowed, and ADMIN OPTION disabled. It must not inherit owner, provisioner, audit-verifier, or key-runtime roles.
- Table ownership remains with a migration/owner principal unavailable to the application.
- SECURITY DEFINER routines are owned by a dedicated non-login routine-owner role. The runtime role receives EXECUTE only on the minimum required routines. PUBLIC receives no EXECUTE.
- Every SECURITY DEFINER routine sets a fixed safe `search_path` (prefer `pg_catalog, public` with all objects schema-qualified), rejects unexpected caller role assumptions, and validates every input.

## 3. Database routine contract

Implement narrowly scoped routines (exact signatures to be finalized against current application call sites):

1. `customer_register(email, normalized_email, organization, account_id, tenant_id, token_id, token_digest, expires_at)`
   - Atomic creation of tenant, pending account and verification token.
   - Enforce normalization/length/status constraints in database.
   - Return only the minimum account identifier and normalized email needed by the mailer; never return token digest.
2. `customer_issue_link(normalized_email, purpose, token_id, token_digest, expires_at)`
   - Purpose limited to verify_email/login.
   - Lock matching account; only pending accounts may receive verification links and only active accounts may receive login links.
   - Avoid account-existence disclosure at HTTP layer.
3. `customer_consume_link(token_digest, purpose, session_id, session_digest, session_expires_at)`
   - Lock token row, verify purpose, expiry, unconsumed state and account status.
   - Consume exactly once and optionally create session in the same transaction.
   - For verification, activate account and set verified timestamp atomically.
4. `customer_authenticate_session(session_digest)`
   - Join session and account; reject expired, revoked, pending, or suspended accounts.
   - Return only account_id, tenant_id, email, organization, status and expiry required by application.
5. `customer_revoke_session(session_digest)`
   - Revoke only the session matching the digest; idempotent behavior must be specified and tested.

All token/session digests are computed by the trusted application using the configured pepper and passed as 32-byte values. Raw tokens never enter PostgreSQL.

## 4. API changes

Refactor `PostgresCustomerIdentityStore` so each public method invokes only the corresponding routine using parameterized SQL. Remove all direct SELECT/INSERT/UPDATE statements against identity tables. The HTTP layer must continue to derive tenant context exclusively from the returned authenticated session object.

The readiness guard must check:
- expected current role and NOLOGIN group semantics;
- no role memberships that confer owner, verifier, provisioner or bypass privileges;
- required routines exist with exact signatures and trusted owners;
- runtime role has EXECUTE on required routines;
- runtime role has no direct table or column privileges on protected tables;
- PUBLIC has no EXECUTE on privileged routines.

## 5. Audit and API-key integration

Identity routines must not grant access to global audit tables. API-key issue/list/revoke must separately resolve the authenticated session digest inside PostgreSQL and derive tenant_id there. A custom GUC may be used only as a non-authoritative query optimization after the routine has independently verified the session; it must never authorize a tenant.

Audit append must be atomic with key mutation and idempotency record. Full historical hash-chain verification must be performed by a separately controlled read-only verifier path, not by granting global audit reads to customer roles. Preserve the exact existing Python canonical JSON bytes and SHA-256 semantics; no checkpoint-only substitute is acceptable.

## 6. Required adversarial PostgreSQL tests

Run as the actual runtime role, not an owner connection with simulated role assumptions:

- Direct SELECT/INSERT/UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER on accounts, tokens and sessions are denied.
- PUBLIC cannot execute privileged routines.
- Runtime cannot SET ROLE to owner, verifier, provisioner, or key-runtime roles.
- Tenant A session cannot obtain Tenant B identity or keys by setting `jas_si.tenant_id` to Tenant B.
- Expired, consumed, revoked, pending, and suspended states are rejected.
- Concurrent token consumption succeeds at most once.
- Concurrent session revocation and API-key operations preserve atomicity and audit-chain continuity.
- Routine owner/search_path/EXECUTE grants are checked from catalog metadata.
- Existing audit records retain byte-for-byte hash compatibility.
- Failed full-chain verification blocks every key mutation.
- Transaction failures roll back account/token/session or key/audit/idempotency changes together.

## 7. Migration and rollout gates

1. Add routines and grants in an additive migration; do not apply at application startup.
2. Test migration from both a clean database and the current schema snapshot.
3. Run the full existing PostgreSQL integration suite plus adversarial tests.
4. Verify rollback behavior on an isolated disposable database.
5. Deploy to staging only after a separate explicit staging-migration approval and a fresh schema/role audit.
6. Keep customer onboarding and API-key self-service fail-closed until all gates pass.
7. Production migration, secret changes, merge, deployment, and financial changes remain separately gated by explicit approval.

## 8. Current known blockers

The current identity migration grants direct access to account, auth-token and session tables. The current API-key migration grants direct access to global audit event/checkpoint tables and uses a mutable tenant GUC for RLS. Existing application methods still issue direct SQL against identity tables. Therefore this specification is not implementation evidence and customer onboarding must remain disabled.
