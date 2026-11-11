# Customer API-Key Database Boundary v2 — Security Design

Status: design proposal only; not an approved migration or production change.

## 1. Purpose and threat model

The current customer-key runtime role is a NOLOGIN group role assumed by the application. It can set arbitrary transaction-local PostgreSQL custom settings, including `jas_si.tenant_id`. Therefore, RLS policies that trust this setting protect against accidental unscoped application queries but do not protect against arbitrary SQL executed with the customer-key role.

The current role also has direct privileges on the global audit event and checkpoint tables. This allows a holder of that database role to read global audit history and attempt direct audit writes/checkpoint changes.

The target security boundary is: possession of the customer-key database credential alone must not let a caller choose a tenant, read another tenant's keys, or alter global audit state.

## 2. Required role separation

- `jas_si_customer_key_runtime`: NOLOGIN; may execute only narrowly scoped customer key routines. No direct SELECT/INSERT/UPDATE/DELETE/TRUNCATE on audit events or audit checkpoint.
- `jas_si_customer_identity_runtime`: NOLOGIN; identity operations only. It must not be a member of the key runtime role or any owner/provisioner role.
- `jas_si_customer_key_owner`: NOLOGIN, non-superuser, non-BYPASSRLS; owns the SECURITY DEFINER routines and has only the table privileges those routines require. No application login may inherit this role.
- Existing `jas_si_runtime` and `jas_si_provisioner` remain separate; do not grant either to customer-facing logins.

All SECURITY DEFINER routines must set a fixed safe `search_path` (prefer `pg_catalog, public` with schema-qualified object references), revoke EXECUTE from PUBLIC, and grant EXECUTE only to the intended runtime role. No dynamic SQL from user-controlled identifiers.

## 3. Session-derived tenant authorization

Customer HTTP handlers already authenticate the browser session and obtain an account record. The database boundary must independently validate the session for every customer key operation:

1. The API computes the existing HMAC-SHA256 digest of the presented session token using the customer token pepper; it never passes the raw cookie token to SQL.
2. A narrowly scoped SECURITY DEFINER routine receives the 32-byte digest and looks up a matching session joined to its customer account.
3. The routine requires: session not revoked, session expiry in the future, account status active, email verified, and the account/tenant relationship intact.
4. The routine derives `tenant_id` and `account_id` from those rows. No caller-supplied tenant UUID is accepted as an authorization input.
5. Create/list/revoke routines operate only on that derived tenant. Revocation also checks that the requested key belongs to the derived tenant.
6. Invalid, expired, revoked, or suspended sessions return a uniform authorization failure without revealing whether a tenant or key exists.

A caller-supplied `jas_si.tenant_id` GUC must be ignored for authorization. Tests must deliberately set it to another tenant and prove that it cannot change the routine's derived tenant.

The HMAC digest is a bearer proof. The customer-key role must not have direct SELECT on customer session/token tables. The application must not expose the digest in responses, logs, traces, or error messages.

## 4. Key lifecycle routines

Expose only three customer operations through SECURITY DEFINER routines:

- issue: validate session digest; derive tenant/account; validate key metadata and allowed scopes; insert key and idempotency record; append audit event; advance checkpoint; return key ID only (the API retains and returns the one-time raw token it generated).
- list: validate session digest; derive tenant; return non-secret metadata for that tenant only.
- revoke: validate session digest; derive tenant; update only a key owned by that tenant; append audit event and advance checkpoint atomically.

The API may generate the random key secret and HMAC digest, but it must not be able to select the tenant by supplying a tenant ID. All business mutations and the corresponding audit append/checkpoint update must be in one database transaction.

## 5. Audit-chain compatibility is a hard constraint

Existing Python audit behavior is defined by:

- event normalization through PostgreSQL JSONB before hashing;
- Python canonical JSON: sorted keys, compact separators, UTF-8, `ensure_ascii=False`, `allow_nan=False`;
- hash material is canonical JSON bytes for `{"event": normalized_event, "previous_hash": previous_hash}`;
- SHA-256 over those exact bytes;
- a singleton checkpoint row locked `FOR UPDATE` by all appenders.

A SQL replacement must not hash PostgreSQL's default JSONB text representation. It must preserve byte-for-byte compatibility with existing hashes, including Unicode, nested objects, nulls, and numeric edge cases. A candidate design is to pass canonical material bytes from the trusted application, parse them as UTF-8 JSONB inside the function, verify semantic equality with the supplied normalized event and previous hash, then hash the original bytes. This is not yet accepted: the full-chain verification path must also remain independent and must not be bypassable by a caller holding only the customer-key role.

Before implementation, settle how full historical-chain verification is performed without granting global audit reads to the customer-key role. Candidate separation: a distinct trusted audit-verifier connection/role with read-only access, plus a restricted append routine; document the trust boundary and ensure the customer-key credential cannot assume that verifier role. Do not replace full-chain verification with a mere checkpoint/last-row check.

## 6. Migration and test gates

A future migration must be additive and reviewed against actual schema state. It must not run automatically at application startup. It must not be applied to Production without separate explicit approval.

Required PostgreSQL integration tests under the actual customer-key role:

- direct SELECT/INSERT/UPDATE/DELETE/TRUNCATE on audit events and checkpoint are denied;
- setting `jas_si.tenant_id` to Tenant B while presenting Tenant A's session digest cannot list, issue, or revoke Tenant B keys;
- Tenant B session digest can operate only on Tenant B;
- expired, revoked, pending, and suspended sessions are rejected;
- a key ID from another tenant returns a non-disclosing not-found result;
- customer role cannot read customer session/token tables or assume owner, verifier, identity, runtime, or provisioner roles;
- routine EXECUTE grants are minimal and PUBLIC has none;
- key mutation, idempotency record, audit event, and checkpoint commit or roll back together;
- concurrent issuance/revocation preserves one valid audit chain;
- old event hashes remain valid after migration;
- canonical byte/hash parity covers Unicode, nested JSON, nulls, numeric edge cases, tampered bytes, and previous-hash mismatch;
- failed audit verification prevents all key mutations.

## 7. Current disposition

PR #36 remains Draft. Existing happy-path CI is green, but it does not prove the adversarial database boundary above. The current migration's direct audit grants and GUC-derived tenant scope remain blockers. This document is a design checkpoint, not evidence of implementation, deployment, or customer readiness.
