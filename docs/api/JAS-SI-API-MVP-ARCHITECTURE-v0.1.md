# JAS-SI API Backend MVP Architecture v0.1

Status: implementation plan grounded in the current `main` branch. This document is not a claim that the proposed tenant/key registry is already deployed.

## 1. What already exists

The current repository already contains a FastAPI backend and a working core integration:

- `src/jas_si_agent/api.py`: `/health`, `POST /v1/authorize`, and `POST /v1/verify`.
- `src/jas_si_agent/verify_router.py`: `POST /v1/github/evidence`, which reads GitHub data at an immutable commit and verifies Git blob integrity.
- `src/jas_si_agent/authorization.py` and `sdk.py`: the authorization decision engine.
- `src/jas_si_agent/verification.py`: outcome-verification semantics.
- `src/jas_si_agent/postgres_security_event_store.py` plus migration `001`: durable hash-chained audit events.
- Current API authentication compares every request against one environment variable, `JAS_SI_API_KEY`.

The current backend is therefore more than a blank architecture. The principal MVP gap is customer/tenant-aware API-key lifecycle and a contract that exactly matches the implemented routes and responses.

## 2. MVP deployment shape

Pilot deployment:

1. HTTPS reverse proxy / managed ingress.
2. One or more stateless FastAPI API workers.
3. PostgreSQL for tenant records, API-key metadata, and the existing hash-chained security audit store.
4. Secret manager for the API-key hashing pepper, database credentials, and optional GitHub token.
5. Operator-only provisioning command executed from a trusted deployment shell.

The API does not execute customer actions. It evaluates authorization, accepts outcome submissions, and performs the bounded GitHub evidence-integrity check already implemented in the repository.

## 3. Authentication flow

API key format (proposed):

`jassi_live_<key-id-uuid-hex>_<base64url-32-byte-secret>`

- Generate the secret with a cryptographically secure random generator (256 bits).
- Display the complete token once at issuance. Never store or log the raw token.
- Store the public key ID, tenant ID, key name, prefix, scopes, status, expiry, pepper version, and HMAC-SHA256 digest of the secret.
- Compute the digest with a server-side pepper from a secret manager. Compare digests with a constant-time comparison.
- Reject unknown, malformed, revoked, expired, suspended-tenant, and invalid keys with the same generic 401 response.
- Fail closed with 503 if the key registry or database is unavailable. Do not silently fall back to the legacy global key in preview/production.
- Record authentication outcomes without recording the presented key or its secret.

The database stores no recoverable API-key secret. A database-only compromise therefore does not reveal the original token; the pepper must be stored separately from PostgreSQL.

## 4. Tenant and scope model

Initial pilot scopes:

- `authorization:check`
- `outcomes:submit`
- `github:evidence:verify`

A key belongs to exactly one tenant. Every authenticated request receives a server-derived tenant ID and scope set. Scope checks happen before the endpoint handler. Tenant identity must never be accepted from a request body or caller-controlled header.

The initial pilot can use one tenant per pilot customer and multiple named keys per tenant (for example staging and production). No self-service customer signup or public key-management endpoint is included.

## 5. Issuance, rotation, and revocation

For the pilot, API-key administration is deliberately out-of-band:

- A trusted operator creates a tenant and issues a scoped key using a CLI on the API host or a controlled admin runner.
- The key is shown once and delivered through an approved secret-sharing channel.
- Rotation means issue a replacement key, validate it with the customer, then revoke the old key.
- Revocation is immediate on the next authentication lookup.
- Expiry is optional but recommended for pilot keys.
- The CLI must never print keys in debug logs, CI logs, or audit events.

There is intentionally no public `POST /admin/api-keys` endpoint. An admin endpoint would require a separate operator identity, strong authorization, CSRF/network controls, and an independent audit trail; it is outside this pilot MVP.

## 6. PostgreSQL schema

Migration `002_create_tenant_api_keys.sql` creates:

- `jas_si_tenants`: tenant identity and active/suspended state.
- `jas_si_api_keys`: key metadata, digest, scopes, expiry, revocation, and last-use metadata.

The existing `001_create_audit_tables.sql` remains the audit-event persistence foundation. Key lifecycle operations should also emit sanitized audit events (tenant ID, key ID, operation, operator identity); never include the token or digest.

## 7. Canonical API contract

`openapi-v1.yaml` in this directory documents the existing backend routes and their current payloads. It is the contract to reconcile with the PHP SDK. Any future key-registry change must update the contract and contract tests in the same change.

The GitHub evidence route proves Git object/file integrity at the selected commit. It does not prove semantic correctness, task completion, or truth of an agent claim. `/v1/verify` treats caller-submitted evidence references as caller-submitted; it does not independently fetch them.

## 8. Pilot security controls

Required before external pilot credentials are issued:

- HTTPS only, HSTS at ingress, no plaintext API exposure.
- Secret manager for DB credentials and key pepper; no secrets in GitHub or source files.
- Separate DB roles: runtime API can read key metadata/update last-used and append audit events; provisioning role can create/revoke keys and manage tenants.
- Least-privilege scopes, tenant status checks, key expiry, immediate revocation.
- Generic authentication errors; constant-time digest comparison.
- Request IDs and durable audit events, with fail-closed behavior for critical authorization/verification results.
- Distributed rate limiting before multi-worker/customer production use. Current rate limiter is per-process and keyed by client IP.
- Backup/restore test for PostgreSQL and audit-chain integrity.
- No customer data returned across tenant boundaries.

## 9. Explicit non-goals for this MVP

- Public signup or self-service dashboard.
- Billing/subscriptions.
- Public Packagist publication.
- Customer-facing admin API.
- Claims of semantic truth beyond the evidence actually retrieved and checked.
- Automatic execution of customer actions.

## 10. Implementation gates

1. Apply migration 002 in a disposable PostgreSQL integration environment.
2. Implement and test the key registry store, key generator, verifier, and operator CLI.
3. Wire database-backed authentication and per-key scopes into FastAPI; retain the legacy static key only for local development/test, never preview/production.
4. Add tests for tenant suspension, key expiry, revocation, wrong pepper, wrong scope, database outage, and no secret leakage.
5. Run the full Python 3.10 test suite and PostgreSQL integration workflow.
6. Deploy to a private staging environment, issue one short-lived pilot key out-of-band, and test cURL from a clean client.
7. Only then invite a pilot customer.

## 11. Current decision

Use PostgreSQL already present in the repository rather than introducing another database product for this MVP. Keep the core engine and methodology unchanged. Keep the PHP SDK as a convenience layer and do not merge/publish it as a customer-ready package until the backend contract is implemented and exercised against a real deployment.
