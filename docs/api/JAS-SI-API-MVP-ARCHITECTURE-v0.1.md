# JAS-SI API Backend MVP Architecture v0.1

Status (historical baseline, reviewed 2026-11-23): v0.1 architecture baseline; implementation has advanced beyond the original proposal. This document is retained as an architectural reference, with live activation blockers tracked in the private-pilot runbook. It must not be read as proof that the full customer journey or agent-execution system is production-ready.

## 1. What already exists

The current repository already contains a FastAPI backend and a working core integration:

- `src/jas_si_agent/api.py`: `/health`, `POST /v1/authorize`, and `POST /v1/verify`.
- `src/jas_si_agent/verify_router.py`: `POST /v1/github/evidence`, which reads GitHub data at an immutable commit and verifies Git blob integrity.
- `src/jas_si_agent/authorization.py` and `sdk.py`: the authorization decision engine.
- `src/jas_si_agent/verification.py`: outcome-verification semantics.
- `src/jas_si_agent/postgres_security_event_store.py` plus migration `001`: durable hash-chained audit events.
- Development/test may use the legacy static API key. Preview/production use the tenant-scoped PostgreSQL API-key registry and database-owned `jas_si_api_key_authenticate` routine; they must fail closed rather than fall back to the global key.

The tenant-aware API-key lifecycle, customer identity/session routes, customer API-key self-service routes, and durable technical-usage metering now exist in `main`. The principal remaining product gaps are live customer activation (dedicated runtime credentials, SMTP, and a verified end-to-end journey), a real agent orchestrator and execution boundary, and a trusted independent evidence collector.

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

The initial pilot uses one tenant per customer and multiple named keys per tenant. Customer signup, session, and tenant-scoped API-key issue/list/revoke endpoints now exist in `main`; they remain unavailable until the dedicated identity/key database connections, login principals, session pepper, and SMTP delivery are correctly configured.

## 5. Issuance, rotation, and revocation

Operator provisioning remains available for controlled pilots, while customer self-service key operations are implemented behind a separate session-bound database role:

- A trusted operator creates a tenant and can issue a scoped key using the CLI on a trusted admin runner.
- A signed-in customer can issue/list/revoke only keys belonging to the server-derived tenant, when the dedicated customer identity and key-management configuration is active.
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

### GitHub repository-read task input boundary

The `github.read_repository` task type accepts exactly three input fields: `repository`, `commit_sha`, and `paths`. The API validates an owner/repository identifier, a full lowercase 40-character immutable commit SHA, and between 1 and 10 unique relative file paths (maximum 500 characters each). Absolute paths, traversal segments, backslashes, NUL bytes, duplicate paths, and unknown input fields are rejected with HTTP 422 before task persistence. This is request-shape validation only; it does not enable task submission or establish repository access. The task-submission switch remains fail-closed until the worker host is independently ready.


## Current implementation and activation status (2026-11-15)

- The tenant-scoped API-key registry and database-owned authentication boundary are present in `main`; the current Production database catalog check confirms the runtime cannot directly read tenant or API-key tables.
- Customer identity, session, usage-read, and API-key self-service routes are present in `main`. They are configuration-gated and are not equivalent to an active customer service.
- Production has no dedicated customer identity/key DSNs, customer session pepper, or SMTP configuration. Preview has dedicated customer DSNs and a session pepper, but SMTP configuration is absent. Do not invite customers or claim signup/login works until the full journey passes.
- Free technical quota reservation is implemented in code. It is a technical API-call allowance, not a monetary credit; live customer usage has not been demonstrated.
- Paid checkout, payment verification, authoritative paid entitlements, and refunds are not active. Paid plans must remain non-purchasable.
- The API does not execute customer actions. `/v1/verify` accepts caller-submitted outcome information and cannot independently establish task completion. The GitHub evidence route verifies Git object/file integrity only. The generic verifier remains fail-closed until a trusted server-side evidence collector is integrated.
- Draft PRs #71–#73 contain pending staging/security-boundary work. Their migrations are not part of `main` and must not be treated as deployed.

## 8. Pilot security controls

Required before external pilot credentials are issued:

- HTTPS only, HSTS at ingress, no plaintext API exposure.
- Secret manager for DB credentials and key pepper; no secrets in GitHub or source files.
- Separate DB roles: runtime API can read key metadata/update last-used and append audit events; provisioning role can create/revoke keys and manage tenants.
- Least-privilege scopes, tenant status checks, key expiry, immediate revocation.
- Generic authentication errors; constant-time digest comparison.
- Request IDs and durable audit events, with fail-closed behavior for critical authorization/verification results.
- Shared PostgreSQL-backed rate limiting is integrated for deployed Preview/Production environments: the general API limiter applies across `/v1/*`, and customer registration/login additionally use a dedicated email-abuse limiter. Draft PR #73 further moves customer rate-limit table access and bounded retention cleanup behind a dedicated database-owned boundary; that migration is not deployed until it is reviewed, merged, and independently verified.
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
