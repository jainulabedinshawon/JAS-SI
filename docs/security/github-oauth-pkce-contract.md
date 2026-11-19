# GitHub App user OAuth: PKCE contract

## Purpose

JAS-SI implements a customer-session-bound GitHub App user-authorization flow. OAuth proves that the authenticated GitHub user can access a candidate Installation for the configured App. A successful proof is persisted as a pending customer claim; it does not activate the Installation or any repository.

## Start and state binding

1. Require an active JAS-SI customer session and CSRF validation.
2. Derive tenant and customer-account IDs only from that authenticated session.
3. Accept a positive candidate Installation ID at the OAuth-start endpoint. Treat it as untrusted input; it is only a lookup candidate.
4. Generate high-entropy OAuth state and a PKCE verifier using S256.
5. Encrypt the verifier with AES-256-GCM. Persist only the state digest, candidate Installation ID, authenticated tenant/account IDs, expiry, redirect-URI digest, ciphertext, and key version through the database-owned create routine.
6. Only after persistence succeeds, return the GitHub authorization URL.
7. The browser receives a five-minute, HttpOnly, path-scoped, SameSite=Lax state cookie. Production and preview use Secure.

Raw state, plaintext PKCE verifier, authorization code, and access token are not persisted in PostgreSQL.

## Callback and same-origin handoff

GitHub's OAuth callback is expected to return `code` and `state`; the candidate Installation ID is not trusted from the provider callback. It was bound to the OAuth attempt at start and is returned by the atomic consume routine.

The callback page:

- Requires exactly one state and one code and rejects provider error responses.
- Constant-time compares state against the short-lived cookie.
- Uses a nonce-based Content Security Policy, no-store caching, and no-referrer policy.
- Removes the authorization code from browser history before submitting the same-origin completion POST.
- Uses the existing SameSite=Strict customer session and CSRF cookies on that same-origin POST.

The completion route atomically consumes the state record for the same active customer session before decrypting the verifier. It exchanges the code with GitHub, verifies the resulting `/user` identity, then independently checks that the candidate Installation appears in the authenticated user's complete Installation list and belongs to the expected GitHub App ID.

## Pending claim persistence

After user and Installation identity match, the API records a durable row through `customer_github_installation_claim_record`. The database routine derives tenant/account ownership from the current customer session; it does not accept tenant/account IDs from the browser. The Installation ID is unique across claims. Repeated claims from the same customer and same GitHub identities are idempotent; a different customer or identity cannot take over an existing Installation claim.

The claim remains `pending_reconciliation`. It records the verified GitHub user ID/login, GitHub account ID/login/type, App ID, customer tenant/account, Installation ID, and proof timestamp. The customer runtime has EXECUTE-only access to the claim routine; direct table access is denied. Worker, Verifier, and general runtime roles cannot read or mutate claims.

## Security and operational boundaries

- The configured redirect URI is HTTPS-only and pinned to `/v1/github/oauth/callback`.
- OAuth attempt lifetime is five minutes (database permits at most ten minutes).
- State consumption is atomic and single-use; concurrent callback requests cannot both succeed.
- PKCE ciphertext uses authenticated encryption; key material is supplied through environment configuration backed by an external secret manager/KMS. The database stores no encryption key.
- The GitHub access token is short-lived, used in memory for identity/Installation verification, and not stored or logged.
- Installation activation and repository allowlisting are separate authority. A webhook payload is a lifecycle signal, not ownership proof.
- OAuth completion does not itself reconcile GitHub webhooks or activate a tenant Installation.

## Remaining work

1. Capture candidate Installation IDs from the GitHub App setup/install callback and expose a safe customer selection flow. The OAuth start API currently requires the candidate ID; it does not yet discover it automatically.
2. Build an authoritative webhook reconciliation processor that checks current GitHub API state and matches the pending claim, App ID, tenant, and selected repository allowlist.
3. Persist reconciled Installation/repository bindings and enable activation only through the controlled reconciliation authority.
4. Run end-to-end Staging verification using a real configured GitHub App and isolated test tenant.

PostgreSQL migration replay and CI integration tests use disposable databases. No production credentials, live Neon migration, external GitHub App configuration, or Installation activation has been performed.
