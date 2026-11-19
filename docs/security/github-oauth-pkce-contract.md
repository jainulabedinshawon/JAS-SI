# GitHub App user OAuth: PKCE contract

## Purpose

This change supplies protocol primitives, tenant-bound durable state, an AEAD verifier envelope, an application service for persist-before-redirect/consume-before-decrypt orchestration, and a strict GitHub token-exchange/user-identity client. It does not implement the OAuth HTTP routes or Installation activation.

## Authorization initiation

1. Authenticate the customer using the existing JAS-SI customer session and CSRF protections.
2. Derive the tenant and customer-account IDs only from the authenticated session; never accept them from browser parameters.
3. Call `create_github_oauth_attempt()` to create a cryptographically random state value and PKCE verifier using S256.
4. Before redirecting, call the durable `customer_github_oauth_attempt_create` routine to persist the state digest, authenticated tenant/account IDs, expiry, redirect-URI digest, and AEAD ciphertext for the PKCE verifier. The database never receives raw state or plaintext verifier. The application must encrypt the verifier with `GitHubOAuthVerifierCipher` before passing the ciphertext to PostgreSQL.
5. Redirect to the returned GitHub authorization URL.

## Application service and provider client

`GitHubOAuthService.begin()` derives no tenant identity from browser input: it accepts the already-authenticated customer account and session token, encrypts the PKCE verifier, persists the state digest and ciphertext, and only then returns the authorization URL. `consume_callback()` validates callback syntax, atomically consumes the session-bound database record, and decrypts only after consumption succeeds. Its result binds the verifier to the database-returned attempt, tenant, and account IDs.

`GitHubOAuthProvider.exchange_code()` sends the authorization code, PKCE verifier, client credentials, and configured redirect URI to GitHub over HTTPS with bounded timeouts and redirects disabled. `authenticated_user()` validates the `/user` response. The short-lived access token is kept in memory and is not persisted or logged by this client. Provider HTTP behavior has no-network mock tests.

## Callback requirements for HTTP integration

1. Require exactly one state and one authorization-code parameter; reject duplicate or missing parameters and provider error callbacks.
2. Call `customer_github_oauth_attempt_consume` with the authenticated session digest, SHA-256 state digest, and configured redirect-URI digest. The database routine atomically consumes a matching, unexpired, session-bound attempt; concurrent callers cannot both receive the same record.
3. Derive tenant/account identity only from that consumed record, not callback parameters or webhook payloads.
4. Use `GitHubOAuthService.consume_callback()` to atomically consume and decrypt; exchange the code with `GitHubOAuthProvider.exchange_code()` using the same redirect URI and verifier.
5. Verify the resulting user access token with `GitHubOAuthProvider.authenticated_user()`, then use the existing `GitHubUserInstallationAccessVerifier` to independently verify the exact Installation and expected App ID.
6. Keep the Installation pending until authoritative Installation and repository reconciliation has completed. Do not trust webhook payload account/repository fields as ownership proof.
7. Redact authorization codes, state, PKCE verifiers, access tokens, and provider response bodies from logs and exception messages.

## Security boundary

The pure callback validator compares the supplied state against a SHA-256 digest using constant-time comparison and validates the authorization code's syntax. This alone is not replay protection. Replay protection exists only when the caller atomically consumes the durable state record before code exchange.

The PKCE verifier must be protected at rest with authenticated encryption using a key held outside the database. The migration `20261204_github_oauth_attempt_store.sql` creates a dedicated table and narrowly scoped create/consume routines. Only the customer identity owner can access the table; the customer runtime receives routine EXECUTE only, while general runtime and agent Worker/Verifier roles are denied. The verifier ciphertext is opaque to PostgreSQL. The `GitHubOAuthVerifierCipher` implements AES-256-GCM with a 96-bit random nonce and 128-bit authentication tag. Its keyring is injected from an external secret manager/KMS; PostgreSQL stores only ciphertext and a key version. Associated data binds attempt ID, tenant ID, account ID, and redirect-URI digest. The callback service must decrypt only after the atomic consume routine succeeds. Key rotation must retain old key versions only for the maximum outstanding attempt lifetime.

## Explicitly incomplete

- OAuth client configuration and external secret/key-manager integration
- Authenticated start and callback HTTP routes, including duplicate-query rejection, CSRF, and cross-site callback cookie policy
- Wiring the verified GitHub user identity into the Installation ownership verifier
- Durable Installation ownership proof persistence
- Installation/repository reconciliation and lifecycle event processor
- End-to-end Staging verification

PostgreSQL replay and concurrency integration tests are added for CI. No production credentials, live database, or external GitHub App configuration are changed.
