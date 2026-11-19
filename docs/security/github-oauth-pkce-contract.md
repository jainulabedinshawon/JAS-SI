# GitHub App user OAuth: PKCE contract

## Purpose

This change supplies protocol primitives for the authenticated GitHub App user-authorization step that precedes Installation ownership verification. It does not implement an HTTP route, token exchange, tenant binding persistence, or Installation activation.

## Authorization initiation

1. Authenticate the customer using the existing JAS-SI customer session and CSRF protections.
2. Derive the tenant and customer-account IDs only from the authenticated session; never accept them from browser parameters.
3. Call `create_github_oauth_attempt()` to create a cryptographically random state value and PKCE verifier using S256.
4. Before redirecting, persist the state digest, authenticated tenant/account IDs, expiry, and an authenticated-encrypted PKCE verifier in a dedicated OAuth-attempt store. Do not store the raw state or plaintext verifier.
5. Redirect to the returned GitHub authorization URL.

## Callback requirements (not implemented by this PR)

1. Require exactly one state and one authorization-code parameter; reject duplicate or missing parameters and provider error callbacks.
2. Atomically claim/consume a matching, unexpired state record. The database operation must be single-use under concurrent callback attempts.
3. Derive tenant/account identity only from that consumed record, not callback parameters or webhook payloads.
4. Decrypt the PKCE verifier only inside the callback service and exchange the code with GitHub using the same redirect URI and verifier.
5. Verify the resulting user access token against GitHub's `/user` endpoint, then use the existing `GitHubUserInstallationAccessVerifier` to independently verify the exact Installation and expected App ID.
6. Keep the Installation pending until authoritative Installation and repository reconciliation has completed. Do not trust webhook payload account/repository fields as ownership proof.
7. Redact authorization codes, state, PKCE verifiers, access tokens, and provider response bodies from logs and exception messages.

## Security boundary

The pure callback validator compares the supplied state against a SHA-256 digest using constant-time comparison and validates the authorization code's syntax. This alone is not replay protection. Replay protection exists only when the caller atomically consumes the durable state record before code exchange.

The PKCE verifier must be protected at rest with authenticated encryption using a key held outside the database. The state digest, verifier ciphertext, tenant ID, account ID, redirect URI binding, creation time, expiry, and consumed timestamp belong in a dedicated table with narrowly scoped database routines and role grants.

## Explicitly incomplete

- OAuth client configuration and secret/key storage
- Durable OAuth-attempt table and atomic create/consume database routines
- Authenticated start and callback HTTP routes, including CSRF and cookie policy
- Authorization-code token exchange and token response validation
- Durable Installation ownership proof persistence
- Installation/repository reconciliation and lifecycle event processor
- End-to-end Staging verification

No production credentials, live database, or external GitHub App configuration are changed by these primitives.
