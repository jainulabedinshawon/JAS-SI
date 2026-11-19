# GitHub App user OAuth and Installation reconciliation

## Purpose

JAS-SI uses a customer-session-bound GitHub App user-authorization flow to prove that an authenticated GitHub user can access a candidate Installation. A successful proof is stored as a pending customer claim. Installation and repository access remain unavailable until a separate reconciler obtains authoritative facts from GitHub's App API and applies the matching claim.

## OAuth start and state binding

1. Require an active JAS-SI customer session and CSRF validation.
2. Derive tenant and customer-account IDs only from that authenticated session.
3. Accept a positive candidate Installation ID at OAuth start. Treat it as untrusted lookup input, not proof.
4. Generate high-entropy OAuth state and a PKCE verifier using S256.
5. Encrypt the verifier with AES-256-GCM. Persist only the state digest, candidate Installation ID, authenticated tenant/account IDs, expiry, redirect-URI digest, ciphertext, and key version through the database-owned create routine.
6. Only after persistence succeeds, return the GitHub authorization URL.
7. The browser receives a five-minute, HttpOnly, path-scoped, SameSite=Lax state cookie. Production and preview use Secure.

Raw state, plaintext PKCE verifier, authorization code, and access token are not persisted in PostgreSQL.

## Callback and pending claim

GitHub's OAuth callback is expected to return `code` and `state`; the candidate Installation ID is not trusted from the provider callback. It was bound to the OAuth attempt at start and is returned by the atomic consume routine.

The callback page:
- Requires exactly one state and one code and rejects provider error responses.
- Constant-time compares state against the short-lived cookie.
- Uses a nonce-based Content Security Policy, no-store caching, and no-referrer policy.
- Removes the authorization code from browser history before submitting the same-origin completion POST.
- Uses the existing SameSite=Strict customer session and CSRF cookies on that same-origin POST.

The completion route atomically consumes the state record for the same active customer session before decrypting the verifier. It exchanges the code with GitHub, verifies the resulting `/user` identity, then independently checks that the candidate Installation appears in the authenticated user's complete Installation list and belongs to the expected GitHub App ID.

After user and Installation identity match, the API records a durable row through `customer_github_installation_claim_record`. The database routine derives tenant/account ownership from the current customer session; it does not accept tenant/account IDs from the browser. The Installation ID is unique across claims. Repeated claims from the same customer and same GitHub identities are idempotent; a different customer or identity cannot take over an existing Installation claim.

The claim starts as `pending_reconciliation`. OAuth success does not activate an Installation or any repository.

## Authoritative GitHub App reconciliation

The implementation now includes:
- `GitHubAppInstallationAPI`: signs short-lived RS256 App JWTs in memory, fetches the current Installation record, verifies the configured App ID/account, handles suspended or missing Installations, mints a short-lived Installation token, and exhaustively paginates the complete `/installation/repositories` response.
- `GitHubInstallationReconciler`: claims durable webhook inbox deliveries through restricted database routines. It ignores webhook payload account/repository/tenant claims and uses the Installation ID only as a lookup candidate.
- `jas_si_github_installation_reconcile_apply`: a database-owned SECURITY DEFINER routine, callable only by the dedicated `jas_si_github_reconciler` capability. It requires an existing pending ownership claim, matches the App ID and GitHub account identity, and requires the customer tenant to remain active before enabling access.
- A complete repository snapshot is applied atomically. Repositories removed from the live GitHub App allowlist are marked revoked. Installation suspension revokes the current binding; deletion (GitHub API 404) revokes the claim and all bindings. Unsuspension can reactivate only after a fresh matching App API snapshot.
- The reconciler has EXECUTE-only access to reconciliation and inbox claim/finish routines. It cannot read or write the claim, installation, repository, or webhook inbox tables directly, and cannot call the public webhook receive routine.
- Missing claims and provider/database failures are retried through the fenced webhook lease state machine. A lost lease is not reported as processed.

Webhook deliveries are authenticated over exact raw bytes and durably stored before acknowledgement. They are signals only. The live GitHub App API response, together with the customer-bound pending claim, is the authority for Installation and repository state.

## Reconciler configuration (not deployed)

The isolated reconciler host requires:
- `JAS_SI_GITHUB_APP_ID`
- `JAS_SI_GITHUB_APP_PRIVATE_KEY_B64` (base64-encoded PEM RSA private key; keep in a secret manager)
- `JAS_SI_GITHUB_RECONCILER_DATABASE_URL` (dedicated login granted membership in `jas_si_github_reconciler`; no direct table privileges)
- Optional `JAS_SI_GITHUB_RECONCILER_POLL_SECONDS` (5–300 seconds; default 15)

The public API webhook receiver separately requires `JAS_SI_GITHUB_WEBHOOK_SECRET` and `JAS_SI_GITHUB_WEBHOOK_DATABASE_URL`. OAuth browser flow configuration remains separate and requires its customer-session database/pepper, OAuth client ID/secret, fixed HTTPS redirect URI, encryption keyring and active key version.

No private key, webhook secret, reconciler DSN, OAuth secret, or database credential has been created, uploaded, or configured by this code change.

## Remaining verification gates

1. Configure the real GitHub App and isolated reconciler host in Staging using secret-manager-backed credentials.
2. Configure the GitHub App webhook URL/secret and verify signed delivery intake.
3. Run a real isolated customer OAuth flow, then verify pending claim → authoritative reconciliation → exact repository allowlist → suspend/delete/revoke lifecycle.
4. Independently inspect Staging database ACLs, worker health, and customer-visible onboarding before any activation.
5. Production migration, secrets, deployment, and Installation activation remain separate explicit approval gates.

PostgreSQL migration replay and integration tests use disposable databases. No live Neon migration, production deployment, secret change, GitHub App configuration, or Installation activation has been performed.
