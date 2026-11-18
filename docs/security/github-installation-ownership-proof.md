# GitHub App Installation ownership proof

## Trust boundary

A callback `installation_id` is an untrusted lookup candidate. A webhook
payload is an untrusted lifecycle signal. Neither value proves that the
currently authenticated JAS-SI customer controls the GitHub Installation.

The ownership proof primitive in
`jas_si_agent.github_installation_ownership` accepts a GitHub App user access
token obtained through a separate OAuth authorization-code flow. It calls
`GET /user` to identify the GitHub user and exhaustively paginates
`GET /user/installations`. The exact Installation ID must appear in that
authenticated user's list and its `app_id` must match the configured JAS-SI
GitHub App ID. Account ID, login, and account type are returned as evidence.

GitHub API failures, malformed responses, pagination bounds, app mismatch,
and absent Installation access all fail closed. Error messages do not include
the access token or upstream response body. The caller is responsible for
discarding the short-lived user token after verification.

## Required integration sequence

1. Authenticate the customer through the existing JAS-SI customer session.
2. Generate a cryptographically random OAuth state and PKCE verifier.
3. Persist only keyed digests of state, PKCE verifier, and a callback-binding
   cookie, together with tenant/account identity and a short expiry.
4. Redirect to GitHub's GitHub App OAuth authorization endpoint.
5. On callback, atomically consume the single-use state and verify the
   callback-binding cookie before exchanging the authorization code.
6. Use the resulting user access token with this ownership verifier.
7. Reconcile the Installation and its complete paginated repository list
   through the GitHub App API. A webhook received earlier remains
   `PENDING_UNCLAIMED`; it cannot activate the binding.
8. Activate only after customer ownership proof and authoritative App API
   reconciliation both succeed. Any mismatch or API outage leaves the
   Installation inactive.

The current primitive does not implement OAuth state persistence, code
exchange, webhook event processing, reconciliation, or activation. It does
not issue installation tokens and must not be treated as a complete onboarding
flow or production-ready feature.

## GitHub API references

- List App installations accessible to the user access token:
  https://docs.github.com/en/rest/apps/installations#list-app-installations-accessible-to-the-user-access-token
- Generate a GitHub App user access token:
  https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app
