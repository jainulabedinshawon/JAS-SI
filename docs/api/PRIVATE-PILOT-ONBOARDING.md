# JAS-SI Private Pilot API Onboarding (Draft)

Status: internal operator runbook. Not a public signup flow. Do not send a customer an API key until the backend key registry and private staging deployment are implemented and tested.

## Pilot access sequence

1. Approve the pilot use case and identify the customer organization.
2. Create a tenant record using the operator-only provisioning tool.
3. Issue a short-lived key with only the required scopes:
   - `authorization:check`
   - `outcomes:submit`
   - `github:evidence:verify`
4. Deliver the one-time token through an approved secret-sharing channel.
5. Give the customer the API base URL, expiry date, enabled scopes, rate-limit policy, and support contact.
6. Validate a cURL smoke test from a clean environment.
7. Record the customer acceptance and key ID (never the secret) in the pilot ledger.

## Client configuration

Store credentials in a secret manager or environment variables:

```bash
export JAS_SI_API_URL="https://<private-staging-host>"
export JAS_SI_API_KEY="<one-time-issued-token>"
```

Do not put the key in source control, screenshots, shell history, issue comments, or chat.

## Smoke test: authorization

```bash
curl --fail-with-body --silent --show-error \
  --request POST "$JAS_SI_API_URL/v1/authorize" \
  --header "Content-Type: application/json" \
  --header "Accept: application/json" \
  --header "X-API-Key: $JAS_SI_API_KEY" \
  --data '{
    "action_id": "pilot-action-001",
    "action": "read_repository",
    "resource": "README.md"
  }'
```

A response with `allowed: true` is an authorization decision only. The customer application must enforce the decision. JAS-SI does not execute the action.

## Smoke test: outcome submission

```bash
curl --fail-with-body --silent --show-error \
  --request POST "$JAS_SI_API_URL/v1/verify" \
  --header "Content-Type: application/json" \
  --header "Accept: application/json" \
  --header "X-API-Key: $JAS_SI_API_KEY" \
  --data '{
    "action_id": "pilot-action-001",
    "claimed_success": true
  }'
```

This route evaluates the submitted claim. Caller-provided evidence references are not independently fetched by this endpoint.

## Smoke test: GitHub evidence integrity

```bash
curl --fail-with-body --silent --show-error \
  --request POST "$JAS_SI_API_URL/v1/github/evidence" \
  --header "Content-Type: application/json" \
  --header "Accept: application/json" \
  --header "X-API-Key: $JAS_SI_API_KEY" \
  --data '{
    "repository": "OWNER/REPOSITORY",
    "commit_sha": "<40-character-commit-sha>",
    "paths": ["README.md"]
  }'
```

This checks Git blob integrity at an immutable commit; it does not establish semantic correctness or task completion.

## Pilot operator checklist

- [ ] Private staging host uses valid HTTPS.
- [ ] PostgreSQL migration 001 and 002 applied and backed up.
- [ ] Key registry and pepper are enabled; no legacy shared key in preview/production.
- [ ] Tenant/key scopes and expiry are confirmed.
- [ ] Customer has received the API URL and one-time key through an approved channel.
- [ ] cURL smoke tests pass.
- [ ] Authentication failures, rate limits, and key revocation have been tested.
- [ ] Audit events contain key IDs only, never raw API keys.
- [ ] Pilot scope, data handling, support, and expiry are agreed.

