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

## Operator provisioning (internal only)

Use two separate Neon credentials. The API runtime credential must never be used by the operator CLI.

- `JAS_SI_DATABASE_URL`: least-privilege runtime role used by the API service.
- `JAS_SI_PROVISIONER_DATABASE_URL`: separate operator role used only from a trusted administrative shell.
- `JAS_SI_API_KEY_PEPPER`: independently generated secret of at least 32 random bytes; store in an approved secret manager.

Generate one fresh staging pepper in a trusted terminal (do not use chat or a ticket):

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Store the same value in the branch-scoped Vercel Preview variable and the operator's secret manager. The earlier staging pepper was configured before any keys were issued; replace it with the operator-controlled value before the first key is provisioned. After keys exist, do not rotate the pepper without a versioned migration plan.

For the Neon `jas_si_provisioner` role, reset its password in the Neon console if the initial one-time password is unavailable, then store its connection string in the operator's local secret manager. Never put this credential in Vercel runtime variables.

Example shell configuration:

```bash
export JAS_SI_PROVISIONER_DATABASE_URL="postgresql://<provisioner-role>:<password>@<host>/<database>"
export JAS_SI_API_KEY_PEPPER="<secret-manager-value-at-least-32-bytes>"

python tools/api_keys.py create-tenant --name "Pilot Customer" --created-by "operator-id"
# Copy the returned tenant_id, then:
python tools/api_keys.py issue-key \
  --tenant-id "<tenant-uuid>" \
  --name "pilot-staging" \
  --created-by "operator-id" \
  --scope authorization:check \
  --scope outcomes:submit \
  --scope github:evidence:verify \
  --expires-in-days 30
```

The issue command prints the token once. Capture it directly in the approved secret manager; do not paste it into tickets or chat. To revoke a key:

```bash
python tools/api_keys.py revoke-key --key-id "<key-uuid>" --revoked-by "operator-id"
```

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
- [ ] PostgreSQL migrations 001 and 002 are applied and backed up.
- [ ] Runtime and provisioner database credentials are separate and least-privileged.
- [ ] Key registry and pepper are enabled; no legacy shared key in preview/production.
- [ ] Tenant/key scopes and expiry are confirmed.
- [ ] Customer has received the API URL and one-time key through an approved channel.
- [ ] cURL smoke tests pass.
- [ ] Authentication failures, rate limits, and key revocation have been tested.
- [ ] Audit events contain key IDs only, never raw API keys.
- [ ] Pilot scope, data handling, support, and expiry are agreed.
