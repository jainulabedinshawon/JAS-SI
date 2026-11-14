# JAS-SI API Developer Quickstart

This guide documents the API contract currently implemented on the customer-onboarding branch. It is not evidence that a production deployment, customer database, or customer API-key self-service has been enabled.

## 1. Choose an environment

Set the base URL for an environment you are authorized to use. Do not assume a preview URL is production.

```bash
export JAS_SI_BASE_URL="https://your-authorized-jas-si-host"
```

Check service health and the public plan catalogue:

```bash
curl --fail-with-body --silent --show-error \
  "$JAS_SI_BASE_URL/health"

curl --fail-with-body --silent --show-error \
  "$JAS_SI_BASE_URL/plans"
```

The Free plan exposes a bounded technical-usage quota. Paid plans remain preview-only while payment processing and paid entitlements are disconnected. Usage units are not currency, invoices, or stored monetary credit.

## 2. Obtain and protect an API key

The `X-API-Key` header authenticates protected API operations. Until customer self-service key management has been enabled for the target environment, obtain a scoped key through the approved operator provisioning process. The signed-in `/customer` portal supports customer key management only after its dedicated database roles, migrations, and secrets are configured.

Store the key in a secret manager or local environment variable. Never commit it, place it in browser JavaScript, paste it into support tickets, or include it in logs.

```bash
export JAS_SI_API_KEY="replace-with-your-secret"
```

## 3. Evaluate an authorization request

`POST /v1/authorize` evaluates a decision and records a security event. It does **not** execute the requested action and its response always reports `executed: false`.

```bash
curl --fail-with-body --silent --show-error \
  -X POST "$JAS_SI_BASE_URL/v1/authorize" \
  -H "X-API-Key: $JAS_SI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "action_id": "demo-action-001",
    "action": "read_report",
    "resource": "reports/monthly-summary"
  }'
```

Your application must enforce the returned decision at its own action boundary. Do not treat an `allowed` response as proof that an action was executed.

## 4. Submit an outcome claim

`POST /v1/verify` evaluates a caller-submitted outcome claim. It does not independently fetch the referenced evidence. The caller cannot establish evidence independence merely by setting `collected_independently`.

```bash
curl --fail-with-body --silent --show-error \
  -X POST "$JAS_SI_BASE_URL/v1/verify" \
  -H "X-API-Key: $JAS_SI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "action_id": "demo-action-001",
    "claimed_success": true
  }'
```

When supplying evidence details, provide both `observed_state` and `evidence_ref`. Treat caller-submitted claims as claims—not as independent proof of real-world success.

## 5. Verify GitHub content integrity

`POST /v1/github/evidence` reads up to 10 requested files at an immutable 40-character commit SHA and recomputes Git blob identifiers. This verifies repository content integrity only; it does not establish semantic truth or prove that an action occurred.

```bash
curl --fail-with-body --silent --show-error \
  -X POST "$JAS_SI_BASE_URL/v1/github/evidence" \
  -H "X-API-Key: $JAS_SI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "repository": "OWNER/REPOSITORY",
    "commit_sha": "0123456789abcdef0123456789abcdef01234567",
    "paths": ["README.md"]
  }'
```

Replace the example repository and SHA with a real repository and immutable commit you are authorized to inspect. A successful response should be interpreted only within its declared integrity-verification scope.

## 6. Inspect tenant usage

`GET /v1/usage` returns technical usage and quota for the tenant resolved from the authenticated API key. It does not accept a caller-supplied tenant ID.

```bash
curl --fail-with-body --silent --show-error \
  "$JAS_SI_BASE_URL/v1/usage" \
  -H "X-API-Key: $JAS_SI_API_KEY"
```

A `since` query parameter may be supplied as a timezone-aware ISO 8601 timestamp. Usage availability depends on the target environment's database configuration.

## 7. Handle errors safely

- `401`: missing or invalid API key; check the secret source and target environment.
- `403`: key is valid but the required scope or tenant boundary is not available.
- `422`: request schema or input validation failed; inspect the response detail without logging secrets.
- `429`: rate limit reached; honor the `Retry-After` header and use bounded backoff.
- `503`: service, database, or durable audit dependency is unavailable; do not report success or retry in a tight loop.
- `502` / `504`: upstream GitHub request failed or timed out; retry only with bounded backoff.

Never log raw API keys, customer session cookies, one-time login links, CSRF values, or authorization headers. Avoid automatic retries for non-idempotent operations unless the endpoint explicitly documents an idempotency contract.

## 8. Customer portal and billing status

The signed-in `/customer` portal provides account, API-key metadata, and tenant usage surfaces when its environment-specific database boundary is enabled. Creating or revoking keys requires a valid customer session and CSRF protection.

Paid checkout, payment collection, invoices, refunds, and paid-plan entitlement are not enabled by this branch. Do not accept payment or grant paid access based on a screenshot or an unverified transaction reference.

## 9. API contract

The generated OpenAPI document is available at `/openapi.json` on a running service. Use it as the machine-readable contract for request and response schemas. This guide reflects the branch implementation and must be rechecked against the deployed environment before customer use.
