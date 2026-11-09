# JAS-SI PHP SDK (contract-first integration)

A PHP 8.1+ client scaffold for the JAS-SI API v1 contract.

**Release status: pre-release / internal integration.** The OpenAPI file defines the intended wire contract; it is not proof that a production API server is deployed. Do not point production workloads at the placeholder server URL.

## Requirements

- PHP 8.1 or later
- PHP cURL extension (\`ext-curl\`)
- Composer 2
- For contract integration tests: Node.js/npm and the Prism CLI (CI invokes it through \`npx\`)

## Source of truth

The canonical runtime contract is maintained at:

- docs/api/openapi-v1.yaml

The SDK copy at sdks/php/openapi/jas-si-api-v1.yaml is byte-for-byte identical and used by SDK tooling. CI compares both files before linting. The canonical schema documents the actual FastAPI request/response fields, validation limits, authentication errors, rate limits, and service-unavailable behavior. Backend and SDK changes must update the canonical contract and SDK copy together.

The servers entry uses the reserved .invalid domain as a deliberate placeholder. Replace it only when a real deployment URL exists.

## Install for repository development

The Composer manifest currently lives at the monorepo root and maps the \`JASSI\\\\\` namespace to \`sdks/php/src/\`.

\`\`\`bash
composer install
composer dump-autoload
composer test
composer analyse
\`\`\`

The package is not yet published on Packagist. Do not use a public Packagist install command for this pre-release branch.

## API key onboarding

There is currently **no public self-service API-key issuance endpoint or customer key portal** in this repository.

For internal testing:
1. Obtain a test key directly from the administrator of the separately deployed JAS-SI API.
2. Confirm which environment and tenant the key belongs to, its allowed scopes, expiry, and rotation/revocation process.
3. Store it in a secret manager or an uncommitted environment file.
4. Never paste the key into source code, GitHub issues, logs, or chat.

Example environment configuration:

\`\`\`bash
export JAS_SI_API_URL="https://your-real-api-host"
export JAS_SI_API_KEY="issued-out-of-band-by-your-api-operator"
\`\`\`

The SDK does not create, issue, rotate, or revoke API keys. If there is no API operator/deployment yet, a customer cannot obtain a usable production key and cannot use a hosted service.

## Example

\`\`\`php
<?php
require __DIR__ . '/vendor/autoload.php';

use JASSI\\\\Client;

$baseUrl = getenv('JAS_SI_API_URL');
$apiKey = getenv('JAS_SI_API_KEY');

if (!is_string($baseUrl) || $baseUrl === '' || !is_string($apiKey) || $apiKey === '') {
    throw new RuntimeException('Set JAS_SI_API_URL and JAS_SI_API_KEY.');
}

$client = new Client($baseUrl, $apiKey);
$decision = $client->authorize('deploy-2026-001', 'deploy', 'production/my-service');

if (($decision['allowed'] ?? false) !== true) {
    throw new RuntimeException('JAS-SI did not authorize this action.');
}

// The calling application must enforce the decision before taking the action.
// An authorization response is not execution, and this SDK never executes actions.
\`\`\`

## Endpoints

| SDK method | HTTP route | Purpose |
|---|---|---|
| \`authorize()\` | \`POST /v1/authorize\` | Evaluate an authorization request |
| \`verify()\` | \`POST /v1/verify\` | Submit an outcome claim and optional caller-provided evidence references |
| \`verifyGithubEvidence()\` | \`POST /v1/github/evidence\` | Check GitHub blob integrity at an immutable commit |

All routes require \`X-API-Key\`. See the OpenAPI spec for exact schemas and responses.

## Contract and backend conformance tests

CI lints the canonical OpenAPI contract, verifies the SDK copy is identical, and starts a Prism mock server for deterministic schema-level tests. It also starts the actual FastAPI application in an isolated test-mode process and runs the PHP SDK against it.

The backend conformance suite asserts the real authorize/verify response fields and validation boundaries, including the 256-character observed-state limit, lowercase GitHub SHA, 500-character path limit and duplicate-path rejection. The backend process uses a test-only static API key and JSONL audit file; it does not connect to a production database or use production credentials.

Run Prism locally in a separate terminal:

```bash
npx --yes @stoplight/prism-cli mock docs/api/openapi-v1.yaml --host 127.0.0.1 --port 4010
```

Then run the Prism tests:

```bash
JAS_SI_MOCK_URL=http://127.0.0.1:4010 composer test
```

Prism is a contract mock, not the real JAS-SI backend. Passing Prism tests proves SDK/schema compatibility only. BackendContractTest.php is the separate suite that calls a running FastAPI instance.

## Verification and security boundaries

- Authorization evaluation is not execution or enforcement in the caller's system.
- Caller-submitted state and evidence references are not independently verified by the SDK.
- Git blob integrity does not prove semantic correctness, task completion, or the truth of an agent claim.
- The SDK is not a security certification or proof that an agent completed its objective.
- The client requires HTTPS except for localhost development, validates TLS certificates, does not follow redirects, and applies bounded timeouts.

## Distribution status

This monorepo's root Composer manifest is useful for development but is not an appropriate public package boundary: publishing it would distribute the monorepo source. The initial release should remain an internal Git/VCS dependency or use a dedicated SDK repository/subtree split.

The package declares a proprietary license. Confirm commercial-use and redistribution terms before any public distribution. Hosted API availability, tenant isolation, key lifecycle, billing, rate limits, support, and service-level commitments are not implemented by this SDK.
