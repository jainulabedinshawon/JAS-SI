# JAS-SI PHP SDK (early integration)

A PHP 8.1+ client scaffold for a proposed JAS-SI REST API contract.

IMPORTANT: this repository's current `main` branch does not contain a deployable REST API server or an OpenAPI specification for the routes below. The SDK must not be presented as a working hosted integration until a server implementation and contract tests exist.

## Requirements

- PHP 8.1 or later
- PHP cURL extension (`ext-curl`)
- A separately deployed server that implements the exact request and response contract
- An API key issued by that deployment

## Local development

The Composer manifest currently lives at the repository root and maps the `JASSI\\` namespace to `sdks/php/src/`.

```bash
composer install
composer dump-autoload
composer test
composer analyse
```

## Configure

Keep credentials in environment variables or a secret manager. Never hard-code or commit API keys.

```bash
export JAS_SI_API_URL="https://your-deployed-api.example"
export JAS_SI_API_KEY="your-api-key"
```

## Example

```php
<?php
require __DIR__ . '/vendor/autoload.php';

use JASSI\\Client;

$client = new Client(
    getenv('JAS_SI_API_URL') ?: '',
    getenv('JAS_SI_API_KEY') ?: ''
);

$decision = $client->authorize(
    'deploy-2026-001',
    'deploy',
    'production/my-service'
);

if (($decision['allowed'] ?? false) !== true) {
    throw new RuntimeException('JAS-SI did not authorize this action.');
}

// The caller's application must enforce the authorization decision.
// This SDK does not execute or authorize actions in the caller's environment.
```

## Client methods and proposed routes

| Method | Route | Purpose |
|---|---|---|
| `authorize()` | `POST /v1/authorize` | Submit an authorization request |
| `verify()` | `POST /v1/verify` | Submit an outcome claim and optional caller-provided evidence references |
| `verifyGithubEvidence()` | `POST /v1/github/evidence` | Request GitHub file-integrity checks at an immutable commit |

These paths and payloads are the SDK's current expected contract, not proof that a compatible API server is deployed. Before release, the server owner must publish an OpenAPI specification and automated contract tests covering authentication, request validation, response schemas, error codes, rate limits, and authorization semantics.

## Verification and security boundaries

- Authorization evaluation is not execution or enforcement in the caller's system.
- Caller-submitted state and evidence references are not independently verified by the SDK.
- A Git blob integrity check, if implemented by the server, does not prove semantic correctness, task completion, or the truth of an agent claim.
- The SDK is not a security certification or proof that an agent completed its objective.
- The client requires HTTPS except for localhost development, validates TLS certificates, does not follow redirects, and applies bounded timeouts.
- This SDK has not yet been integration-tested against a live JAS-SI API deployment.

## Packaging status

This is an early integration SDK. The root-level Composer manifest is convenient for repository development but is not yet an ideal public package boundary: publishing it from this monorepo would distribute the whole repository as the package source. Before Packagist publication, split the SDK into a dedicated repository or use a reproducible subtree-split release process.

The package currently declares a proprietary license. Confirm the intended customer redistribution and commercial-use terms before public publication.

Hosted API availability, customer onboarding, tenant isolation, key lifecycle management, billing, rate limits, and service-level commitments remain separate release requirements.
