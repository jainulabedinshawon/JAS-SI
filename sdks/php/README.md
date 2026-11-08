# JAS-SI PHP SDK (early integration)

A small PHP 8.1+ client for the JAS-SI REST API.

## Requirements

- PHP 8.1 or later
- PHP cURL extension (ext-curl)
- A reachable JAS-SI API deployment and valid API key

## Local use

From the repository root, run:

~~~bash
composer dump-autoload
~~~

The root Composer metadata maps the JASSI namespace to sdks/php/src/.

## Configure

Keep credentials in environment variables or a secret manager. Never hard-code or commit API keys.

~~~bash
export JAS_SI_API_URL="https://your-jas-si-api.example"
export JAS_SI_API_KEY="your-api-key"
~~~

## Example

~~~php
<?php
require __DIR__ . '/vendor/autoload.php';

use JASSI\Client;

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

// Your application must enforce the decision before executing an action.

$result = $client->verifyGithubEvidence(
    'OWNER/REPOSITORY',
    '0123456789abcdef0123456789abcdef01234567',
    ['README.md', 'src/main.php']
);
~~~

## Methods

- authorize(actionId, action, resource) → POST /v1/authorize
- verify(actionId, claimedSuccess, observedState?, evidenceRef?) → POST /v1/verify
- verifyGithubEvidence(repository, commitSha, paths) → POST /v1/github/evidence

Protected routes require X-API-Key. The SDK uses HTTPS, validates TLS certificates, does not follow redirects, and does not log credentials or request bodies.

## Verification boundaries

- Authorization evaluates policy; it does not execute or enforce actions in the caller's system.
- The current /v1/verify route accepts caller-submitted state/evidence references; it does not itself fetch or independently validate those evidence sources.
- /v1/github/evidence retrieves files from GitHub at a full commit SHA and checks Git blob integrity. It does not prove semantic correctness, task completion, or the truth of an agent claim.
- This SDK is not a security certification or proof that an agent completed its objective.

This is an early integration SDK. Hosted public API availability, customer onboarding, tenant isolation, key lifecycle management, billing, and service-level commitments remain separate release requirements.
