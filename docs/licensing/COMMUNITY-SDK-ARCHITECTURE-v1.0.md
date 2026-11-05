JAS-SI Community SDK Architecture v1.0

Licensing Model: Hybrid / Open Core
Target License: Apache-2.0
Status: Proposed — Pending Implementation

1. Objective

Create an independent, open-source Python client SDK that communicates with the JAS-SI REST API over HTTPS.

The Community SDK must not contain or reproduce proprietary authorization or verification implementations.

2. Repository Separation

Proposed repository:

"jainulabedinshawon/jas-si-python-client"

This repository will be independently licensed under Apache License 2.0 after the source, dependencies, and contributor rights are reviewed.

The existing JAS-SI repository retains its current licensing boundaries.

3. Community SDK Responsibilities

The client SDK may provide:

- API connection management.
- API key authentication through HTTP headers.
- Health endpoint access.
- Authorization API requests.
- Outcome verification API requests.
- GitHub evidence integrity API requests.
- HTTP timeout and error handling.
- Typed request and response models.
- Usage examples and documentation.

4. Explicit Exclusions

The Community SDK must not include:

- AuthorizationGate implementation.
- Proprietary authorization policy logic.
- Verification engine implementation.
- Internal security event storage.
- Database or audit-chain implementation.
- API server implementation.
- External action execution.
- Any functionality that bypasses the hosted API's authorization controls.

5. API Interface

The client may communicate with these documented endpoints:

Endpoint| Purpose
"GET /health"| Service health
"POST /v1/authorize"| Authorization evaluation
"POST /v1/verify"| Outcome verification request
"POST /v1/github/evidence"| GitHub commit and file integrity verification

Protected endpoints require the configured "X-API-Key" header.

The client must report API responses faithfully and must not reinterpret an inconclusive result as verified success.

6. Technical Requirements

- Python 3.10 compatibility.
- HTTPS by default.
- Configurable API base URL.
- Configurable request timeout.
- Secure API key handling.
- No hardcoded credentials.
- No local copies of proprietary Core logic.
- Automated unit tests using mocked HTTP responses.
- Clear handling of HTTP errors and malformed responses.

7. Licensing Requirements

- Apache-2.0 applies only to the independent Community SDK repository.
- Third-party dependencies retain their original licenses.
- Copyright and attribution notices must be preserved.
- Contributor rights must be reviewed.
- The existing JAS-SI Core is not relicensed by this SDK.

8. Release Gate

Before publishing the Community SDK:

1. Confirm technical independence from the Core.
2. Review all source files and dependencies.
3. Verify API compatibility against the deployed API.
4. Run automated tests.
5. Add Apache-2.0 LICENSE and appropriate NOTICE information.
6. Publish a versioned SDK release.

Next milestone: Independent Python HTTP client implementation.
