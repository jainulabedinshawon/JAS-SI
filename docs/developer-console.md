# JAS-SI Developer Console

The root route serves a static, responsive developer landing page. The page reads the public health endpoint at runtime and links to the generated OpenAPI/Swagger documentation.

## Security and product boundaries

- The public console never displays, requests, or stores an API key.
- API credentials remain managed by the existing tenant-scoped provisioning and revocation workflow.
- Usage/billing counters are explicitly marked unavailable until a trustworthy metering source exists.
- Quickstart examples use the currently implemented `X-API-Key` header and `/v1/authorize` schema.
- The API evaluates authorization and verifies outcomes; it does not execute actions.
- No production environment, database, secret, deployment, or existing API route is modified by this feature branch.

## Local verification

Run the repository test suite in the project’s supported Python environment. The dashboard-specific tests verify the root HTML response and preserve the health endpoint’s JSON contract.

## GitHub evidence verification

The protected `POST /v1/github/evidence` endpoint verifies that requested file contents match GitHub Git blob identifiers at the supplied immutable commit SHA. A successful result establishes repository content integrity only; it does not establish semantic truth or prove that an action occurred.

Every verification attempt that reaches the endpoint records a sanitized `github_evidence_verification` event in the configured security event store. The event includes the request ID, tenant/key identity when available, repository, commit SHA, requested file count, outcome, and HTTP status. It does not store file contents, API tokens, or GitHub authorization headers. If the audit event cannot be persisted, the endpoint fails closed with HTTP 503 rather than returning an unaudited result.
