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
