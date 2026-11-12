# JAS-SI Developer Console

The root route serves a static, responsive developer landing page. The page reads the public health endpoint at runtime and links to the generated OpenAPI/Swagger documentation.

## Security and product boundaries

- The public console never displays, requests, or stores an API key.
- Customer self-service API-key creation and revocation are exposed only in the signed-in `/customer` portal and only when the dedicated database roles, migrations and secrets are configured. Otherwise, keys remain operator-provisioned.
- Tenant usage summary and event history are available in the signed-in customer portal when its database boundary is enabled. The public console does not display tenant usage.
- Usage values are technical units, not money, invoices, paid credit or payment status. Billing remains disconnected until a reviewed payment and entitlement implementation is enabled.
- Quickstart examples use the currently implemented `X-API-Key` header and `/v1/authorize` schema.
- The API evaluates authorization and verifies outcomes; it does not execute actions.
- No production environment, database, secret, deployment, or existing API route is modified by this feature branch.

## Local verification

Run the repository test suite in the project’s supported Python environment. The dashboard-specific tests verify the root HTML response and preserve the health endpoint’s JSON contract.

## GitHub evidence verification

The protected `POST /v1/github/evidence` endpoint verifies that requested file contents match GitHub Git blob identifiers at the supplied immutable commit SHA. A successful result establishes repository content integrity only; it does not establish semantic truth or prove that an action occurred.

Every verification attempt that reaches the endpoint records a sanitized `github_evidence_verification` event in the configured security event store. The event includes the request ID, tenant/key identity when available, repository, commit SHA, requested file count, outcome, and HTTP status. It does not store file contents, API tokens, or GitHub authorization headers. If the audit event cannot be persisted, the endpoint fails closed with HTTP 503 rather than returning an unaudited result.


## Interactive demonstration

The public `/demo` route is a browser-only walkthrough using synthetic fixtures. It illustrates `FALSE_SUCCESS`, a matching success report, and `INCONCLUSIVE` when evidence is missing. It does not call the API, contact GitHub, collect independent evidence, execute actions, or write audit events. Every result is labelled synthetic and must not be represented as a live verification result.
