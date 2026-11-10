# JAS-SI Standalone-First Product Architecture Decision

**Status:** Accepted project direction; implementation and operational readiness remain subject to evidence.  
**Decision date:** 2026-11-10  
**Scope:** JAS-SI product architecture and delivery sequence.

## 1. Decision

JAS-SI will reach independently deployable and customer-usable product readiness before integrating with JAS Platform.

JAS-SI must not depend on JAS Platform being deployed, commercially ready, or available for a customer to register, authenticate, obtain an API key, use the API within a standalone quota, inspect usage, or complete onboarding.

This decision changes the implementation sequence and the interim ownership boundary. It does not authorize production migrations, payment operations, or destructive changes.

## 2. Standalone responsibilities

During the standalone-first phase, JAS-SI owns and operates:

- Customer registration, login, sessions, account recovery/verification, and tenant lifecycle.
- Tenant-scoped API-key issuance, rotation, revocation, and secure display-once handling.
- Developer portal, public API documentation, interactive product demo, and customer onboarding.
- Durable usage-event metering, idempotency, tenant-scoped usage views, and operational limits.
- A standalone entitlement/quota implementation with explicit free-tier policy and fail-closed behavior where required.
- Security controls, audit events, support diagnostics, CI, verification, and benchmark evidence.

These are product responsibilities, not claims that the features are already implemented. Each capability requires tests and a real customer-journey proof before it can be marked complete.

## 3. Provider boundaries for future integration

Core product logic must depend on narrow provider contracts rather than hard-coded assumptions about a future central platform.

Initial standalone implementations should be provided for:

- IdentityProvider: customer and tenant identity operations.
- EntitlementProvider: feature access, quota decisions, and usage limits.
- BillingProvider: an explicit not-configured/no-payment implementation until a real payment system is selected and approved.

The interfaces must define stable tenant/customer identifiers, error semantics, idempotency, security requirements, and migration/linking behavior. Avoid duplicating identity or entitlement logic across adapters.

A future JAS Platform adapter may be added behind these contracts. Platform account linking and migration must be explicit, auditable, reversible where feasible, and must not silently merge customer identities or tenant data.

## 4. Billing and payment boundary

Standalone usage metering and free-tier quota enforcement are in scope now. They are not payment processing and must not be represented as paid billing.

Until a real payment provider is selected, onboarded, configured, security-reviewed, and tested end-to-end:

- Do not expose a checkout flow or claim that customers can pay.
- Do not grant paid entitlements based on browser redirects or caller-supplied claims.
- Do not treat technical usage events as monetary charges.
- Clearly label paid plans/payment as unavailable or not configured.

A future commercial phase may connect JAS Platform as the central owner of catalog, checkout, payment verification, subscriptions, invoices, refunds, financial ledger, and cross-product commercial entitlements. JAS-SI will consume authenticated entitlement decisions through its adapter; it will not create a competing financial authority.

## 5. Product architecture

```text
Customer / Developer
        |
        v
JAS-SI standalone product
  - Customer Portal / IdentityProvider
  - Tenant + API Key Registry
  - Developer Portal / API / Demo
  - EntitlementProvider (standalone free quota)
  - Usage Meter + Customer Usage Dashboard
  - Authorization / Verification / Audit
        |
        +---- future provider adapters ----+
                                           |
                                           v
                                  JAS Platform (future)
                                  - Central accounts/linking
                                  - Catalog and checkout
                                  - Payments and subscriptions
                                  - Financial ledger
                                  - Commercial entitlements
```

JAS-SI's authorization and verification semantics remain independent of commercial entitlement. A valid quota grant never bypasses the authorization gate; authorization does not prove an outcome; verification must evaluate appropriate evidence.

## 6. Security and data requirements

- Derive tenant context from authenticated server-side identity/API-key records; never trust tenant IDs supplied in request bodies.
- Hash secrets/tokens at rest using reviewed keyed-digest practices; show API secrets only once.
- Use secure, HttpOnly, SameSite cookies for browser sessions, with CSRF protection where applicable.
- Rate-limit registration, login-link/verification, key issuance, and sensitive account operations.
- Prevent account enumeration through uniform public responses for sensitive identity flows.
- Enforce tenant isolation in database queries and tests, including negative cross-tenant cases.
- Keep identity, usage, entitlement, and audit records durable and traceable.
- Never store raw customer request bodies solely for idempotency; store a cryptographic fingerprint and the necessary request metadata.
- Apply schema migrations only through reviewed, tested, explicitly approved operational procedures.

## 7. Delivery gates

The product is not customer-ready until evidence demonstrates all applicable gates:

1. **Identity:** a real user can register, verify, sign in, sign out, recover access, and maintain an isolated tenant.
2. **API keys:** a customer can create, view once, rotate, revoke, and use a key; revoked/foreign keys are rejected.
3. **API:** documented endpoints work against the deployed service with correct authentication, validation, errors, and tenant isolation.
4. **Quota and usage:** limits are enforced durably; retries are idempotent; customer-visible usage reconciles to persisted events.
5. **Portal and onboarding:** a new customer can complete onboarding without operator-only hidden steps.
6. **Demo:** the demo clearly distinguishes synthetic walkthroughs from real API-backed behavior.
7. **Security:** automated tests and review cover authentication, authorization, secrets, rate limits, tenant isolation, and abuse cases.
8. **Operations:** CI, deployment, health checks, logs, backup/recovery and rollback procedures are evidenced.
9. **Verification:** a complete customer journey is exercised against the deployed environment; screenshots/logs/API responses and relevant run IDs are retained.
10. **Commercial honesty:** payment and paid entitlements remain explicitly unavailable until independently verified end-to-end.

A green CI run, merged PR, successful deployment status, or synthetic demo alone does not satisfy these gates.

## 8. Migration from standalone to Platform

When JAS Platform is ready, integration requires a separate reviewed plan covering:

- Customer identity linking and collision handling.
- Tenant/account ownership mapping.
- API-key continuity or safe rotation.
- Entitlement precedence and transition windows.
- Usage-event reconciliation and idempotency across systems.
- Downtime, rollback, auditability, privacy, and customer communication.

No automatic migration or identity merge is implied by this decision.

## 9. Supersession and compatibility

This decision supersedes earlier JAS-SI planning statements that make JAS Platform a prerequisite for standalone identity, quota enforcement, or customer onboarding.

Existing billing architecture documents remain useful for the future Platform-owned commerce boundary, but must be interpreted consistently with this standalone-first sequence. In case of conflict about the current delivery phase, this decision governs until explicitly replaced by a newer accepted decision.

## 10. Completion discipline

Maintain separate states for **implemented**, **tested**, **deployed**, and **verified in a real customer journey**. Never collapse them into a single “complete” label. Report blockers and unavailable capabilities plainly.