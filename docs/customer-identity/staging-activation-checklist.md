# JAS-SI Customer Onboarding — Staging Activation Checklist

**Status (2026-11-13): blocked on isolated runtime configuration.**  
This checklist is an operator handoff. It is not authorization to change Vercel, Neon, Production, payment settings, or customer data.

## What is already in the PR #36 branch

- Customer registration, email verification, magic-link login, and secure session cookies.
- PostgreSQL-backed shared registration/login abuse limiting.
- Tenant-scoped API-key create/list/revoke routines.
- Tenant-scoped technical usage summary and keyset-paginated history.
- Free technical quota reservation.
- Public plan catalogue; paid tiers remain preview-only.
- Customer email adapter using SMTP STARTTLS (or SMTP-over-TLS on port 465).

Passing CI is evidence for the tested code paths, not evidence that external runtime services or a live customer journey are configured.

## Configuration audit result

A read-only Vercel project environment metadata check found 15 environment-variable entries. It did not find any customer-specific runtime configuration entries. In particular, the following were absent from the inspected project environment metadata:

- `JAS_SI_CUSTOMER_DATABASE_URL`
- `JAS_SI_CUSTOMER_API_KEY_DATABASE_URL`
- `JAS_SI_CUSTOMER_TOKEN_PEPPER`
- `JAS_SI_CUSTOMER_SMTP_HOST`
- `JAS_SI_CUSTOMER_SMTP_PORT`
- `JAS_SI_CUSTOMER_SMTP_USERNAME`
- `JAS_SI_CUSTOMER_SMTP_PASSWORD`
- `JAS_SI_CUSTOMER_SMTP_SENDER`
- `JAS_SI_CUSTOMER_PUBLIC_URL`

The existing general `JAS_SI_DATABASE_URL` and `JAS_SI_API_KEY_PEPPER` do not replace the dedicated customer identity and customer API-key database connections or the customer session pepper. Do not point the customer DSNs at a database owner, provisioner, superuser, or general API runtime connection.

No secret values were decrypted or read during this audit.

## Staging prerequisites

Complete these in an isolated, disposable Neon staging branch — never against Production as part of this checklist:

1. Create separate least-privilege LOGIN principals for customer identity and customer API-key connections.
2. Grant each login only its corresponding NOLOGIN runtime group role. Do not grant provisioner, owner, general API runtime, or superuser memberships.
3. Apply the migrations in the exact dependency order documented in `customer-api-key-runtime-setup.md`. Inspect existing objects and ACLs; `IF NOT EXISTS` is not proof of schema correctness.
4. Verify the effective `current_user`, `session_user`, role flags, memberships, schema privileges, table/column ACLs, SECURITY DEFINER owners, fixed search paths, RLS policies, and cross-tenant denial.
5. Generate a fresh random customer session pepper (at least 32 UTF-8 bytes) in the approved secret manager. Do not reuse the API-key pepper.
6. Configure the dedicated customer DSNs and customer session pepper only for the exact PR preview branch after the isolated database roles and routines have been verified.
7. Configure SMTP credentials and sender identity using a verified sender domain. Use STARTTLS on the provider's supported submission port or implicit TLS on port 465. Never log tokens, recipients, passwords, or full DSNs.
8. Set the customer public URL to the exact HTTPS preview origin. Do not point preview links at the production customer portal.
9. Keep customer registration disabled until all identity, email, rate-limiter, session, API-key, usage, and tenant-isolation checks pass.
10. Run the customer journey in this order: register → receive email → verify → request login → receive email → sign in → view account → create API key → make authorized API request → view usage and history → revoke key → confirm revoked key is rejected → log out → confirm session is rejected.
11. Confirm SMTP delivery, generic responses for unknown emails, rate-limit behavior across instances, CSRF protection, cookie flags, tenant isolation, and audit evidence.
12. Capture sanitized evidence (test IDs, HTTP status codes, role names, migration versions, and timestamps); never capture credentials, one-time tokens, session cookies, or raw API keys.

## Required Vercel Preview variables

Only add these after the isolated staging database and sender identity exist. Scope every variable to the intended Preview branch; do not add them globally or to Production by default.

| Variable | Purpose |
|---|---|
| `JAS_SI_CUSTOMER_DATABASE_URL` | Customer identity + session + shared abuse-limiter runtime role |
| `JAS_SI_CUSTOMER_API_KEY_DATABASE_URL` | Separate customer API-key self-service runtime role |
| `JAS_SI_CUSTOMER_TOKEN_PEPPER` | Independent customer session/link/IP HMAC pepper |
| `JAS_SI_CUSTOMER_SMTP_HOST` | SMTP provider host |
| `JAS_SI_CUSTOMER_SMTP_PORT` | Submission port (587 or provider-approved TLS port; 465 uses implicit TLS) |
| `JAS_SI_CUSTOMER_SMTP_USERNAME` | Optional provider username |
| `JAS_SI_CUSTOMER_SMTP_PASSWORD` | Optional provider password; set together with username |
| `JAS_SI_CUSTOMER_SMTP_SENDER` | Verified sender address |
| `JAS_SI_CUSTOMER_PUBLIC_URL` | Exact HTTPS preview origin |

The existing Vercel `VERCEL_ENV` fallback determines Preview/Production cookie and trusted-proxy behavior unless `JAS_SI_ENVIRONMENT` is explicitly overridden. Do not override a Preview deployment to development or test.

## Billing and entitlement boundary

Paid checkout is not part of this JAS-SI branch. The plan catalogue is descriptive; Starter, Pro, and Enterprise must remain non-purchasable. JAS Platform is the authoritative owner of payment state, invoices, refunds, and paid entitlements. JAS-SI must consume an authenticated, verifiable entitlement decision from JAS Platform before any paid quota or capability is granted.

Do not collect card details, publish unverified prices, accept manual payment references, or mark an account paid from a browser request. Before paid access is enabled, require an independently authenticated entitlement response, tenant binding, expiry/revocation semantics, replay protection, audit evidence, and tests for downgrade/refund/chargeback outcomes.

## Explicit approval gates

This checklist does not authorize:
- Production schema migrations or role/grant changes.
- Production environment-variable changes or secret rotation.
- Vercel deployment/redeployment or project setting changes.
- PR merge.
- Payment-provider activation, charges, refunds, or live paid entitlements.

Those actions require a separate review and explicit approval. If a staging migration fails, stop, preserve logs/state, and use a reviewed recovery plan validated on a disposable database; do not improvise destructive rollback SQL.
