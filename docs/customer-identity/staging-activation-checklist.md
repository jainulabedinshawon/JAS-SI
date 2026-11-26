# JAS-SI Customer Onboarding — Staging Activation Checklist

**Status (2026-11-14): onboarding code is merged and deployed; live customer activation is blocked by missing dedicated runtime credentials and SMTP configuration.**  
This checklist is an operator handoff. It is not authorization to change Vercel, Neon, Production, payment settings, or customer data.

## Current Production evidence (2026-11-14)

Customer onboarding code from PR #36 is merged into `main` (merge commit `d5f68af0cb31f834472202ec1dea77994b9be81c`). The current Production deployment is READY at commit `e55bc006658647a97ce9e69c7f8fa62b70e9a660` (deployment `dpl_EY8AsWXwyvEFeRABTnPUoWdkqBZQ`).

Read-only live checks returned:
- `GET /health`: HTTP 200, API enabled.
- `GET /customer`: HTTP 200; the standalone portal HTML is served.
- `GET /openapi.json`: HTTP 200; customer identity, session, usage and API-key routes are registered.
- `GET /plans`: HTTP 200; Free exposes 100 technical units by default, while paid tiers are non-purchasable and payment status is `not_connected`.

These checks prove deployment and route availability only. They do not prove registration, email delivery, session creation, API-key issuance, or customer usage end-to-end.

A read-only Production Vercel environment metadata check found no `JAS_SI_CUSTOMER_*` variables. In Production Neon, `jas_si_customer_runtime` and `jas_si_customer_key_runtime` are NOLOGIN group roles, but no dedicated customer LOGIN principals were present in the inspected `jas_si_*` role set. SMTP host/sender/credentials are also absent. Therefore the portal is visible but its customer backend is not activated; do not invite customers or claim self-service onboarding is live.

No secrets were decrypted. No customer registration request, email, or test account was created during these checks.

### Current Preview configuration snapshot (2026-11-15)

Read-only Vercel metadata now shows the dedicated customer identity DSN, customer API-key DSN, and customer session pepper scoped to Preview only. No customer SMTP host/sender/credential variables are configured. These partial Preview settings do not establish that email verification or login works. Production still has none of the dedicated customer identity/key variables. Do not enable customer signup or invite customers until SMTP, role boundaries, the complete journey, and independent staging checks pass.

## What is merged into main

- Customer registration, email verification, magic-link login, and secure session cookies.
- PostgreSQL-backed shared registration/login abuse limiting.
- Tenant-scoped API-key create/list/revoke routines.
- Tenant-scoped technical usage summary and keyset-paginated history.
- Free technical quota reservation.
- Public plan catalogue; paid tiers remain preview-only.
- Customer email adapter using SMTP STARTTLS (or SMTP-over-TLS on port 465).

Passing CI is evidence for tested code paths, not evidence that external runtime services or a live customer journey are configured.

Both layers are now PostgreSQL-backed and shared across application instances, with separate HMAC namespaces and dedicated least-privilege database boundaries:
- Customer registration/login email-abuse limiter: dedicated customer rate-limit table and runtime boundary.
- General versioned API ingress limiter: `jas_si_api_rate_limits`, migration `20261118_shared_api_rate_limits.sql`, and a separate `JAS_SI_API_RATE_LIMIT_PEPPER`.

The general API limiter applies to all `/v1/*` routes, including customer portal API routes; customer registration/login additionally retain the stricter email-abuse limiter. Preview/Production startup must fail unless the shared API limiter pepper, database connection, schema, and privilege boundary verify successfully. Tests cover cross-request behavior, trusted proxy handling, expiry/retry semantics, and denial of direct runtime table access. Live behavior behind the actual Vercel proxy remains unverified until an isolated Preview is configured and exercised.

## Configuration audit result

The latest read-only Production environment metadata check found no customer-specific variables. The following must be provisioned before activation; values must be stored as encrypted/sensitive Vercel variables and never committed:

- `JAS_SI_CUSTOMER_DATABASE_URL`
- `JAS_SI_CUSTOMER_API_KEY_DATABASE_URL`
- `JAS_SI_CUSTOMER_TOKEN_PEPPER`
- `JAS_SI_CUSTOMER_SMTP_HOST`
- `JAS_SI_CUSTOMER_SMTP_PORT`
- `JAS_SI_CUSTOMER_SMTP_USERNAME`
- `JAS_SI_CUSTOMER_SMTP_PASSWORD`
- `JAS_SI_CUSTOMER_SMTP_SENDER`
- `JAS_SI_CUSTOMER_PUBLIC_URL`

The inspected Production environment does contain `JAS_SI_API_RATE_LIMIT_PEPPER`, `JAS_SI_DATABASE_URL`, and `JAS_SI_API_KEY_PEPPER`. Those general API variables do not replace the dedicated customer identity and customer API-key database connections or the customer session pepper. Do not point the customer DSNs at a database owner, provisioner, superuser, or general API runtime connection.

No secret values were decrypted or read during this audit.

## Migration-chain integrity invariant (2026-11-26)

The Main-branch clean replay workflow treats every canonical security and Agent Worker/Verifier migration as required input. Missing migration files must fail CI before SQL execution; they must never be silently skipped as an optional migration. The workflow replays the complete ordered chain twice from a clean PostgreSQL 16 database and then checks the resulting least-privilege boundaries. A green replay is evidence only for the exact workflow commit and migration files in that checkout; it is not evidence that a live Neon branch has been migrated or that a production runtime is deployed.

The mandatory security/agent sequence begins with the customer identity/API-key ACL and audit/rate-limit writer boundaries (20261119–20261122), continues through task scope, task store and worker lifecycle (20261123–20261124), then proceeds through usage scope, failure handling, evidence finalization, verifier claims, default ACLs, active-tenant guard and inconclusive/human-review lifecycle (20261125–20261201). The workflow's explicit ordered list is authoritative; do not infer applied migration state from filenames or table presence alone.

## Agent host liveness and readiness verification

The Worker and independent Verifier supervisors expose local `/health` liveness and `/ready` readiness endpoints. Liveness only confirms the process HTTP handler is responding. Readiness remains HTTP 503 until the host completes a successful database-backed poll; a later poll failure returns readiness to 503. The Main Docker Container Verification workflow exercises the Worker health server inside the locked application image, checks the not-ready-to-ready transition, and verifies the image health check. Unit tests separately cover Worker and Verifier supervisor state transitions. These checks do not prove that a live Render service is deployed or that a real Staging DSN is configured.

## Staging prerequisites

Complete these in an isolated, disposable Neon staging branch — never against Production as part of this checklist:

1. Create separate least-privilege LOGIN principals for customer identity and customer API-key connections.
2. Grant each login only its corresponding NOLOGIN runtime group role. Do not grant provisioner, owner, general API runtime, or superuser memberships.
3. Apply the migrations in the exact dependency order documented in `customer-api-key-runtime-setup.md`, including the API-key authentication and usage-routine migrations. Apply `20261117_runtime_usage_routine_only.sql` only after `20261116_api_key_bound_usage_routines.sql`; verify the API still records usage and reads summary/quota/history through authenticated routines while both `jas_si_runtime` and `jas_si_provisioner` have no direct or inherited usage-table privileges. Inspect existing objects and ACLs; `IF NOT EXISTS` is not proof of schema correctness.
4. Verify the effective `current_user`, `session_user`, role flags, memberships, schema privileges, table/column ACLs, SECURITY DEFINER owners, fixed search paths, RLS policies, and cross-tenant denial.
5. Generate a fresh random customer session pepper (at least 32 UTF-8 bytes) in the approved secret manager. Do not reuse the API-key pepper.
6. Configure the dedicated customer DSNs and customer session pepper only for the exact PR preview branch after the isolated database roles and routines have been verified.
7. Configure SMTP credentials and sender identity using a verified sender domain. Use STARTTLS on the provider's supported submission port or implicit TLS on port 465. Never log tokens, recipients, passwords, or full DSNs.
8. Set the customer public URL to the exact HTTPS preview origin. Do not point preview links at the production customer portal.
9. Configure the dedicated API ingress pepper for the Preview branch and verify the shared limiter startup boundary; keep customer registration disabled until all identity, email, rate-limiter, session, API-key, usage, and tenant-isolation checks pass.
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

JAS-SI is designed to operate as an independent standalone SaaS first. Under ADR-002, each tenant has exactly one server-controlled commerce authority:
- `jas_si_standalone`: JAS-SI will own its provider adapter, order snapshots, verified provider-event inbox, minimal reconciliation ledger, subscription/payment lifecycle, and authoritative paid entitlement for that tenant.
- `jas_platform_linked`: JAS Platform owns checkout, payments, financial records and paid entitlements; JAS-SI consumes an authenticated, tenant-bound entitlement decision.

The authority is selected only from trusted server-side tenant configuration. A tenant must never have both authorities active. ADR-002 is the current architecture authority; the Billing Core v0.1 and manual TrxID documents are historical context where they conflict.

No payment provider, hosted checkout, financial ledger, paid entitlement or manual TrxID collection is active in this PR. The plan catalogue is descriptive; Starter, Pro and Enterprise remain non-purchasable until a provider is selected, sandbox reconciliation passes, prices/unit economics are approved, and separate production authorization is granted.

Do not collect card details in JAS-SI, publish unverified prices, accept browser-supplied payment claims, or mark an account paid from a client request. For standalone mode, only server-verified provider events or authenticated provider lookups may establish payment state. For Platform-linked mode, require an authenticated entitlement response with tenant binding, expiry/revocation semantics, replay protection, audit evidence and tests for downgrade/refund/chargeback outcomes. Never dual-write financial state.

## Explicit approval gates

This checklist does not authorize:
- Production schema migrations or role/grant changes.
- Production environment-variable changes or secret rotation.
- Vercel deployment/redeployment or project setting changes.
- PR merge.
- Payment-provider activation, charges, refunds, or live paid entitlements.

Those actions require a separate review and explicit approval. If a staging migration fails, stop, preserve logs/state, and use a reviewed recovery plan validated on a disposable database; do not improvise destructive rollback SQL.
