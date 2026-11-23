# JAS-SI Hosting Strategy — Quota-Aware, No-Cutover Decision

**Status:** Architecture decision; no infrastructure change authorized or performed  
**Baseline:** `main` at `62161081499097b1e8dded97ae09ae3d15b5c344`  
**Assessment date:** 2026-11-23  
**Decision owner:** JAS-SI project owner

## Current verified deployment posture

- Vercel Production is READY for the current `main` commit `62161081499097b1e8dded97ae09ae3d15b5c344`. This proves the web deployment completed; it does not prove Worker/Verifier runtime readiness or customer SaaS readiness.
- Render currently has no services in the connected workspace. Earlier service provisioning returned `need_payment_info`; no paid service or payment method was created.
- Neon has separate Production and Staging branches. Both are reported ready but `protected=false`.
- The latest catalog inspection found 9 of 18 Staging public tables with RLS disabled and 9 of 11 Production public tables with RLS disabled. These include customer identity, audit, rate-limit and usage tables. Do not treat database security as production-ready until each table's access policy and effective role privileges are reviewed and tested.
- The repository includes a Python FastAPI application, Dockerfile and container entrypoint. A static hosting product alone is not a replacement for the API runtime.
- GitHub Actions is the primary code-validation path. The durable task-store PR is not yet integrated into current Main; its Worker/Verifier deployment and authenticated end-to-end customer journey remain unverified.

## Decision

Adopt a **quota-aware, deployment-neutral hybrid strategy**, but do not migrate, upgrade, or create infrastructure until the relevant staging and cost gates pass.

1. **Preserve current Vercel Production and domain configuration.** Keep it as the current web/API deployment while its runtime and account quotas remain suitable. Do not change DNS or production traffic as part of this decision.
2. **Keep the Python FastAPI API as a container workload.** The existing Dockerfile is the portable deployment artifact. A Docker-capable managed host or VPS may be evaluated only after current pricing, region, sleep/cold-start behavior, persistent logs, health checks, secrets, backups and operational burden are verified.
3. **Use Cloudflare only where its role is technically appropriate.** DNS/CDN/WAF can front a separately hosted origin when configured and tested. Workers Static Assets or Pages may serve a future genuinely static frontend/docs bundle; they are not a drop-in runtime for the Python FastAPI container.
4. **Keep PostgreSQL authoritative.** Do not move customer identity, usage, idempotency, payment or audit records into edge KV or static hosting. Any database proxy must preserve transaction, locking, TLS and connection-pool semantics.
5. **Separate public static assets from authenticated API traffic.** Never shared-cache customer sessions, API-key responses, usage, billing, authorization or verification endpoints. Use explicit private/no-store cache policies.
6. **Retain a reversible cutover plan.** Any future migration requires staging deployment, secret inventory, DB connectivity and migration checks, liveness/readiness probes, API contract tests, synthetic customer journey, rollback rehearsal, DNS TTL plan and explicit owner approval before production DNS or traffic changes.

## Provider evaluation gates

| Candidate | Appropriate role | Gate before selection |
|---|---|---|
| Vercel | Current Production deployment | Confirm current quota, runtime fit, logs and deployment limits |
| Cloudflare Workers Static Assets / Pages | Static docs or separately built static frontend | Confirm static build output; do not assume it runs FastAPI |
| Render or another Docker host | FastAPI, Broker, Worker or Verifier containers | Verify actual plan, cost, sleep behavior, region, health checks, secrets and persistent operations |
| OCI Always Free Compute (candidate only) | Isolated Staging Broker / future Worker host | Verify eligibility, free quotas, regional capacity, reclaim policy, ingress/egress and billing guardrails; never enable Pay As You Go without explicit approval |
| VPS | Full container control | Include OS patching, firewall, TLS, backups, monitoring, incident response and total monthly cost |
| Netlify | Static frontend/docs | Not a direct replacement for the Python API runtime |

## Conditional free-tier Broker candidate

OCI Always Free Compute remains a **candidate only**, not an approved or provisioned dependency. Promotional trial credits are distinct from Always Free entitlements. Before creating an instance, verify current eligibility, regional capacity, resource quotas, inactivity/reclamation conditions, public-IP/network costs and that the account remains on Free Tier. If a genuinely free resource is unavailable, stop rather than selecting a paid substitute.

For an isolated Staging Broker, prefer a private CA and dedicated ASGI TLS listener requiring client certificates. The Broker must validate certificate chain, expiry, revocation and pinned workload identity. Do not trust caller-supplied certificate headers. Keep the GitHub App private key exclusively inside the isolated Broker credential boundary.

Tailscale may be evaluated as private transport for authorized CI/workload clients, with short-lived enrollment where supported. Tailnet membership does not replace task, tenant or repository authorization, mTLS, or Broker policy. GitHub Actions runners are ephemeral CI clients, not a 24/7 Worker/Verifier runtime.

This candidate remains blocked until a zero-cost Staging host is available, the listener is hardened, and CI plus adversarial Staging E2E prove the full trust chain. No OCI instance, certificate, Tailscale node, DNS record, secret or service is created by this ADR.

## Cost and quota policy

- No paid upgrade, subscription, provider purchase, domain purchase or payment commitment without explicit owner approval.
- No deployment merely to test a provider; validate locally/CI first and use staging only when credentials and budget are approved.
- Prefer one controlled staging deployment over repeated preview deployments.
- Keep GitHub Actions as the primary code verification path; avoid redundant workflow runs.
- Measure actual compute, database, storage, email, logs, bandwidth and support costs before publishing customer plan prices.
- **Free-only guardrail:** do not switch OCI to Pay As You Go, attach paid resources or accept charges to overcome capacity/quota limits. Stop and report the blocker.

## Acceptance criteria for any future migration

- Identical OpenAPI contract and API behavior.
- PostgreSQL 16 integration tests pass, including RLS, transaction locks, idempotency and tenant isolation.
- Every customer/audit/usage table has reviewed RLS and effective role grants; production and staging branch protection and recovery posture are documented.
- Secrets are configured out-of-band and never appear in logs or build artifacts.
- Health and readiness distinguish process liveness from database readiness.
- Authenticated responses are not publicly cached.
- TLS, custom domain, CORS, trusted proxy/IP handling and rate limiting are tested at the new edge.
- Synthetic customer journey passes from onboarding through API-key lifecycle and usage display.
- Rollback to the prior origin is rehearsed and independently verified.
- Broker tests cover positive/negative mTLS, certificate rotation/revocation, task lease/claim replay, pinned commit/path enforcement and independent evidence capture on Staging.

## Explicit non-actions

This ADR does not upgrade Vercel; switch OCI to Pay As You Go; create or deploy Cloudflare, Netlify, Render or VPS services; change DNS/domains; move PostgreSQL/customer data; configure secrets; apply migrations; enable paid plans/payment; or claim a customer-ready release.
