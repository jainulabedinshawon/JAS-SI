# JAS-SI Hosting Strategy — Quota-Aware, No-Cutover Decision

**Status:** Proposed architecture decision; no infrastructure change authorized or performed  
**Baseline:** `main` at `b4d42eea898e5829b5c6d540841871da90e8cb91`  
**Decision owner:** JAS-SI project owner

## Context verified from the repository

- The repository's production entrypoint is `main.py`, which imports the FastAPI application from `src/jas_si_agent/api.py`.
- The root `Dockerfile` builds a Python 3.10 container, installs hash-locked dependencies, runs as an unprivileged user, and starts Uvicorn on port 8000.
- The root contains Python packaging and PHP SDK material; it does not contain a separate conventional React/Next.js frontend build manifest at this baseline.
- Therefore, treating the current application as a static-only site and moving it directly to Cloudflare Pages would not host the FastAPI runtime.
- The customer portal and identity work in PR #36 is not part of `main`; its routes and dependencies must not be assumed to exist in the current production application.

## Decision

Adopt a **quota-aware, deployment-neutral hybrid strategy**, but do not migrate or upgrade hosting yet.

1. **Preserve current Vercel production and domain configuration.** Avoid preview builds and redeployments while the account daily deployment limit is exhausted. Do not change DNS.
2. **Keep the Python FastAPI API as a container workload.** The existing Dockerfile is the portable deployment artifact. Candidate hosts may include a Docker-capable managed container service or a small VPS, subject to current pricing, regional latency, persistent storage, secrets, health checks, backups, and operational burden.
3. **Use Cloudflare only where its role is technically appropriate.** Cloudflare DNS/CDN/WAF can sit in front of a separately hosted origin if configured and tested. Cloudflare Workers Static Assets or Pages may serve a future genuinely static frontend/documentation bundle. They are not a drop-in runtime for this Python FastAPI container.
4. **Do not select a replacement provider based on headline free bandwidth alone.** Verify build limits, sleeping/cold starts, CPU/RAM, outbound transfer, database connection limits, logs, backups, support, and production terms.
5. **Keep PostgreSQL external and authoritative.** Do not move customer identity, usage, idempotency, payment or audit records into edge KV or static hosting. Any database connectivity proxy must preserve transaction, locking, TLS and connection-pool semantics.
6. **Separate public static assets from authenticated API traffic.** Never cache customer sessions, API-key responses, usage, billing, authorization or verification endpoints at a shared CDN. Use explicit no-store/private cache policies.
7. **Retain a reversible cutover plan.** A future migration requires a staging deployment, secret inventory, database connectivity and migration checks, health/readiness probes, API contract tests, synthetic customer journey, rollback rehearsal, DNS TTL plan, and owner approval before production DNS or traffic changes.

## Provider evaluation gates

| Candidate | Appropriate role | Gate before selection |
|---|---|---|
| Vercel | Existing API deployment while quota permits | Account quota reset/usage, deployment limits and runtime fit |
| Cloudflare Workers Static Assets / Pages | Static docs or a separately built static frontend | Confirm static build output; do not assume it runs FastAPI |
| Docker-capable managed host (e.g. Render) | FastAPI container | Current plan limits, sleeping behavior, region, persistent logs, health checks, secrets and cost |
| VPS (e.g. Hetzner / DigitalOcean) | Full container control | OS patching, firewall, TLS, backups, monitoring, incident response and total monthly cost |
| Netlify | Static frontend/docs | Not a direct replacement for the current Python API runtime |

No provider is selected by this ADR. Current prices and plan limits must be checked immediately before procurement or migration.

## Cost and quota policy

- No paid upgrade, subscription, provider purchase, domain purchase, or payment commitment without explicit owner approval.
- No deployment merely to test a provider; first validate locally/CI and use a non-production staging environment only when credentials and budget are approved.
- Prefer one controlled staging deployment over repeated preview deployments.
- Keep GitHub Actions as the primary code verification path; do not trigger redundant workflows.
- Measure actual monthly API compute, database, storage, email, logs, bandwidth and support costs before publishing customer plan prices.

## Acceptance criteria for any future migration

- Identical OpenAPI contract and API behavior.
- PostgreSQL 16 integration tests pass, including row-level security, transaction locks, idempotency and tenant isolation.
- Secrets are configured out-of-band and never appear in logs or build artifacts.
- Health and readiness checks distinguish process liveness from database readiness.
- Authenticated responses are not publicly cached.
- TLS, custom domain, CORS, trusted proxy/IP handling and rate limiting are tested at the new edge.
- Synthetic customer journey passes from signup through API-key lifecycle and usage display.
- Rollback to the prior origin is rehearsed and independently verified.

## Explicit non-actions

This ADR does not:
- upgrade Vercel;
- create or deploy a Cloudflare, Netlify, Render or VPS service;
- change DNS or domains;
- move PostgreSQL or customer data;
- configure secrets;
- apply migrations;
- enable customer signup, billing or payment;
- claim a migration or customer-ready release is complete.
