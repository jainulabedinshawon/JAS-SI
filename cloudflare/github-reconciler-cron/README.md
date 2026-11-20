# JAS-SI GitHub Staging Worker

This Cloudflare Worker provides two narrowly scoped functions:

1. A stateless Cron scheduler for the bounded Staging reconciliation endpoint.
2. A GitHub webhook ingress proxy that validates the raw-body HMAC before forwarding the original signed delivery to the protected Vercel Preview.

It is not a persistent agent worker. Neon owns durable inbox state, claim leases, and retry timing. The reconciler fetches authoritative GitHub App state before applying repository bindings.

## Why the proxy exists

The JAS-SI Vercel project currently has Vercel Authentication / SSO Deployment Protection enabled for non-custom deployment URLs. GitHub webhook delivery cannot perform an interactive SSO login. The Worker therefore exposes a dedicated webhook endpoint and forwards only a valid GitHub-signed request to the exact configured Preview URL, adding the Vercel protection bypass header.

The bypass credential is stored only as a Cloudflare Worker secret. It must never be placed in a URL, repository, log, webhook payload, or chat. Do not disable Vercel Deployment Protection to make this integration work.

## Worker secrets

Configure these as Cloudflare Worker **secrets**, not plaintext variables:

- `JAS_SI_GITHUB_WEBHOOK_SECRET`: GitHub App webhook signing secret, at least 32 UTF-8 bytes. The exact same secret must be configured in Vercel Preview as `JAS_SI_GITHUB_WEBHOOK_SECRET`, because the application independently verifies the raw-body signature again.
- `JAS_SI_GITHUB_RECONCILER_TRIGGER_SECRET`: independently generated bearer secret, at least 32 UTF-8 bytes. The exact same value must be configured in Vercel Preview as `JAS_SI_GITHUB_RECONCILER_TRIGGER_SECRET`.
- `JAS_SI_VERCEL_PROTECTION_BYPASS_SECRET`: Vercel Deployment Protection bypass secret for automation. Generate it in the Vercel project protection settings and store it only in the Worker secret store. It is sent as the `x-vercel-protection-bypass` request header and never placed in a URL.

## Worker variables

- `JAS_SI_GITHUB_WEBHOOK_FORWARD_ENDPOINT`: exact Staging Preview URL ending in `/webhooks/github`.
- `JAS_SI_RECONCILER_ENDPOINT`: exact Staging Preview URL ending in `/internal/github/reconcile`.
- `JAS_SI_RECONCILER_ALLOWED_HOST`: exact hostname shared by both Preview endpoints, with no scheme, path, port, or trailing slash.

Both endpoints must use HTTPS, match the exact allowed host, and match the Vercel branch Preview hostname form `jas-si-git-<branch>-<team>.vercel.app`. The `main` Production alias, unique Production deployment URLs, non-JAS-SI hosts, redirects, query strings, and fragments are rejected.

## GitHub App webhook configuration

Set the GitHub App webhook URL to the deployed Worker URL:

`https://<your-worker-subdomain>.workers.dev/github/webhook`

Set the GitHub App webhook secret to the same value configured in the Worker and Vercel Preview as `JAS_SI_GITHUB_WEBHOOK_SECRET`. Enable only the installation events required by the JAS-SI integration. Do not point GitHub directly at the protected Vercel Preview.

The Worker:
- accepts only `POST /github/webhook`;
- rejects unexpected query strings and routes;
- limits the raw request body to 2 MB;
- validates `X-Hub-Signature-256` using HMAC-SHA256 before any forwarding;
- validates delivery and event headers;
- forwards the exact raw body and signed GitHub headers to the exact Preview endpoint;
- adds the Vercel bypass header only on the server-to-server request;
- never logs request bodies, signature material, bypass credentials, or provider payloads.

The Vercel application independently verifies the signature and persists the delivery using the dedicated webhook database login. The Worker returns HTTP 202 only after the Preview application accepts the delivery.

## Reconciliation scheduler

The Worker Cron Trigger calls `POST /internal/github/reconcile` with:
- `Authorization: Bearer <JAS_SI_GITHUB_RECONCILER_TRIGGER_SECRET>`
- `x-vercel-protection-bypass: <JAS_SI_VERCEL_PROTECTION_BYPASS_SECRET>`

The API processes at most one authoritative GitHub Installation snapshot per invocation: one webhook delivery if any are queued, otherwise one pending OAuth claim. PostgreSQL claim leases protect overlapping invocations. Logs contain aggregate counters only.

A once-per-minute schedule produces 1,440 invocations/day. Before enabling it, verify the Cloudflare account's current Free-plan request, CPU, Cron Trigger, and billing limits. This stateless Worker is not a replacement for a persistent task worker.

## Staging setup — not deployed

1. Separately approve and create the Staging Preview deployment with GitHub OAuth, webhook intake, and reconciliation activation disabled.
2. Verify the deployed commit, exact Preview hostname, API readiness, audit integrity, base rate-limit readiness, and exact-branch environment variable names. Do not decrypt or print environment values.
3. Generate and provision the Vercel Deployment Protection automation bypass secret. Store it in the Worker secret store only. Do not add it to the webhook URL or source code.
4. Provision the GitHub App OAuth configuration, webhook signing secret, and reconciliation trigger secret only under separate explicit credential approval. Register the exact OAuth callback URI in the GitHub App settings.
5. Deploy the Worker only after its exact endpoints and required secrets have been reviewed and separately approved. Configure GitHub App webhook URL as the Worker URL above.
6. Add the Cron Trigger only after a valid signed webhook can be accepted and the protected Preview reconciliation endpoint passes authentication.
7. Test invalid signatures (401), missing configuration (503), oversized payloads (413), Vercel protection rejection, and successful delivery. Confirm Neon inbox/claim/audit evidence and Worker aggregate counters using a disposable tenant and repository.

Do not use Production secrets, Production database credentials, or Production routes for this Staging Worker. Do not deploy the Worker, configure GitHub webhook delivery, or enable the schedule until the infrastructure plan and required credentials are reviewed and separately approved.

## Local tests

```sh
node --test cloudflare/github-reconciler-cron/worker.test.mjs
```
