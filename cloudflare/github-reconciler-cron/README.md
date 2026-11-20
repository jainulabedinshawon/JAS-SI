# JAS-SI GitHub Staging Webhook Worker

This Cloudflare Worker has one responsibility: authenticate GitHub webhook deliveries and forward the original signed request to the protected JAS-SI Staging Vercel Preview.

**It does not run reconciliation or scheduled jobs.** The only authoritative GitHub Installation reconciler is the isolated Render worker:

`python -m jas_si_agent.github_installation_reconciler`

The Render worker alone receives the GitHub App private key and dedicated reconciler database DSN. The public Vercel API receives neither credential and exposes no reconciliation trigger endpoint. This separation keeps App signing authority outside the public request process and avoids duplicate schedulers.

## Why the webhook proxy exists

Vercel Deployment Protection may require interactive authentication for non-custom deployment URLs. GitHub webhook delivery cannot complete an interactive login. This Worker accepts GitHub-signed requests and forwards them to the exact configured Preview URL, adding the Vercel protection bypass header server-to-server.

The bypass credential is stored only as a Cloudflare Worker secret. Never place it in a URL, repository, log, webhook payload, or chat. Do not disable Vercel Deployment Protection.

## Worker secrets

Configure these as Cloudflare Worker **secrets**, not plaintext variables:

- `JAS_SI_GITHUB_WEBHOOK_SECRET`: GitHub App webhook signing secret, at least 32 UTF-8 bytes. The same secret is configured in Vercel Preview for independent signature verification.
- `JAS_SI_VERCEL_PROTECTION_BYPASS_SECRET`: Vercel Deployment Protection bypass secret. Store only in the Worker secret store.

## Worker variables

- `JAS_SI_GITHUB_WEBHOOK_FORWARD_ENDPOINT`: exact Staging Preview URL ending in `/webhooks/github`.
- `JAS_SI_GITHUB_WEBHOOK_ALLOWED_HOST`: exact hostname of that Preview URL, without scheme, path, port, or trailing slash.

The endpoint must use HTTPS and match the exact allowed host and Vercel branch Preview hostname form `jas-si-git-<branch>-<team>.vercel.app`. Production aliases, unique deployment URLs, non-JAS-SI hosts, redirects, query strings, and fragments are rejected.

## GitHub App webhook configuration

Set the GitHub App webhook URL to the deployed Worker URL:

`https://<your-worker-subdomain>.workers.dev/github/webhook`

Set the GitHub App webhook secret to the same value configured in the Worker and Vercel Preview as `JAS_SI_GITHUB_WEBHOOK_SECRET`. Enable only the installation events required by JAS-SI. Do not point GitHub directly at the protected Vercel Preview.

The Worker:
- accepts only `POST /github/webhook`;
- rejects unexpected query strings and routes;
- limits the raw request body to 2 MB;
- validates `X-Hub-Signature-256` using HMAC-SHA256 before forwarding;
- validates delivery and event headers;
- forwards the exact raw body and signed GitHub headers to the exact Preview endpoint;
- adds the Vercel bypass header only on the server-to-server request;
- never logs request bodies, signature material, bypass credentials, or provider payloads.

The Vercel application independently verifies the signature and persists the delivery using the dedicated webhook database login. It returns HTTP 202 only after the delivery is durably accepted.

## Isolated reconciliation runtime

Deploy exactly one persistent Render worker from `render.yaml`:

- Command: `python -m jas_si_agent.github_installation_reconciler`
- Credentials available only to this Render worker:
  - `JAS_SI_GITHUB_APP_ID`
  - `JAS_SI_GITHUB_APP_PRIVATE_KEY_B64`
  - `JAS_SI_GITHUB_RECONCILER_DATABASE_URL`
  - optional `JAS_SI_GITHUB_RECONCILER_POLL_SECONDS` (default 15; range 1–300)

The reconciler's private key, DSN, and polling configuration are parsed by a dedicated `GitHubReconcilerSettings` class in that process. They are deliberately absent from the public API `Settings` object. The Render worker uses the dedicated login and explicitly switches to the constrained `jas_si_github_reconciler` capability.

## Staging setup — not deployed

1. Separately approve and create the Staging Preview deployment with OAuth and webhook intake disabled.
2. Verify the deployed commit, exact Preview hostname, API readiness, audit integrity, rate-limit readiness, and exact-branch environment variable names. Do not decrypt or print environment values.
3. Provision the GitHub App OAuth configuration and webhook signing secret only under separate explicit credential approval. Register the exact OAuth callback URI.
4. Provision the Render reconciler's App ID, private key, and dedicated database DSN in the Render Environment Group/service secret store; never copy them into Vercel.
5. Deploy the Cloudflare webhook proxy only after its exact endpoint and required secrets have been reviewed and separately approved. Configure the GitHub App webhook URL as the Worker URL above.
6. Test invalid signatures (401), missing configuration (503), oversized payloads (413), Vercel protection rejection, and successful durable delivery using a disposable tenant/repository.
7. Verify the Render reconciler consumes the inbox, fetches authoritative GitHub App state, and records the exact repository allowlist plus suspension/deletion revocation evidence.

Do not use Production secrets, Production database credentials, or Production routes for Staging. Do not deploy the Worker, configure GitHub webhook delivery, or start the Render worker until the infrastructure plan and required credentials are reviewed and separately approved.

## Local tests

```sh
node --test cloudflare/github-reconciler-cron/worker.test.mjs
```
