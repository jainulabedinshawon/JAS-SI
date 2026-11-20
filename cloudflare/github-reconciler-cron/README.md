# JAS-SI GitHub Reconciler Scheduler

This Cloudflare Worker is a **stateless scheduler**, not a persistent agent
worker. It wakes the bounded JAS-SI API reconciliation endpoint; Neon owns
claim leases and retry timing, and the reconciler fetches authoritative GitHub
App state before applying repository bindings.

## Free-plan fit

The Worker uses only one scheduled invocation and one outbound HTTPS request.
Cloudflare's current Workers Free limits include 100,000 requests/day, 10 ms CPU
per invocation, and up to five Cron Triggers per account. One invocation per
minute is 1,440 scheduled executions/day. The request spends most of its time
waiting on network I/O, which does not count as Worker CPU time. Verify the
account's current limits before enabling the schedule.

## Runtime contract

- Fixed endpoint: `https://jas-si.vercel.app/internal/github/reconcile`
- Method: `POST`
- Authentication: `Authorization: Bearer <JAS_SI_GITHUB_RECONCILER_TRIGGER_SECRET>`
- Request body: none
- Timeout: 20 seconds
- The API processes at most one authoritative GitHub Installation snapshot
  per invocation: one webhook delivery if any are queued, otherwise one pending
  OAuth claim. This bounds Vercel request time; PostgreSQL leases protect
  overlapping scheduler invocations.
- Logs contain aggregate counters only; response bodies, secrets, DSNs, and
  provider payloads are never logged.

## Staging setup — not yet deployed

1. Create a Worker named `jas-si-github-reconciler-staging` in the existing
   Cloudflare account and deploy the contents of `worker.mjs` as an ES module.
2. Add the Worker secret `JAS_SI_GITHUB_RECONCILER_TRIGGER_SECRET`.
3. Configure a Cron Trigger of `* * * * *` (once per minute).
4. Add the same independently generated secret to the Vercel **Preview** or
   dedicated Staging environment as `JAS_SI_GITHUB_RECONCILER_TRIGGER_SECRET`.
5. Configure the Vercel Staging environment with the GitHub App ID/private key
   and the dedicated reconciler database URL. The DB login must be deliberately
   enabled through the approved credential workflow before this URL can work.
6. Test the endpoint with invalid credentials (401), missing configuration
   (503), and a valid scheduler invocation. Confirm Neon claim/audit evidence
   and the Worker counters before considering the Staging lifecycle verified.

Do not use Production secrets, Production database credentials, or Production
routes for this Staging Worker. Do not deploy or enable the schedule until the
Staging secrets and database login are ready and the infrastructure plan is
reviewed and separately approved.

## Local test

```sh
node --test cloudflare/github-reconciler-cron/worker.test.mjs
```
