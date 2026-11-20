# JAS-SI GitHub Reconciler Scheduler

This Cloudflare Worker is a **stateless scheduler**, not a persistent agent
worker. It wakes the bounded JAS-SI API reconciliation endpoint; Neon owns
claim leases and retry timing, and the reconciler fetches authoritative GitHub
App state before applying repository bindings.

## Free-plan fit

The Worker uses one scheduled invocation and one outbound HTTPS request.
Cloudflare's current Workers Free limits include 100,000 requests/day, 10 ms CPU
per invocation, and up to five Cron Triggers per account. One invocation per
minute is 1,440 scheduled executions/day. The request spends most of its time
waiting on network I/O, which does not count as Worker CPU time. Verify the
account's current limits before enabling the schedule.

## Runtime contract

- Endpoint is supplied through `JAS_SI_RECONCILER_ENDPOINT`; there is no
  Production default.
- The endpoint must be HTTPS, use a JAS-SI Vercel Preview hostname matching
  `jas-si-*.vercel.app`, and end exactly in
  `/internal/github/reconcile`. The Production host
  `jas-si.vercel.app`, non-JAS-SI hosts, query strings, and redirects are not
  accepted by validation.
- Method: `POST`
- Authentication: `Authorization: Bearer <JAS_SI_GITHUB_RECONCILER_TRIGGER_SECRET>`
- Request body: none
- Timeout: 20 seconds
- The API processes at most one authoritative GitHub Installation snapshot
  per invocation: one webhook delivery if any are queued, otherwise one pending
  OAuth claim. PostgreSQL claim leases protect overlapping invocations.
- Logs contain aggregate counters only; response bodies, secrets, DSNs, and
  provider payloads are never logged.

## Staging setup — not yet deployed

1. Identify the exact Vercel Preview URL for the JAS-SI Staging build and append
   `/internal/github/reconcile`. Verify its hostname matches the allowlist
   before setting the Worker variable.
2. Create a Worker named `jas-si-github-reconciler-staging` in the existing
   Cloudflare account and deploy `worker.mjs` as an ES module.
3. Add the Worker secret `JAS_SI_GITHUB_RECONCILER_TRIGGER_SECRET`.
4. Add the plain-text Worker variable `JAS_SI_RECONCILER_ENDPOINT` with the
   exact verified Preview URL. Do not use `https://jas-si.vercel.app`.
5. Configure a Cron Trigger of `* * * * *` (once per minute), only after the
   endpoint and secret are ready.
6. Add the same independently generated trigger secret to the Vercel Preview
   environment. Configure the Staging GitHub App ID/private key and dedicated
   reconciler database URL. The database login must be deliberately enabled
   through the approved credential workflow before this URL can work.
7. Test invalid credentials (401), missing configuration (503), and a valid
   scheduler invocation. Confirm Neon claim/audit evidence and Worker counters
   before considering the Staging lifecycle verified.

Do not use Production secrets, Production database credentials, or Production
routes for this Staging Worker. Do not deploy or enable the schedule until the
Staging secrets and database login are ready and the infrastructure plan is
reviewed and separately approved.

## Local test

```sh
node --test cloudflare/github-reconciler-cron/worker.test.mjs
```
