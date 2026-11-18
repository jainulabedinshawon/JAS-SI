# GitHub App webhook ingress

The API exposes `POST /webhooks/github` for GitHub App webhook deliveries.

## Required runtime configuration

- `JAS_SI_GITHUB_WEBHOOK_SECRET`: the exact webhook secret configured in the GitHub App settings. It must contain at least 32 UTF-8 bytes.
- `JAS_SI_GITHUB_WEBHOOK_DATABASE_URL`: a dedicated database login that is permitted to `SET ROLE jas_si_runtime` and execute the inbox routines from the durable-inbox migration.

Do not use the migration-owner, database-superuser, Worker, or Verifier DSN for this endpoint. Do not put the webhook secret in source control, logs, issue comments, or chat.

## Request handling

1. Bound the streamed request body to 2 MB.
2. Verify `X-Hub-Signature-256` against the exact raw body using HMAC-SHA256 and constant-time comparison.
3. Validate `X-GitHub-Delivery`, `X-GitHub-Event`, action, and positive Installation ID.
4. Persist the raw-body SHA-256 digest and event payload through the database-owned receipt routine.
5. Return HTTP 202 only after durable receipt. Duplicate delivery IDs are idempotently acknowledged; a delivery ID reused with different content is rejected by the database routine.

## Security boundary

Webhook payload fields are untrusted signals, including account, sender, repository list, and any tenant-like fields. The ingress does not create a tenant binding, mark an Installation active, issue tokens, or infer repository allowlists. A separate callback ownership proof and authoritative GitHub API reconciliation are required before activation.

The webhook receiver does not process lifecycle events in the request path. It only persists them for a later worker/reconciler. If persistence is unavailable, it fails closed with HTTP 503 so GitHub can redeliver.
