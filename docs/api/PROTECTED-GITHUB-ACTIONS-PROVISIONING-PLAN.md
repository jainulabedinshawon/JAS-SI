# JAS-SI Protected GitHub Actions Provisioning — Design & Test Plan

Status: design gate for PR #20. This document is not an enabled provisioning workflow and does not authorize or perform API-key issuance.

## Security decision

Use a manually dispatched GitHub Actions workflow bound to a protected GitHub Environment. Do not add a public HTTP provisioning endpoint. Do not expose the provisioner database credential or API-key pepper to Vercel runtime.

The workflow must not be enabled for real provisioning until every implementation and test gate below passes. In particular, the existing operator CLI is not sufficient: API-key insertion and audit-chain append currently use separate PostgreSQL transactions. A compensating revoke after audit failure is not atomic and does not satisfy this design.

## Threat model and controls

- Untrusted pull-request code must never receive provisioning secrets. The provisioning job must have no `pull_request`, `pull_request_target`, `push`, or scheduled trigger.
- The workflow must be manually dispatched from the protected default branch only, use a dedicated GitHub Environment (for example `jas-si-staging-provisioning`), and require an independent human reviewer before the job receives environment secrets.
- Job permissions must be explicitly minimal: `contents: read`; no repository write, pull-request write, deployment write, or OIDC permissions.
- Use a concurrency group with `cancel-in-progress: false` to prevent overlapping issuance attempts. Add a database-enforced idempotency key based on the GitHub workflow run ID so a rerun cannot create a second key.
- Secrets must be environment-scoped: `JAS_SI_PROVISIONER_DATABASE_URL` and `JAS_SI_API_KEY_PEPPER`. Never put the provisioner DSN in Vercel. Do not print, mask-and-print, pass as command-line arguments, or write either secret to an artifact.
- The workflow must pin every third-party action to a reviewed full commit SHA. Python dependencies must install from the repository's hash-locked requirements file. No unpinned `pip install`, `npx`, curl-pipe-shell, or mutable action tags in the privileged job.
- The job must check out only the trusted default-branch commit and verify the expected repository, ref, workflow identity, tenant ID allowlist, key scope allowlist, key name bounds, and short expiry bounds before opening a database connection.
- Key issuance, audit event insertion, audit checkpoint update, and the workflow-run idempotency record must commit in one PostgreSQL transaction. Any failure must roll back all of them. Never rely on a follow-up revoke as a substitute for rollback.
- Raw token delivery must be end-to-end encrypted to an operator-held public key. The proposed first implementation uses an OpenPGP public-key input (public material only), encrypts the one-time token on the ephemeral runner, and uploads ciphertext only with a one-day artifact retention. The private key stays on the operator's device. If this delivery path cannot be tested on the operator's Android device, do not issue a token and choose another approved secure delivery channel.
- Never place the raw token in Actions logs, step outputs, job summaries, cache, workflow outputs, issue/PR comments, or unencrypted artifacts. Disable shell tracing. Do not enable debug logging. Remove temporary plaintext files in an unconditional cleanup step; runner destruction remains the final cleanup boundary.
- The artifact must contain only ciphertext plus non-sensitive metadata (key ID, expiry, scopes, run ID). Artifact access is still repository-reader access; encryption is mandatory.
- A workflow run must fail closed if audit integrity verification fails before issuance, if the tenant is not active, if the requested scopes exceed the allowlist, or if any secret/configuration is missing.

## Required implementation work

1. Refactor PostgreSQL audit append into a transaction-aware method that accepts an existing psycopg connection. Keep the existing standalone `append()` API behavior by opening a connection and delegating to that method.
2. Add a single operator provisioning service method that:
   - validates tenant, operator identity, scopes, expiry, and idempotency key;
   - opens one PostgreSQL connection/transaction;
   - locks and validates the active tenant;
   - inserts the API-key digest and metadata;
   - appends the sanitized `api_key_issued` event using the same connection and updates the hash-chain checkpoint;
   - inserts a unique provisioning-run/idempotency record;
   - commits only after all writes succeed; and
   - returns the raw token only in process memory after successful commit.
3. Add a migration for the unique provisioning-run/idempotency table. No raw token, token fragment, digest, pepper, or DSN may be stored in that table.
4. Update the operator CLI to call the atomic service. Remove the separate insert-then-audit/revoke flow.
5. Add a protected workflow file with manual dispatch only, protected Environment, strict inputs, minimal permissions, immutable action pins, no untrusted checkout, concurrency protection, encrypted delivery, one-day artifact retention, and unconditional plaintext cleanup.
6. Add a runbook for creating the GitHub Environment, required reviewers, branch restrictions, environment-scoped secrets, and operator public-key enrollment. Do not document or request pasting secrets into chat.
7. Keep the workflow unavailable for real issuance until the Environment protection and secret configuration are independently checked in GitHub UI.

## Test plan and release gates

### Unit tests
- Invalid/missing/short pepper fails before database access.
- Unknown tenant, suspended tenant, invalid scope, malformed expiry, and out-of-range expiry fail closed.
- Audit event serialization failure rolls back the key insert and idempotency record.
- Audit checkpoint update failure rolls back the event, key insert, and idempotency record.
- Key insert failure leaves no audit event or idempotency record.
- Duplicate workflow run ID is rejected and creates no second key.
- Concurrent attempts for the same idempotency key yield exactly one committed key and one audit event.
- Audit event contains tenant ID, key ID, operator identity, scopes, expiry, and run ID; it contains no token, secret, digest, DSN, or pepper.
- The CLI and workflow never emit the raw token to stdout/stderr, logs, job summary, step outputs, or unencrypted files.

### PostgreSQL integration tests (PostgreSQL 16)
- Successful provisioning creates exactly one active key, exactly one audit event, exactly one idempotency record, and a matching valid checkpoint.
- Force failures after each SQL write and prove that all rows/checkpoint roll back.
- Concurrent issuance and audit append preserve chain order and integrity.
- Duplicate run ID is rejected after a successful attempt.
- A fresh workflow run can issue a separate key only after explicit operator approval.
- Existing audit chain verifies before and after provisioning; all pre-existing audit records remain unchanged.
- Runtime role cannot insert keys or provisioning-run records; provisioner role can perform only the documented lifecycle writes and cannot delete tenant/key/audit history.

### Workflow/security tests
- Static YAML/policy test confirms manual-only trigger and rejects PR/push/schedule triggers.
- Confirm `permissions: contents: read` and absence of write permissions/OIDC.
- Confirm protected Environment is referenced and concurrency does not cancel an active provisioning run.
- Confirm all actions are pinned to full commit SHAs and dependencies are hash-locked.
- Confirm no shell tracing, debug flags, raw token echo, artifact upload of plaintext, or secret in command arguments.
- Confirm public-key encryption is mandatory and rejects missing/invalid recipient keys before database connection.
- Confirm artifact contains ciphertext only, is private to repository access, and retention is one day.
- Confirm cleanup runs on success and failure.
- Verify the workflow is not runnable for a PR branch and that a reviewer must approve the protected Environment before secrets become available.

### End-to-end staging acceptance
1. Verify the existing staging audit chain and checkpoint before the test.
2. Configure the dedicated GitHub Environment and required reviewers in the GitHub UI.
3. Store only the staging provisioner DSN and matching staging pepper as Environment secrets. Do not copy either into repository variables or Vercel.
4. Import the operator public key; retain the private key only on the operator's Android device.
5. Dispatch one run from the protected default branch and approve it as a separate reviewer.
6. Download the encrypted artifact, decrypt locally on the Android device, and validate the token against the Preview API over HTTPS.
7. Verify a valid scoped request succeeds; missing, malformed, wrong, expired, revoked, and wrong-scope credentials return the expected 401/403 behavior.
8. Independently query Neon metadata and verify exactly one key row, one issuance audit event, a valid audit chain/checkpoint, and no token/digest in audit metadata.
9. Revoke the test key and verify the old token fails. Confirm the revocation event is appended and the chain remains valid.
10. Remove the temporary public-key input and encrypted artifact when no longer needed; review Environment access, secret scope, workflow permissions, run logs, and artifact retention. Keep the provisioning workflow disabled or reviewer-gated until an explicit operational decision.

## Current blockers / non-claims

- GitHub connector access available to this implementation can read repository/workflow data and commit files, but cannot manage GitHub Environment secrets or dispatch workflows. Those actions require an authorized operator in GitHub UI.
- No end-to-end test has been run from the operator's Android device. Encrypted artifact delivery is therefore a design proposal, not yet validated.
- The existing CLI's issue and audit writes are separate transactions. No production-grade atomic issuance is currently available.
- No API key is issued by this design document. No production branch, deployment, database, or customer credential is changed.
