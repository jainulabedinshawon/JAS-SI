# JAS-SI Protected GitHub Actions Provisioning — Design & Test Plan

Status: design gate for PR #20. This document is not an enabled provisioning workflow and does not authorize or perform API-key issuance.

## Security decision

Use a manually dispatched GitHub Actions workflow bound to a protected GitHub Environment. Do not add a public HTTP provisioning endpoint. Do not expose the provisioner database credential or API-key pepper to Vercel runtime.

The workflow must not be enabled for real provisioning until every implementation and test gate below passes. The earlier operator CLI used separate PostgreSQL transactions for key insertion and audit append. That path has now been replaced on this feature branch by an atomic audited issuance method; the implementation remains unverified until CI and staging tests pass.

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

## Implementation status on the feature branch

- Added `PostgresSecurityEventStore.append_in_transaction(connection, event)`; the existing `append()` now delegates to it while retaining its standalone transaction behavior.
- Added `PostgresApiKeyRegistry.issue_key_with_audit(...)`, which checks the required schema and audit-chain integrity, then inserts the API-key digest, idempotency row, audit event, and checkpoint through one PostgreSQL connection/transaction.
- Changed the compatibility `issue_key(...)` method to delegate to the atomic audited method, so callers cannot accidentally use the former unaudited issuance path.
- Added migration `003_atomic_api_key_provisioning.sql` with a unique provisioning-run ledger and conditional least-privilege grants for the known operator/runtime roles.
- Updated the operator CLI to use atomic audited issuance.
- Added PostgreSQL integration tests for successful commit, failure after key insert, idempotency insert, audit append, and checkpoint update; invalid checkpoint fail-closed; duplicate and concurrent run IDs; inactive tenants; role grants; and atomic revocation success/rollback.
- The initial OpenPGP artifact-delivery approach was superseded after review: a PGP app is unnecessary when the immediate goal is API staging validation rather than handing a reusable credential to a human.
- Added `tools/staging_api_smoke_test.py`: the short-lived key remains only in runner process memory, is sent only to a fixed HTTPS Preview deployment, tests valid/missing/invalid/wrong-scope authorization, and is revoked with an atomic audit event in a `finally` block. The key also has a 30-minute expiry as a backstop. The script prints only check outcomes and the non-secret key ID, never the raw token.
- Updated `.github/workflows/protected-staging-api-key-provisioning.yml`: manual dispatch only, main-branch guard, protected GitHub Environment, read-only job permissions, SHA-pinned setup actions, hash-locked dependencies, no artifact, no key output, and no PGP dependency.
- Updated static workflow-policy tests to enforce in-memory-only delivery and automatic revocation; included the smoke-test script in the CI compile step.
- PostgreSQL 16 CI run `42490998246` completed successfully on 2026-11-08: 72 tests passed, including real registry-backed API authentication checks (valid scoped key 200, missing/invalid key 401, wrong scope 403), key/ledger insert failure injection, checkpoint failure injection, invalid checkpoint fail-closed, duplicate/concurrent idempotency, role grants, atomic revocation rollback, OpenPGP encryption/decryption round-trip, and static workflow policy checks.
- Audit-chain verification was moved inside the key-issuance transaction after locking the singleton checkpoint row, closing the verification-to-issuance race window. All audit appenders serialize on that checkpoint row.
- Migration 003 is applied to the Neon staging branch and independently checked. The provisioner can read/insert the provisioning ledger and append/update audit metadata; runtime cannot read/insert the ledger or insert/update key lifecycle state, while retaining the required `last_used_at` column update.
- These changes remain on Draft PR #20. CI success and schema/permission checks do not yet constitute a real staging API-key issuance or Android encrypted-delivery acceptance test.

## Remaining implementation work

1. Complete an independent security review of the atomic issuance/revocation paths and the privileged workflow before merge.
2. Have an authorized repository owner create/configure the `jas-si-staging-provisioning` GitHub Environment with required reviewers, a `main`-only deployment branch rule, and environment-scoped `JAS_SI_PROVISIONER_DATABASE_URL` / `JAS_SI_API_KEY_PEPPER` secrets.
3. Export an OpenPGP public key from the operator's Android device; keep the private key only on that device. Validate the public key/fingerprint without sharing private material.
4. Obtain explicit approval to take Draft PR #20 out of Draft and merge it to `main`; do not merge automatically.
5. After merge and Environment verification, dispatch one controlled staging run, download the one-day encrypted artifact, decrypt on Android, and test the resulting scoped token against Preview.
6. Independently verify exactly one key row, one issuance event, a valid audit chain/checkpoint, then revoke the test key and verify the revocation event and rejection of the old token.
7. Delete the encrypted artifact when no longer needed and keep the Environment reviewer-gated. No customer-facing rollout is authorized by this staging test.
 
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
- The future workflow never emits the raw token to stdout/stderr, logs, job summary, step outputs, or unencrypted files. The trusted local CLI may display a one-time token only to the operator's private terminal; it must never be used as the workflow delivery mechanism.

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
- Atomic issuance and revocation and transaction-scoped audit verification pass the PostgreSQL 16 suite. The in-memory smoke-test workflow is implemented but has not been run: it is guarded to `main`, while PR #20 remains Draft and unmerged. GitHub Environment settings and secrets have been reported configured by the repository owner but cannot be independently read through the available GitHub integration. No staging or customer key has been issued.
- No API key is issued by this design document. No production branch, deployment, database, or customer credential is changed.
