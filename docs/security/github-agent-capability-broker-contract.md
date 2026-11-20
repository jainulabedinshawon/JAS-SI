# GitHub Agent Capability Broker Contract

Status: Proposed contract; not implemented or deployed.
Scope: Staging-first, private-repository read capability for the task Worker and independent Verifier.
Security invariant: a caller's task ID, tenant ID, repository, worker UUID, or verifier claim token is never sufficient proof of authority.

## Current boundary

- The Render GitHub Installation Reconciler is the sole holder of GitHub App signing material and the sole component that reconciles authoritative Installation snapshots.
- The Worker and Verifier supervisors reject GitHub App signing configuration and run public-repository-only until an authenticated capability path exists.
- Worker task lifecycle and Verifier claim/finalization currently use their dedicated PostgreSQL capability logins directly. Their caller-supplied worker UUID and verifier claim token are not cryptographic workload identities.
- The current installation-binding resolver checks tenant/repository binding, but does not bind token issuance to a live Worker lease or Verifier claim.

## Required trust model

1. Authenticate each workload at the broker boundary using mutually authenticated TLS or an equivalently strong workload identity mechanism. Map the authenticated certificate/service identity to a server-side Worker or Verifier principal. Never accept a caller-supplied UUID as identity.
2. Keep the GitHub App private key confined to the isolated Reconciler/token-issuer trust boundary. Never add it to the shared Render Environment Group consumed by Worker and Verifier. The actual group variable inventory must be inspected before any deployment.
3. Do not grant Worker, Verifier, or Task Owner broad table access or Reconciler login/capability membership. Broker database access must use a dedicated least-privilege capability with narrowly scoped SECURITY DEFINER routines and pinned search_path.
4. Derive tenant, repository, task type, and expected commit/paths from persisted task state. Treat request payload values as assertions to compare, never as authority.
5. Fail closed on missing/invalid workload identity, stale lease/claim, expiry, task cancellation, tenant suspension, installation revocation, repository allowlist mismatch, database/broker outage, or any inconsistent state.

## Worker authorization contract

A Worker credential request must carry task_id and lease_fence, but those values are only lookup/fencing inputs. The broker must:
- authenticate the Worker workload identity;
- verify that the authenticated Worker owns the current persisted lease;
- verify task status is running, lease is unexpired, and lease_fence is current;
- derive tenant and repository from the persisted task;
- verify active tenant, verified installation, and exact repository allowlist membership;
- issue a short-lived token scoped to exactly that repository and read-only permissions;
- bind issuance to the authenticated Worker principal and current lease fence.

Renew, report, fail, and cancellation acknowledgement must receive the same authenticated workload check. A stale or replaced Worker must not report or continue obtaining credentials.

## Verifier authorization contract

A Verifier request must carry task_id and verifier_claim_token as fencing inputs. The broker must:
- authenticate the Verifier workload identity independently of the Worker;
- verify the persisted task is awaiting_verification and the claim is current and unexpired;
- derive tenant/repository/commit/paths from persisted task state;
- verify active tenant, installation, and exact repository allowlist;
- issue a short-lived read-only token bound to that Verifier principal and claim;
- permit finalization only through the matching live claim and independently collected evidence.

Worker and Verifier identities must be distinct. A Worker credential must never authorize a Verifier request, or vice versa.

## Token and database constraints

- Token scope: exactly one allowlisted repository; read-only permissions only; expiry no longer than the existing bounded GitHub installation-token TTL.
- No token, private key, DSN, bearer credential, or certificate private material in logs, task results, exception text, or evidence payloads.
- Broker must not expose arbitrary GitHub API proxying, arbitrary installation IDs, repository enumeration, or caller-selected permission scopes.
- Database routines must use persisted task state and authenticated principal inputs; reject client-provided tenant/repository mismatches.
- Do not solve this by granting the token issuer direct table access or broad Worker/Verifier role membership.
- Preserve the Reconciler's existing narrow reconciliation authority; do not reuse its login/DSN as the broker's database identity.

## Mandatory negative tests

- unauthenticated client, invalid certificate, wrong service identity, and Worker/Verifier identity substitution;
- cross-tenant task, altered tenant/repository/commit/path assertion, arbitrary installation ID, and repository not on allowlist;
- unknown task, wrong task type/status, cancelled task, expired lease, stale lease fence, wrong lease owner, and replaced Worker;
- forged, stale, expired, released, or wrong-task verifier claim; replaced Verifier;
- suspended tenant, removed repository, suspended/deleted installation, and revoked binding;
- token repository scope mismatch, write permission, extra permission, excessive TTL, and malformed token response;
- broker/database unavailable, timeout, replayed request, and secret leakage through logs/errors;
- proof that Worker/Verifier processes cannot read signing material and that public-only behavior remains fail-closed.

## Rollout gates

1. Implement broker authentication and narrow database routines with unit/contract tests; do not deploy.
2. Run clean migration replay on PostgreSQL 16 and 18 and exact-HEAD security/unit CI.
3. Perform a separate Staging-only database and credential review/approval before applying any new migration or provisioning workload identities.
4. Deploy only to a separately approved, non-production Staging environment; verify the actual Render Environment Group contains no App private key.
5. Run disposable-tenant end-to-end negative and positive tests with independent evidence.
6. Production protection, migrations, credentials, deployment, and rollout require separate explicit approval.

This document is a design contract, not evidence that a broker, mTLS identity, database routines, service, or live private-repository workflow exists.
