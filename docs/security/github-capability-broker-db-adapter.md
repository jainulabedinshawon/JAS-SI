# GitHub Capability Broker — database adapter slice

## Scope

This Main-based integration slice adds the PostgreSQL task-scoped capability resolver adapter and isolated unit tests. It deliberately does not expose an HTTP endpoint, mint GitHub credentials, start a service, or enable Worker/Verifier access.

## Authorization contract

The adapter accepts only the immutable `WorkloadIdentity` value produced by the existing TLS certificate pin registry. Python values are not cryptographic capabilities by themselves: the caller must be the server-side `require_authenticated_workload` dependency, and must never construct or deserialize identity from request-controlled data. Callers must not construct this from request headers, JSON, or caller-supplied principal/role fields. The HTTP/mTLS layer is not part of this PR; therefore this adapter is not yet exposed to a network service.

- Require PostgreSQL TLS hostname verification (`sslmode=verify-full`).
- Accept only the dedicated `jas_si_agent_broker_login` database session identity.
- Execute `SET ROLE jas_si_agent_capability_broker` only after checking that login identity.
- Delegate task, tenant, installation, repository binding, lease-fence, and verifier-claim authorization to the already-present SECURITY DEFINER database resolver.
- Fail closed and redact driver/database error details.
- Validate persisted commit and repository path metadata before returning it, including rejection of ASCII control characters U+0000–U+001F and U+007F.

## Current branch and CI evidence — 2026-11-27

- Main SHA observed: `3922dc5a3f82b82da6d89e85b721fec9baa6a4ac`.
- The Broker adapter source/tests were reviewed at implementation commit `f0226532f0693481aa9b3dc2f1c26aee96ae7da4`. This evidence correction was committed as `1eafc32fb27d4f1d3091ce16966d7568eb4169da`.
- At the evidence-correction commit, comparison against current Main was 21 commits ahead, 0 behind; merge base equaled Main.
- Exact-head CI for evidence-correction commit `1eafc32fb27d4f1d3091ce16966d7568eb4169da`: 11 returned check-run records across two push attempts; all 11 completed successfully. Eight distinct check names passed: Security Verification (Python 3.10), JSONL Recovery, Vercel Runtime Compatibility (Python 3.12), Docker Container Verification, Dependency Lock Verification, Broker Adapter Unit Tests, Agent Unit Tests (Python 3.10), and Wheel Build and Install.
- Latest full security run `46032264550` ran 1,121 discovered tests; 109 were skipped and the job passed. Skipped tests are not counted as executed.
- Latest Broker adapter unit-test run `46032264643` passed. Python 3.12 compatibility run `46032264648` also passed.
- The optional PostgreSQL migration/adapter integration test is gated by `JAS_SI_BROKER_MIGRATION_TEST_DSN`. The Broker adapter CI job does not configure that DSN; therefore these checks do not prove a live Broker DB connection or execute that optional integration test.
- The check evidence above is attached to the exact commit shown; a subsequent documentation-only commit must be independently checked before being described as exact-head CI verified.

## Evidence correction history

Earlier versions cited head `328a0f8...` and then `f0226532...` as current. Those values became stale as documentation commits advanced the branch. Always use the Git ref's current head and query check runs for that exact SHA before making a current CI claim.


## Staging and completion boundary

- The adapter requires the dedicated `jas_si_agent_broker_login` login and the `jas_si_agent_capability_broker` SET ROLE membership. The latest read-only Neon Staging inventory does not contain that login; this adapter is not yet deployable against the current Staging role set.
- The Broker capability resolver exists on Staging and EXECUTE is scoped to the Broker capability role; Worker and Verifier capability roles cannot execute it directly.
- The database migration is present in the repository, but the dedicated Broker login provisioning and live Broker DB connection are not verified. Do not infer successful migration replay or runtime readiness from the source tree.
- API route, isolated mTLS server, token-free repository read, Worker/Verifier wiring, private-repository task execution, and live independent end-to-end verification are not included in this slice and remain unverified.
- No credentials, Render services, paid resources, or Production settings are created or changed.

## Completion status

Adapter implementation and focused regression tests: **IMPLEMENTED + TESTED (exact-head CI)**. Main branch integration: **BRANCH-ALIGNED**. Staging integration: **BLOCKED / NOT VERIFIED**. Production verification: **NOT IMPLEMENTED**.

## Additional least-privilege finding — 2026-11-27

A deeper read-only Neon Staging privilege inspection found that `jas_si_agent_task_owner` had table-wide SELECT on `public.jas_si_tenants`. The six visible columns (`tenant_id`, `tenant_name`, `status`, `created_at`, `updated_at`, `provisioning_lock_version`) were all readable by this NOLOGIN SECURITY DEFINER owner role. Worker and Verifier had no tenant SELECT. The installation-binding migration had intentionally granted only `tenant_id` and `status`, but the later Broker migration broadened that to table-wide SELECT. The resolver only needs tenant identity and active status; the broader grant was unnecessary.

A corrective migration, `20261216_agent_task_owner_tenant_select_scope.sql`, has been added on this Draft PR branch. It revokes table-wide SELECT, restores only `tenant_id` and `status` column SELECT, and fails closed if any other tenant column remains readable. The canonical clean migration replay workflow now includes the corrective migration, and the migration contract test asserts its narrow grant.

**Important:** This correction is IMPLEMENTED on the PR branch only. It has not been applied to Neon Staging or Production. Exact-head CI and clean migration replay must pass before considering a separately authorized Staging application. No database privilege was changed by this review.
