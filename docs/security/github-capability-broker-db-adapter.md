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

Adapter implementation and focused regression tests: **IMPLEMENTED + TESTED (exact-head CI)**. Main branch integration: **BRANCH-ALIGNED**. Staging least-privilege correction: **APPLIED + INDEPENDENTLY VERIFIED**. Broker login/connection and runtime integration: **BLOCKED / NOT VERIFIED**. Production verification: **NOT IMPLEMENTED**.

## Additional least-privilege finding — 2026-11-27

A deeper read-only Neon Staging privilege inspection found that `jas_si_agent_task_owner` had table-wide SELECT on `public.jas_si_tenants`. The six visible columns (`tenant_id`, `tenant_name`, `status`, `created_at`, `updated_at`, `provisioning_lock_version`) were all readable by this NOLOGIN SECURITY DEFINER owner role. Worker and Verifier had no tenant SELECT. The installation-binding migration had intentionally granted only `tenant_id` and `status`, but the later Broker migration broadened that to table-wide SELECT. The resolver only needs tenant identity and active status; the broader grant was unnecessary.

A corrective migration, `20261216_agent_task_owner_tenant_select_scope.sql`, has been added on this Draft PR branch. It revokes table-wide SELECT, restores only `tenant_id` and `status` column SELECT, and fails closed if any other tenant column remains readable. The canonical clean migration replay workflow now includes the corrective migration, and the migration contract test asserts its narrow grant.

**Staging application update — 2026-11-27:** Following explicit user approval for this Staging-only corrective action, the exact corrective SQL above was applied to Neon Staging branch `br-wandering-bonus-b32u1xg2` in one database transaction. A subsequent independent catalog query confirmed:
- Task Owner table-wide SELECT: `false`.
- Task Owner column SELECT for `tenant_id`: `true`.
- Task Owner column SELECT for `status`: `true`.
- Unexpected additional Tenant columns readable: `NULL` (none).
- Broker capability role EXECUTE on task-scoped resolver: `true`.
- Worker and Verifier EXECUTE on that resolver: both `false`.
- Dedicated Broker LOGIN: still absent.

This establishes the least-privilege correction as **STAGING APPLIED + INDEPENDENTLY VERIFIED**. The SQL transaction returned successfully and its in-transaction assertions passed. Production was not changed. No dedicated Broker credential was created, no runtime was deployed, and no live Broker connection was tested. Neon does not expose a migration-history row for this direct SQL application in this workflow; the repository migration remains the canonical replay record.


## Evidence refresh — 2026-11-28 (UTC+6)

The following is a new live audit snapshot; the historical 2026-11-27 observations above are retained as history and must not be interpreted as the current branch head.

- Current Main SHA: `3922dc5a3f82b82da6d89e85b721fec9baa6a4ac`.
- Current adapter integration branch head at this audit: `2cb57bc408b6cc780fe1d06fa2309230866043e1`.
- Current compare: 30 commits ahead / 0 behind; merge base equals Main.
- Exact-head workflow query returned 14 PR-triggered runs, all completed successfully. The endpoint returns only its first page and is not a complete required-check inventory.
- Broker Adapter workflow run `46066428921`, job `broker-adapter-unit-tests`, executed both `tests/test_github_capability_broker_adapter.py` and `tests/test_github_capability_identity.py`; the combined test step completed successfully.
- A read-only Neon Staging recheck confirmed Task Owner table-wide tenant SELECT=false; `tenant_id` and `status` column SELECT=true; Broker resolver EXECUTE=true; Worker and Verifier resolver EXECUTE=false.
- Render workspace service inventory returned no services. The referenced Vercel Production deployment remains READY on Main SHA above.
- The current PR remains Draft. No submitted review or inline review thread was returned by the review endpoints.
- The PR metadata reports 10 changed files while the current compare response enumerates 8 files; reconcile this discrepancy against GitHub's authoritative PR file list before merge. Do not infer the exact diff inventory from either count alone.

**Current decision:** Keep Draft. Do not merge until exact PR file inventory, full required-check inventory, and independent review are reconciled. Broker LOGIN/connection, mandatory-mTLS listener, private repository proxy, Worker/Verifier runtime wiring, E2E, and Production verification remain **NOT VERIFIED**.


## Live evidence refresh — 2026-11-28 (UTC+6), after documentation commit

This snapshot supersedes the preceding branch-head snapshot; older entries remain historical.

- Main remains `3922dc5a3f82b82da6d89e85b721fec9baa6a4ac`.
- Current adapter branch head: `48a6ccb2a22824ed278af43c0c9fdc0d6db08ace`.
- Current compare: 31 commits ahead / 0 behind; merge base is Main.
- Exact-head workflow query for `48a6ccb...` returned 14 PR-triggered workflow runs, all `completed/success`.
- Broker Adapter run `46068485803` was inspected at job level: `broker-adapter-unit-tests` succeeded; its combined adapter + workload identity test step succeeded.
- The workflow endpoint returns its first page only; 14 successes are not a complete required-check inventory.
- PR #153 is Open. The issue payload did not expose an authoritative `changed_files` count or a `draft` field. The compare endpoint enumerates eight changed paths. An earlier report mentioned ten PR files; because the current available PR payload does not expose the file-list endpoint, that discrepancy is **UNRESOLVED**, not explained.
- No submitted PR reviews were returned.
- Neon Staging read-only assertions remain: Task Owner table-wide tenant SELECT=false; `tenant_id`/ `status` SELECT=true; Broker resolver EXECUTE=true; Worker/Verifier EXECUTE=false.
- Render workspace returned an empty service inventory.
- Vercel Production deployment `dpl_8X3FLYpTRKw41qDE7Joo57brBozQ` is READY and points to Main SHA above.

**Decision:** Keep PR #153 unmerged and Draft status unconfirmed (the issue payload omits the draft field). Do not claim complete merge-gate verification. Broker LOGIN/connection, mandatory-mTLS listener, repository-read proxy, Worker/Verifier runtime wiring, full E2E, and Production runtime verification remain **NOT VERIFIED**. No infrastructure, credentials, database grants, or Production settings were changed in this audit.
