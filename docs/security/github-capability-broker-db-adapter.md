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

- Main SHA observed during this audit: `3922dc5a3f82b82da6d89e85b721fec9baa6a4ac`.
- Current branch head at the time of this review: `f0226532f0693481aa9b3dc2f1c26aee96ae7da4`.
- GitHub compare against current `main`: 20 commits ahead, 0 behind; merge base equals current Main SHA.
- Exact-head CI for `f0226532f0693481aa9b3dc2f1c26aee96ae7da4`: 11 returned check-run records completed successfully across two push attempts; all 11 concluded `success`. They cover 8 distinct check names: Security Verification (Python 3.10), JSONL Recovery, Vercel Runtime Compatibility (Python 3.12), Docker Container Verification, Dependency Lock Verification, Broker Adapter Unit Tests, Agent Unit Tests (Python 3.10), and Wheel Build and Install.
- Latest full security job `46030799738` ran 1,121 discovered tests; 109 were skipped and the job concluded successfully. The skipped tests must not be represented as executed.
- The optional PostgreSQL migration/adapter integration test is gated by `JAS_SI_BROKER_MIGRATION_TEST_DSN`. The Broker adapter CI job does not configure that DSN; therefore these CI results do not prove a live Broker database connection or execute that optional integration test.
- The adapter test job `46030799702` completed successfully. Python 3.10 security verification, Python 3.12 runtime compatibility, Docker verification, dependency lock, JSONL recovery, and wheel build/install checks also completed successfully.
- Exact-head evidence is CI evidence only. It does not establish Staging integration, deployed Broker runtime, private-repository task execution, or independent end-to-end verification.

## Evidence correction history

An earlier version of this document referred to head `328a0f8a9c3fb26746a82f101d2d15c8c214fb39` and 19 commits ahead. That is stale: the current branch head is `f0226532f0693481aa9b3dc2f1c26aee96ae7da4`, and the current comparison is 20 ahead / 0 behind. The older 3/3 CI statement applied to an earlier commit and is not the current evidence summary.


## Staging and completion boundary

- The adapter requires the dedicated `jas_si_agent_broker_login` login and the `jas_si_agent_capability_broker` SET ROLE membership. The latest read-only Neon Staging inventory does not contain that login; this adapter is not yet deployable against the current Staging role set.
- The Broker capability resolver exists on Staging and EXECUTE is scoped to the Broker capability role; Worker and Verifier capability roles cannot execute it directly.
- The database migration is present in the repository, but the dedicated Broker login provisioning and live Broker DB connection are not verified. Do not infer successful migration replay or runtime readiness from the source tree.
- API route, isolated mTLS server, token-free repository read, Worker/Verifier wiring, private-repository task execution, and live independent end-to-end verification are not included in this slice and remain unverified.
- No credentials, Render services, paid resources, or Production settings are created or changed.

## Completion status

Adapter implementation and focused regression tests: **IMPLEMENTED + TESTED (exact-head CI)**. Main branch integration: **BRANCH-ALIGNED**. Staging integration: **BLOCKED / NOT VERIFIED**. Production verification: **NOT IMPLEMENTED**.
