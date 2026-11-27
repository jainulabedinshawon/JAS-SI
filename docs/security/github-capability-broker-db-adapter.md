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

- Main base: `3922dc5a3f82b82da6d89e85b721fec9baa6a4ac`.
- Main-aligned Broker integration commit: `614d4aa4cb6fc0ec9e881f37ebf21842e212b28c`.
- The branch is 18 commits ahead and 0 behind Main; the integration commit has Main as its first parent.
- Exact-head push CI for `614d4aa4cb6fc0ec9e881f37ebf21842e212b28c`: 3/3 workflows successful:
  - GitHub Capability Broker Adapter Tests — run `46028849292`; focused adapter test step passed.
  - Post-Merge Security Verification — run `46028849523`; Python 3.10 compilation and complete discovered unit-test suite passed.
  - Vercel Runtime Compatibility (Python 3.12) — run `46028849354`; compilation, FastAPI entrypoint validation, and complete unit-test suite passed.
- Regression coverage includes actual U+0001, U+001F, and U+007F characters (not escaped backslash text).

## Staging and completion boundary

- The adapter requires the dedicated `jas_si_agent_broker_login` login and the `jas_si_agent_capability_broker` SET ROLE membership. The latest read-only Neon Staging inventory does not contain that login; this adapter is not yet deployable against the current Staging role set.
- The Broker capability resolver exists on Staging and EXECUTE is scoped to the Broker capability role; Worker and Verifier capability roles cannot execute it directly.
- The database migration is present in the repository, but the dedicated Broker login provisioning and live Broker DB connection are not verified. Do not infer successful migration replay or runtime readiness from the source tree.
- API route, isolated mTLS server, token-free repository read, Worker/Verifier wiring, private-repository task execution, and live independent end-to-end verification are not included in this slice and remain unverified.
- No credentials, Render services, paid resources, or Production settings are created or changed.

## Completion status

Adapter implementation and focused regression tests: **IMPLEMENTED + TESTED (exact-head CI)**. Main branch integration: **BRANCH-ALIGNED**. Staging integration: **BLOCKED / NOT VERIFIED**. Production verification: **NOT IMPLEMENTED**.
