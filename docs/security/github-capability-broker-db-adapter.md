# GitHub Capability Broker — database adapter slice

## Scope

This Main-based integration slice adds the PostgreSQL task-scoped capability resolver adapter and isolated unit tests. It deliberately does not expose an HTTP endpoint, mint GitHub credentials, start a service, or enable Worker/Verifier access.

## Authorization contract

- Require PostgreSQL TLS hostname verification (`sslmode=verify-full`).
- Accept only the dedicated `jas_si_agent_broker_login` database session identity.
- Execute `SET ROLE jas_si_agent_capability_broker` only after checking that login identity.
- Delegate task, tenant, installation, repository binding, lease-fence, and verifier-claim authorization to the already-present SECURITY DEFINER database resolver.
- Fail closed and redact driver/database error details.
- Validate persisted commit and repository path metadata before returning it.

## Completion status

- Adapter and focused unit tests: proposed in this PR; not yet CI-tested.
- Database migration: present on Main; Staging catalog status is tracked separately.
- API route, mTLS server, token-free repository read, Worker/Verifier wiring, and live E2E: not included in this slice and remain unverified.
- No credentials, Render services, paid resources, or Production settings are created or changed.
