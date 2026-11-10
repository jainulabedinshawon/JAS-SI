# JAS-SI Standalone SaaS Architecture

JAS-SI will operate as an independent SaaS product. It will not require JAS Platform identity, commerce, billing, or entitlement APIs at runtime. JAS Platform may be an optional integration later, never a dependency.

JAS-SI owns customer identity, email verification, sessions, tenant-scoped API keys, technical usage metering, plans, quotas, entitlement decisions, payment-provider adapters, customer dashboard, developer portal, audit, and support operations.

A payment provider is a payment rail, not the authority for product authorization. Signed webhooks must be verified, replay-safe, idempotent, and reconciled. JAS-SI owns subscription and entitlement state.

Initial launch target: free/pilot access without payment integration; paid plans only after end-to-end payment and reconciliation tests for international and Bangladesh-capable providers.

Release gates: verified customer onboarding; scoped key creation/revocation; tenant-isolated usage dashboard; independent API docs and real backend demo; fail-closed quota enforcement; signed webhook verification; backup/restore, monitoring, rollback, and security evidence.

No production migration or deployment is included in this architecture decision. The existing API must not claim independent semantic verification unless independent evidence collectors actually exist.