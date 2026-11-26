# GitHub Task Capability Broker — Database Boundary

**Status:** Implemented on the main-based integration branch and exact-head CI validated. Independent code review and Broker runtime integration remain pending. A read-only Neon inspection on 2026-11-26 found the matching task-scoped resolver and NOLOGIN capability role already present in Staging; Production does not contain them. This PR did not apply a database migration.

## Purpose

The Worker and Independent Verifier must not obtain GitHub installation access by directly reading installation-binding tables or calling an unscoped resolver. The capability Broker is the only database principal allowed to resolve a GitHub repository capability for a specific persisted task.

## Authorization contract

- The Broker database capability role is NOLOGIN, non-superuser, non-inheriting, and cannot create databases or roles or bypass RLS.
- A dedicated Broker login may enter that role only through SET-only membership; Worker and Verifier roles do not inherit or receive Broker execution privileges.
- The SECURITY DEFINER resolver is owned by the task-owner role and fixes search_path=pg_catalog.
- A Worker lookup requires the persisted task to be running, the exact workload principal to own its unexpired lease, and the current lease fence to match.
- A Verifier lookup requires the persisted task to be awaiting verification, the exact verifier principal to own its unexpired claim, and the claim token to match.
- Both paths require an active tenant, a verified active GitHub installation and repository binding, a bounded repository-read task, a full 40-character commit SHA, and a path list of 1–10 non-empty relative strings, each at most 512 characters, with absolute paths, traversal segments, control characters, and backslashes rejected.
- The old unscoped installation resolver is revoked from Worker and Verifier; the Broker does not receive that legacy resolver.

## Expanded negative-case verification

The PostgreSQL integration test also checks that no capability is returned when the tenant is inactive, the installation or repository binding is inactive/unverified, the repository name does not match, the task type or state is wrong, the Worker lease or Verifier claim is expired, the commit SHA is malformed, or path entries are empty, non-string, oversized, absolute, contain traversal segments, control characters, or backslashes. Invalid role and null-argument combinations must raise the documented validation SQLSTATE. Fixture mutations are restored after each negative assertion so later replay and positive cases remain deterministic.

These assertions are test coverage only. They do not imply that the migration has been applied to a live Neon branch or that a Broker runtime is deployed.

## Verification

The migration integration test checks clean replay/idempotency, approved-style SET-only Broker membership, Worker and Verifier principal matching, stale lease fencing, invalid claim rejection, and denial of direct Worker/Verifier execution.

The canonical full migration replay workflow also includes this migration so that main's migration chain cannot silently omit the Broker DB boundary.

## Operational boundary

This migration does not create login credentials, TLS listeners, Render services, certificates, or production identities. It does not activate the Worker, Verifier, or Broker runtime. Staging and production application remain separate authorization and deployment gates.


## Live database boundary observation (2026-11-26)

Read-only catalog inspection of Neon project `odd-violet-93299575` found:

- Staging contains `jas_si_github_task_capability_resolve(uuid,name,text,bigint,uuid)`, owned by `jas_si_agent_task_owner`, SECURITY DEFINER, with fixed `search_path=pg_catalog`.
- The resolver is executable by `jas_si_agent_capability_broker`; Worker and Verifier capability roles cannot execute it; PUBLIC has no EXECUTE grant.
- The capability role is NOLOGIN, non-superuser, non-inheriting, and not BYPASSRLS. Its only observed membership is the Neon-managed `neondb_owner` ADMIN-only membership (no SET/INHERIT).
- No dedicated Broker LOGIN role was present in Staging, so this catalog evidence does **not** establish that a Broker process can connect or that mTLS identity mapping is live.
- Production has no Broker capability role or task-scoped resolver.

These observations are catalog state only. No migration, DDL, DML, login creation, credential injection, service deployment, or task execution was performed during this inspection.
