# GitHub Task Capability Broker — Database Boundary

**Status:** Implemented on an integration branch; exact-head CI and review pending. Not deployed to staging or production.

## Purpose

The Worker and Independent Verifier must not obtain GitHub installation access by directly reading installation-binding tables or calling an unscoped resolver. The capability Broker is the only database principal allowed to resolve a GitHub repository capability for a specific persisted task.

## Authorization contract

- The Broker database capability role is NOLOGIN, non-superuser, non-inheriting, and cannot create databases or roles or bypass RLS.
- A dedicated Broker login may enter that role only through SET-only membership; Worker and Verifier roles do not inherit or receive Broker execution privileges.
- The SECURITY DEFINER resolver is owned by the task-owner role and fixes search_path=pg_catalog.
- A Worker lookup requires the persisted task to be running, the exact workload principal to own its unexpired lease, and the current lease fence to match.
- A Verifier lookup requires the persisted task to be awaiting verification, the exact verifier principal to own its unexpired claim, and the claim token to match.
- Both paths require an active tenant, a verified active GitHub installation and repository binding, a bounded repository-read task, a full 40-character commit SHA, and a bounded path list.
- The old unscoped installation resolver is revoked from Worker and Verifier; the Broker does not receive that legacy resolver.

## Verification

The migration integration test checks clean replay/idempotency, approved-style SET-only Broker membership, Worker and Verifier principal matching, stale lease fencing, invalid claim rejection, and denial of direct Worker/Verifier execution.

The canonical full migration replay workflow also includes this migration so that main's migration chain cannot silently omit the Broker DB boundary.

## Operational boundary

This migration does not create login credentials, TLS listeners, Render services, certificates, or production identities. It does not activate the Worker, Verifier, or Broker runtime. Staging and production application remain separate authorization and deployment gates.
