# Agent per-instance PostgreSQL login provisioning

## Purpose and security boundary

The database-principal migration binds Worker leases and Verifier claims to PostgreSQL `session_user`. The host preflight can accept a bounded, role-specific instance login and checks that the connected session is that login with the expected capability role.

This is a **database-login identity**, not cryptographic process identity. Each independently isolated Worker or Verifier service instance must use a distinct PostgreSQL LOGIN and a distinct credential. Replicas that share a DSN remain one principal and are not isolated from one another by this mechanism.

This runbook is an operator procedure only. It does not create roles, set credentials, change Render, or apply a migration.

## Naming constraints

- Worker: `jas_si_agent_worker_login_<instance>`
- Verifier: `jas_si_agent_verifier_login_<instance>`
- The suffix must be 1–32 lowercase ASCII characters from `a-z`, `0-9`, and `_`.
- Use a stable, non-secret instance identifier. Do not put tenant IDs, customer data, secrets, or environment names that disclose sensitive topology in the role name.

## Provision one isolated login

Run the following as a database administrator only after the matching application migration is installed and reviewed. Replace the example suffix with a unique permitted identifier. Run only the block matching the workload.

Worker example:

```sql
CREATE ROLE jas_si_agent_worker_login_instance_01
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS;
GRANT jas_si_agent_worker
  TO jas_si_agent_worker_login_instance_01
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
```

Verifier example:

```sql
CREATE ROLE jas_si_agent_verifier_login_instance_01
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS;
GRANT jas_si_agent_verifier
  TO jas_si_agent_verifier_login_instance_01
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
```

Do not grant both capability roles to one login. Do not grant `jas_si_agent_task_owner`, Reconciler, schema-owner, or table-owner roles. The LOGIN must use `SET ROLE` to its one NOLOGIN capability role as the runtime already does.

## Credential delivery

1. Generate a unique credential or client certificate for this login using the approved secret-management process.
2. Deliver it only to the matching Worker or Verifier service instance. Never place it in a shared Environment Group inherited by both workloads.
3. Configure the matching DSN and expected-login setting:
   - Worker: `JAS_SI_AGENT_WORKER_DSN` and `JAS_SI_AGENT_WORKER_DB_LOGIN`
   - Verifier: `JAS_SI_AGENT_VERIFIER_DSN` and `JAS_SI_AGENT_VERIFIER_DB_LOGIN`
4. Keep the credential out of source control, build logs, CI output, task payloads, and application logs.
5. Do not point two independently isolated instances at the same LOGIN credential.

## Verification before enabling task execution

From each instance's own connection, verify without printing its DSN or credential:

```sql
SELECT session_user,
       current_user,
       pg_has_role(session_user, 'jas_si_agent_worker', 'MEMBER') AS worker_member,
       pg_has_role(session_user, 'jas_si_agent_verifier', 'MEMBER') AS verifier_member;
```

For a Worker, require the exact configured Worker LOGIN, `worker_member = true`, and `verifier_member = false`. For a Verifier, require the exact configured Verifier LOGIN, `verifier_member = true`, and `worker_member = false`. The application preflight must also pass its required routine and table-isolation checks.

Use disposable Staging tasks to prove:
- two distinct Worker logins cannot renew, report, fail, or otherwise mutate each other's live leases;
- an expired lease can be reclaimed and becomes owned by the new login;
- two distinct Verifier logins cannot release, finalize, or record an inconclusive outcome for each other's live claims;
- expired claims can be reclaimed and become owned by the new login;
- an unbound legacy active lease/claim fails closed until expiry.

Do not use production customer tasks as test fixtures.

## Rotation and retirement

For rotation, create a new uniquely named LOGIN, provision a separate credential, deploy and verify the new instance, then drain the old instance before revoking its capability membership and disabling its LOGIN. Never rotate by copying the old credential to another instance.

Before dropping a retired role, verify it owns no objects and has no active sessions or outstanding work. Prefer disabling login and revoking capability membership first; destructive role deletion requires a separate reviewed operation.

## Explicit non-goals

This procedure does not provide mTLS, certificate-to-instance attestation, a Capability Broker, per-request task/lease authorization at a broker, or isolation between processes that share one LOGIN. It does not provision roles or credentials automatically. Live Neon changes, credential delivery, and service deployment require explicit operational approval.
