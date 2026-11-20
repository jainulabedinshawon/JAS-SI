# GitHub App Staging rollout preflight

Status: **preparation only — not an authorization to execute migrations**

Scope: Staging-only preflight for the GitHub App webhook inbox, customer OAuth/PKCE attempt store, Installation ownership claims, and isolated Installation reconciler. This runbook is intentionally read-only until the separate migration approval is granted.

## Verified implementation contract

The current implementation is in the stacked GitHub integration PR chain. The five migration files are:

1. `20261201_github_installation_binding.sql` — tenant-owned Installation and repository binding tables; requires the existing tenant and agent capability roles.
2. `20261202_github_webhook_inbox.sql` — durable, tenant-neutral inbox; requires `jas_si_agent_task_owner` and `jas_si_runtime`.
3. `20261204_github_oauth_attempt_store.sql` — single-use OAuth state/PKCE attempt store; requires `jas_si_customer_identity_owner` and `jas_si_customer_runtime`.
4. `20261206_github_installation_claims.sql` — customer-session-bound pending Installation claims; requires the customer identity roles and customer session/account/tenant tables.
5. `20261207_github_installation_reconciliation.sql` — authoritative snapshot reconciliation; requires the preceding GitHub tables and both owner roles.

The final migration creates the capability role `jas_si_github_reconciler` as `NOLOGIN`, `NOSUPERUSER`, `NOCREATEDB`, `NOCREATEROLE`, `NOREPLICATION`, `NOBYPASSRLS`, and `NOINHERIT` when absent. It does **not** create a service login or configure a database URL. A separately provisioned login must be granted membership in this capability through the approved secret/role-provisioning process. The same principle applies to customer-identity and webhook service logins.

## Hard rollout gates

- Do not run these migrations against Staging or Production without a separate, explicit approval naming the target branch and migration set.
- Never put passwords, DSNs, OAuth secrets, webhook secrets, or private keys in this document, Git, CI logs, or chat.
- Use a dedicated migration executor. Do not use a customer, webhook, worker, verifier, or reconciler service login as migration owner.
- Confirm the target database and branch identity before every operation. Stop if the connection target is ambiguous.
- Capture a recoverable Neon branch snapshot/restore point under the operator's approved procedure before any write.
- Apply migrations in the listed order using the repository's migration runner. Do not manually skip, reorder, or partially replay files.
- Keep GitHub App installation activation disabled until the live OAuth → pending claim → authoritative reconciliation lifecycle has passed.

## Read-only pre-migration inventory

Run using the approved Staging read-only administrative connection. These statements inspect catalog state only.

### 1. Confirm target and caller

```sql
SELECT current_database() AS database_name,
       current_user AS current_role,
       session_user AS session_role,
       inet_server_addr() AS server_address,
       inet_server_port() AS server_port,
       current_setting('server_version') AS server_version,
       current_setting('transaction_read_only') AS transaction_read_only;
```

The operator must independently match the connection to the intended Neon Staging branch in the Neon console. A database name alone is not sufficient proof of branch identity.

### 2. Inspect required roles and security flags

```sql
SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole,
       rolreplication, rolbypassrls, rolinherit
FROM pg_catalog.pg_roles
WHERE rolname IN (
  'jas_si_runtime',
  'jas_si_provisioner',
  'jas_si_agent_task_owner',
  'jas_si_agent_worker',
  'jas_si_agent_verifier',
  'jas_si_agent_worker_login',
  'jas_si_agent_verifier_login',
  'jas_si_customer_identity_owner',
  'jas_si_customer_runtime',
  'jas_si_github_reconciler'
)
ORDER BY rolname;
```

Expected before migration: existing prerequisites must be present. The reconciler capability may be absent before migration 20261207. Do not pre-create it with ad hoc attributes; let the reviewed migration create it. Service login names are environment-specific and must be recorded in the operator's secret inventory, not guessed from this list.

### 3. Inspect membership edges

```sql
SELECT granted.rolname AS granted_role,
       member.rolname AS member_role,
       m.admin_option,
       m.inherit_option,
       m.set_option,
       pg_catalog.pg_has_role(member.oid, granted.oid, 'MEMBER') AS is_member,
       pg_catalog.pg_has_role(member.oid, granted.oid, 'USAGE') AS privileges_inherited
FROM pg_catalog.pg_auth_members AS m
JOIN pg_catalog.pg_roles AS granted ON granted.oid = m.roleid
JOIN pg_catalog.pg_roles AS member ON member.oid = m.member
WHERE granted.rolname LIKE 'jas_si_%'
   OR member.rolname LIKE 'jas_si_%'
ORDER BY 1, 2;
```

Interpret the membership direction carefully: `granted_role` is the role being granted; `member_role` is the role receiving membership. A row showing `neondb_owner` as member of an application capability is not the same as an application login being a member of `neondb_owner`. `INHERIT` controls automatic privilege inheritance; `SET` controls whether the member can explicitly switch into the granted role; `ADMIN OPTION` controls whether it can grant that membership onward. Record all three flags and check both `MEMBER` and `USAGE` semantics.

Before migration, record the actual worker, verifier, customer-identity, webhook/runtime, and migration-executor memberships. After service logins are provisioned, verify each exact login is a member of only its intended capability role(s). Do not grant service logins membership in owner, superuser, provisioner, or unrelated runtime roles.

### 4. Inspect existing GitHub objects and migration prerequisites

```sql
SELECT n.nspname, c.relname, c.relkind,
       pg_catalog.pg_get_userbyid(c.relowner) AS owner
FROM pg_catalog.pg_class AS c
JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relname LIKE 'jas_si_github_%'
ORDER BY c.relname;

SELECT n.nspname, p.proname,
       pg_catalog.pg_get_userbyid(p.proowner) AS owner,
       p.prosecdef AS security_definer,
       p.proconfig
FROM pg_catalog.pg_proc AS p
JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
WHERE n.nspname = 'public'
  AND p.proname LIKE '%github%'
ORDER BY p.proname;
```

Also confirm the prerequisite tenant, customer account/session, and agent-task objects referenced by the migration preflight blocks exist. Stop on unexpected partial GitHub objects; do not assume `IF NOT EXISTS` makes a partially applied schema safe.

### 5. Snapshot default privileges

```sql
SELECT d.defaclrole::regrole AS owner_role,
       CASE WHEN d.defaclnamespace = 0 THEN '(all schemas)'
            ELSE d.defaclnamespace::regnamespace::text END AS schema_name,
       d.defaclobjtype,
       d.defaclacl
FROM pg_catalog.pg_default_acl AS d
ORDER BY 1, 2, 3;
```

Record the output before and after. Investigate any default DML grant and any default SELECT grant to runtime or service identities; default SELECT is still a future-object privilege expansion even though it is not DML. In particular, inspect defaults for every owner that creates application tables (including `neondb_owner`) and distinguish provider-managed defaults from application-owned defaults. Review column-level grants separately with `information_schema.column_privileges`. Do not change default privileges as part of this preflight.

A Staging audit on 2026-11-20 observed a `neondb_owner` default-privilege entry for future public tables granting `SELECT` to both `jas_si_runtime` and `jas_si_provisioner`, with `neondb_owner` as grantor. This is a confirmed catalog finding, not proof of a currently exploitable path or of a production issue. The same audit found `neondb_owner` is a member of both `jas_si_runtime` and `jas_si_provisioner` with `ADMIN OPTION=true`, but `INHERIT=false` and `SET=false`; it therefore does not automatically inherit those roles' privileges and cannot SET ROLE through those membership edges, but it can grant the memberships onward. Treat this as a distinct role-delegation review item and confirm whether the Neon-managed owner role is expected to retain that grant authority.

The GitHub migrations create their tables while executing as the dedicated owner roles (`jas_si_customer_identity_owner` for claims and `jas_si_agent_task_owner` for reconciliation objects), not as `neondb_owner`; therefore the observed `neondb_owner` default table ACL does not automatically attach to those tables. Verify the actual table owner and effective ACL after migration rather than assuming either inheritance or isolation. Before applying any schema migration, establish whether the default grants and owner-to-capability ADMIN memberships are intentional and required; if not, prepare a separately reviewed least-privilege correction and obtain explicit approval before changing them. Recheck after migrations because future objects inherit defaults from their creating owner.

## Post-migration ACL verification

Run only after the separately approved migration has completed successfully. Use a read-only verifier connection first.

### 1. Verify reconciler capability is non-login and constrained

```sql
SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole,
       rolreplication, rolbypassrls, rolinherit
FROM pg_catalog.pg_roles
WHERE rolname = 'jas_si_github_reconciler';
```

Expected: exactly one role; LOGIN=false and every elevated flag false. The migration creates a capability, not the application login.

### 2. Verify effective table and routine privileges

```sql
WITH identities(role_name) AS (
  VALUES ('jas_si_runtime'),
         ('jas_si_customer_runtime'),
         ('jas_si_agent_worker'),
         ('jas_si_agent_verifier'),
         ('jas_si_github_reconciler')
),
tables(table_name) AS (
  VALUES ('jas_si_github_app_installations'),
         ('jas_si_github_app_installation_repositories'),
         ('jas_si_github_webhook_inbox'),
         ('jas_si_github_oauth_attempts'),
         ('jas_si_github_installation_claims')
)
SELECT i.role_name, t.table_name,
       has_table_privilege(i.role_name, 'public.' || t.table_name, 'SELECT') AS can_select,
       has_table_privilege(i.role_name, 'public.' || t.table_name, 'INSERT') AS can_insert,
       has_table_privilege(i.role_name, 'public.' || t.table_name, 'UPDATE') AS can_update,
       has_table_privilege(i.role_name, 'public.' || t.table_name, 'DELETE') AS can_delete,
       has_table_privilege(i.role_name, 'public.' || t.table_name, 'TRUNCATE') AS can_truncate,
       has_table_privilege(i.role_name, 'public.' || t.table_name, 'REFERENCES') AS can_reference,
       has_table_privilege(i.role_name, 'public.' || t.table_name, 'TRIGGER') AS can_trigger
FROM identities AS i CROSS JOIN tables AS t
ORDER BY 1, 2;
```

This checks effective privileges inherited through role membership as well as direct grants. It is not a substitute for checking column-level privileges: inspect `information_schema.column_privileges` for these identities and relations too.

Expected: reconciler, worker, and verifier have no direct/effective table privileges on the protected GitHub tables; the webhook/runtime role has no direct/effective inbox table privileges; customer runtime has no direct/effective OAuth-attempt or Installation-claim table privileges. Review every non-zero result against the reviewed migration ACLs. The migration's embedded assertion checks selected reconciler/worker/verifier table privileges and selected routine grants; this expanded matrix is an additional rollout gate, not a claim that the migration itself asserts every privilege shown.

Inspect routine ACLs by exact signature, including:
- `jas_si_github_installation_claim_pending(integer)`
- `jas_si_github_installation_reconcile_apply(bigint,bigint,bigint,text,text,boolean,boolean,jsonb)`
- `jas_si_github_webhook_claim(integer,integer)`
- `jas_si_github_webhook_mark_processed(text,uuid)`
- `jas_si_github_webhook_mark_failed(text,text,uuid,integer)`
- `jas_si_github_webhook_receive(text,text,text,bigint,bytea,jsonb)`
- `customer_github_oauth_attempt_create(bytea,uuid,bigint,bytea,bytea,text,bytea,timestamptz)`
- `customer_github_oauth_attempt_consume(bytea,bytea,bytea)`
- `customer_github_installation_claim_record(bytea,uuid,bigint,bigint,text,bigint,text,text,bigint)`

Expected:
- `jas_si_github_reconciler` receives EXECUTE on pending-claim, reconcile-apply, and inbox claim/finish routines; it must not receive EXECUTE on public webhook receive.
- `jas_si_runtime` receives EXECUTE on webhook receive/claim/finish routines, but no direct inbox table access.
- `jas_si_customer_runtime` receives EXECUTE on OAuth attempt create/consume and customer Installation claim-record routines, but no direct access to the OAuth-attempt or claim tables.
- Worker and verifier capability roles must not receive direct access to protected GitHub tables or EXECUTE on customer-only claim-record and reconciler-only privileged routines.
- Privileged routines must not have broad PUBLIC EXECUTE. Confirm each routine's owner, SECURITY DEFINER flag, and fixed `search_path=pg_catalog`.

Use the exact signatures above when querying `pg_proc` or `has_function_privilege`; overloaded routine names must never be checked by name alone.

Run this routine ownership/ACL inventory for the same signatures (populate the VALUES list with each exact `regprocedure` signature listed above):

```sql
WITH routines(signature) AS (
  VALUES
    ('public.jas_si_github_installation_claim_pending(integer)'::regprocedure),
    ('public.jas_si_github_installation_reconcile_apply(bigint,bigint,bigint,text,text,boolean,boolean,jsonb)'::regprocedure),
    ('public.jas_si_github_webhook_claim(integer,integer)'::regprocedure),
    ('public.jas_si_github_webhook_mark_processed(text,uuid)'::regprocedure),
    ('public.jas_si_github_webhook_mark_failed(text,text,uuid,integer)'::regprocedure),
    ('public.jas_si_github_webhook_receive(text,text,text,bigint,bytea,jsonb)'::regprocedure),
    ('public.customer_github_oauth_attempt_create(bytea,uuid,bigint,bytea,bytea,text,bytea,timestamptz)'::regprocedure),
    ('public.customer_github_oauth_attempt_consume(bytea,bytea,bytea)'::regprocedure),
    ('public.customer_github_installation_claim_record(bytea,uuid,bigint,bigint,text,bigint,text,text,bigint)'::regprocedure)
)
SELECT p.oid::regprocedure AS signature,
       pg_catalog.pg_get_userbyid(p.proowner) AS owner,
       p.prosecdef AS security_definer,
       p.proconfig,
       pg_catalog.pg_get_function_result(p.oid) AS result_type,
       p.proacl
FROM routines r JOIN pg_catalog.pg_proc p ON p.oid=r.signature
ORDER BY 1;
```

For each routine, evaluate `has_function_privilege(role_name, signature, 'EXECUTE')` for all five service/capability roles and `PUBLIC`. PUBLIC must be checked from `aclexplode(COALESCE(proacl, acldefault('f', proowner)))`, because a NULL `proacl` means default function privileges, not "no grants".

### 3. Verify real service logins

Catalog checks alone do not prove the host can authenticate or that the application uses the intended role. For each configured service login, connect using the secret manager without exposing the DSN, then run:

```sql
SELECT session_user, current_user,
       pg_has_role(session_user, 'jas_si_github_reconciler', 'MEMBER')
         AS is_reconciler_member;
```

Run the equivalent membership check for the exact intended worker, verifier, customer-identity, and webhook capability. Execute an approved positive routine call only with a disposable fixture and an approved test procedure. Negative tests must prove direct table reads/writes and unauthorized routine execution fail with permission denial. Do not run a reconciliation mutation against a real Installation as an ACL probe.

### 4. Verify RLS and object ownership

For each protected GitHub table, inspect `pg_class.relrowsecurity`, `pg_class.relforcerowsecurity`, policies in `pg_policy`, table owner, and both table-level and column-level ACLs. Verify no service login owns protected tables and no service identity has BYPASSRLS. Check default privileges again for the owner roles and public schema.

## Operational lifecycle verification

After credentials, GitHub App settings, webhook configuration, and the reconciler host are separately approved and configured in Staging:

1. Deliver a correctly signed test webhook; verify durable inbox insert and duplicate delivery idempotency.
2. Complete OAuth using a dedicated test customer; verify the OAuth attempt is single-use and the claim remains pending.
3. Run the reconciler; independently verify the live App ID/account identity and full paginated repository snapshot.
4. Verify only the exact repositories from the authoritative snapshot become active.
5. Remove a repository, suspend the Installation, unsuspend it, and delete it in a controlled test App; verify revocation/reactivation semantics.
6. Verify retry ceiling, retry delay, lease fencing, worker heartbeat, and no cross-tenant binding.
7. Independently inspect database rows, audit evidence, host logs, and customer-visible state. The agent's own success report is not proof.

## Failure and recovery

- Stop immediately on any failed migration preflight, unexpected owner, unexpected grant, RLS mismatch, duplicate identity, or partially applied object set.
- Preserve migration output and read-only catalog snapshots with timestamps and target branch identity. Redact credentials and customer data.
- Do not manually drop GitHub tables, roles, or functions to "roll back" a partially applied rollout.
- Use the approved Neon restore/branch recovery procedure or a reviewed forward-fix migration. Confirm data impact and obtain separate approval before destructive recovery.
- After recovery, rerun the full preflight and exact migration-chain replay against a disposable PostgreSQL database before another Staging attempt.

## Current known boundary at authoring time

The Staging branch has previously been observed without the five GitHub integration tables and without the `jas_si_github_reconciler` role. Re-run the read-only inventory immediately before any rollout; this note is historical context, not a substitute for a live preflight.

No Staging or Production migration, service login creation, secret configuration, GitHub App setup, webhook registration, Installation activation, or deployment is authorized by this document.
