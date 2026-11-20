# GitHub App Staging rollout preflight

Status: **preparation only — not an authorization to execute migrations**

Scope: Staging-only preflight for the GitHub App webhook inbox, customer OAuth/PKCE attempt store, Installation ownership claims, and isolated Installation reconciler. This runbook is intentionally read-only until the separate migration approval is granted.

## Verified implementation contract

The current implementation is in the stacked GitHub integration PR chain. The Staging rollout migration set contains eight files in canonical order:

1. `20261201_github_installation_binding.sql` — tenant-owned Installation and repository binding tables; requires the existing tenant and agent capability roles.
2. `20261202_github_webhook_inbox.sql` — durable, tenant-neutral inbox; requires `jas_si_agent_task_owner` and `jas_si_runtime`.
3. `20261203_api_key_provisioner_rls_policies.sql` — required API-key provisioner RLS policy boundary in the complete branch migration chain; this is a prerequisite security migration, not a GitHub integration table migration.
4. `20261204_github_oauth_attempt_store.sql` — single-use OAuth state/PKCE attempt store; requires `jas_si_customer_identity_owner` and `jas_si_customer_runtime`.
5. `20261206_github_installation_claims.sql` — customer-session-bound pending Installation claims; requires the customer identity roles and customer session/account/tenant tables.
6. `20261207_github_installation_reconciliation.sql` — authoritative snapshot reconciliation and the dedicated `jas_si_github_reconciler` capability role.
7. `20261208_github_webhook_login_boundary.sql` — creates the dedicated `jas_si_github_webhook_login` as NOLOGIN/NOINHERIT and grants only the four webhook inbox routine EXECUTE permissions. Its membership in `jas_si_runtime` is MEMBER-only: INHERIT=false and SET=false, preventing broad runtime/audit capability use.
8. `20261209_github_reconciler_login_boundary.sql` — creates the dedicated `jas_si_github_reconciler_login` as NOLOGIN/NOINHERIT and grants SET-only membership in `jas_si_github_reconciler`; the application must explicitly SET ROLE on every connection.

The migration-chain CI replays the complete branch chain, including the 20261203 prerequisite, rather than only the GitHub-specific migrations. Keep this exact order when validating the branch; do not omit the RLS prerequisite.

Migrations 20261208 and 20261209 intentionally create **NOLOGIN** identities. They do not create passwords or configure database URLs. Enabling LOGIN, generating credentials, and placing dedicated DSNs in the approved secret manager are separate operator actions requiring separate approval. The webhook login must not inherit or SET `jas_si_runtime`; the reconciler login must SET only `jas_si_github_reconciler`. Do not replace either identity with the broad `jas_si_runtime` login.

## Hard rollout gates

- Do not run these migrations against Staging or Production without a separate, explicit approval naming the target branch and migration set.
- Never put passwords, DSNs, OAuth secrets, webhook secrets, or private keys in this document, Git, CI logs, or chat.
- Use a dedicated migration executor. Do not use a customer, webhook, worker, verifier, or reconciler service login as migration owner.
- Confirm the target database and branch identity before every operation. Stop if the connection target is ambiguous.
- Capture a recoverable Neon branch snapshot/restore point under the operator's approved procedure before any write.
- Apply migrations in the listed order using the repository's migration runner. Do not manually skip, reorder, or partially replay files.
- The current Neon Staging branch reports PostgreSQL 18.7. CI must replay the full chain on PostgreSQL 16 and 18 before Staging approval; a PostgreSQL 16-only pass is not sufficient evidence for this target.
- Keep GitHub App installation activation disabled until the live OAuth → pending claim → authoritative reconciliation lifecycle has passed.

## Staging runtime configuration manifest

Configure these names only in the Vercel **Preview** environment for the exact JAS-SI Staging deployment. Do not put values in Git, this runbook, PR comments, CI output, or chat. The current project Preview inventory has not yet shown these GitHub integration keys, and the target feature branch currently has no Vercel Preview deployment; therefore this manifest is a required preflight, not evidence of a live configuration.

| Variable | Type | Requirement / validation |
|---|---|---|
| `JAS_SI_GITHUB_APP_ID` | Non-secret | Positive integer GitHub App ID |
| `JAS_SI_GITHUB_APP_PRIVATE_KEY_B64` | Secret | Base64-encoded PEM private key; use the existing locally generated App key |
| `JAS_SI_GITHUB_OAUTH_CLIENT_ID` | Non-secret | GitHub App OAuth Client ID |
| `JAS_SI_GITHUB_OAUTH_CLIENT_SECRET` | Secret | OAuth client secret |
| `JAS_SI_GITHUB_OAUTH_REDIRECT_URI` | Non-secret URL | Exact HTTPS Preview origin plus `/v1/github/oauth/callback`; no query or fragment |
| `JAS_SI_GITHUB_OAUTH_ENCRYPTION_KEYRING` | Secret | JSON object mapping version labels to Base64-encoded 32-byte keys |
| `JAS_SI_GITHUB_OAUTH_ACTIVE_KEY_VERSION` | Non-secret | Must match a key version in the keyring |
| `JAS_SI_GITHUB_WEBHOOK_SECRET` | Secret | GitHub App webhook secret, at least 32 UTF-8 bytes |
| `JAS_SI_GITHUB_WEBHOOK_DATABASE_URL` | Secret | Dedicated DSN authenticating as `jas_si_github_webhook_login`; never `jas_si_runtime` |
| `JAS_SI_GITHUB_RECONCILER_DATABASE_URL` | Secret | Dedicated DSN authenticating as `jas_si_github_reconciler_login`; adapter explicitly SET ROLE to `jas_si_github_reconciler` |
| `JAS_SI_GITHUB_RECONCILER_TRIGGER_SECRET` | Secret | Random bearer secret, at least 32 bytes; must match the Cloudflare Worker secret |
| `JAS_SI_GITHUB_RECONCILER_POLL_SECONDS` | Non-secret, optional | Defaults to 15; allowed range 1–300 |

The Vercel Preview hostname must be the actual deployment hostname used for the OAuth callback. Do not guess a deployment URL or use the Production hostname. The OAuth callback must be registered in the GitHub App configuration to match the configured redirect URI exactly.

The Cloudflare Worker separately requires:
- Secret `JAS_SI_GITHUB_RECONCILER_TRIGGER_SECRET`, identical to the Vercel value.
- Variable `JAS_SI_RECONCILER_ENDPOINT`, set to the exact Preview URL ending in `/internal/github/reconcile`.
- Variable `JAS_SI_RECONCILER_ALLOWED_HOST`, set to only that Preview URL's hostname.

Before enabling the Cron Trigger, verify the deployed Preview reports the expected commit and that all required environment keys exist by name (never decrypt or print values). Run the dedicated database identity smoke tests and the negative authorization checks. Then perform a controlled GitHub App test installation and verify OAuth, webhook receipt, pending claim, authoritative repository snapshot, revocation, and audit evidence. Keep real customer repositories out of initial tests; use a disposable test tenant and test repository. A configured environment is not a verified lifecycle.

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
  'jas_si_github_reconciler',
  'jas_si_github_webhook_login',
  'jas_si_github_reconciler_login'
)
ORDER BY rolname;
```

Expected before migration: existing prerequisites must be present. The reconciler capability may be absent before migration 20261207, and the two dedicated GitHub login identities may be absent before migrations 20261208 and 20261209. Do not pre-create these roles with ad hoc attributes; let the reviewed migrations create them. After the migrations, both dedicated login identities are expected to remain NOLOGIN until separately approved credential provisioning.

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
         ('jas_si_github_reconciler'),
         ('jas_si_github_webhook_login'),
         ('jas_si_github_reconciler_login')
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

Expected: reconciler capability, reconciler login, webhook login, worker, and verifier have no direct/effective table privileges on the protected GitHub tables; customer runtime has no direct/effective OAuth-attempt or Installation-claim table privileges. The broad `jas_si_runtime` identity is not the webhook application login and must not be used for webhook processing. Review every non-zero result against the reviewed migration ACLs. The migration's embedded assertion checks selected capability/login privileges; this expanded matrix is an additional rollout gate.

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
- `jas_si_github_reconciler` receives EXECUTE on pending-claim, reconcile-apply, and inbox claim/finish routines; it must not receive EXECUTE on public webhook receive. The login `jas_si_github_reconciler_login` must receive SET-only membership in this capability, not inherited EXECUTE privileges or direct table grants.
- `jas_si_github_webhook_login` receives EXECUTE on webhook receive/claim/finish routines; `jas_si_runtime` must not retain those grants. The webhook login has no direct inbox/audit table access and cannot INHERIT or SET the broad runtime role.
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

For each routine, evaluate `has_function_privilege(role_name, signature, 'EXECUTE')` for the service/capability identities listed above and `PUBLIC`. For `jas_si_github_reconciler_login`, a false result before `SET ROLE jas_si_github_reconciler` is expected; after the application explicitly sets that capability, verify EXECUTE as `current_user`. PUBLIC must be checked from `aclexplode(COALESCE(proacl, acldefault('f', proowner)))`, because a NULL `proacl` means default function privileges, not "no grants".

### 3. Verify real service logins

Catalog checks alone do not prove the host can authenticate or that the application uses the intended role. For each configured service login, connect using the secret manager without exposing the DSN, then run:

```sql
SELECT session_user, current_user,
       pg_has_role(session_user, 'jas_si_github_reconciler', 'MEMBER')
         AS is_reconciler_member,
       pg_has_role(session_user, 'jas_si_github_reconciler', 'SET')
         AS can_set_reconciler;
```

For the reconciler connection, require `session_user=jas_si_github_reconciler_login`, then verify the adapter executes `SET ROLE jas_si_github_reconciler` and that `current_user` changes to that capability. For the webhook connection, require `session_user=jas_si_github_webhook_login`; do not SET or inherit `jas_si_runtime`. Run equivalent checks for worker, verifier, and customer-identity identities. Execute approved positive routine calls only with disposable fixtures. Negative tests must prove direct table reads/writes, broad-runtime access from the webhook login, and unauthorized routine execution fail with permission denial. Do not run a reconciliation mutation against a real Installation as an ACL probe.

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

Before the November 20, 2026 Staging rollout, the branch had been observed without the GitHub integration tables and without the `jas_si_github_reconciler` role. That observation is historical and is superseded by the supplemental post-migration evidence below. Re-run the read-only inventory immediately before any future rollout; this note is not a substitute for a live preflight.

No Staging or Production migration, service login creation, secret configuration, GitHub App setup, webhook registration, Installation activation, or deployment is authorized by this document.


## Supplemental Staging catalog evidence — 2026-11-20

A second read-only catalog pass on Neon Staging branch `br-wandering-bonus-b32u1xg2` refined the membership interpretation above:

- The duplicate-looking owner/capability membership edges have distinct grantors. `cloud_admin` grants `neondb_owner` ADMIN OPTION on several JAS-SI capability/owner roles with `INHERIT=false` and `SET=false`; separate grants made by `neondb_owner` permit it to SET ROLE into selected owner roles. Do not collapse these rows or infer that ADMIN OPTION itself grants role usage. The effective `pg_has_role(..., 'SET')` result can be true because of the separate SET-enabled edge.
- The `jas_si_agent_worker_login` and `jas_si_agent_verifier_login` memberships in their respective capability roles are granted by `neondb_owner`, with `INHERIT=true`, `SET=true`, and no ADMIN OPTION. They inherit the intended worker/verifier capability privileges. `jas_si_customer_identity_login` is a member of `jas_si_customer_runtime` with `INHERIT=false`, `SET=true`, and no ADMIN OPTION; it must explicitly SET ROLE before using that capability.
- The read-only table-grant inventory found direct table grants on existing agent tables for `jas_si_agent_task_owner`, and customer identity tables for `jas_si_customer_identity_owner`; it found no direct table grants to worker/verifier/customer-identity service login roles or their worker/verifier/customer-runtime capability roles. Existing runtime/provisioner grants are limited to the previously inventoried API-key, audit, tenant, and provisioning tables. Recheck effective privileges after GitHub migrations because those introduce new protected objects and routines.
- The current public SECURITY DEFINER routine inventory showed fixed `search_path=pg_catalog` and explicit owner/capability EXECUTE ACLs for the inspected routines; no PUBLIC entry was visible in the listed ACLs. This inventory is not a substitute for the exact-signature PUBLIC/default-ACL and effective privilege checks in the post-migration procedure.
- Existing Staging RLS is mixed: agent task/evidence tables have both RLS and FORCE RLS; API keys and tenants have RLS but not FORCE; other existing customer/session/usage/audit tables inspected have RLS disabled. Record table-by-table expectations and do not treat absence of RLS alone as a confirmed exploit without reviewing ownership, grants, and SECURITY DEFINER boundaries.

This evidence refines catalog interpretation only. It does not authorize changing memberships, default privileges, RLS, or table grants. The Neon-managed `cloud_admin`/ `neondb_owner` delegation remains a provider-boundary review item; distinguish it from application-login membership and confirm intended provider semantics before proposing a change.


## Supplemental Staging evidence — 2026-11-20, read-only catalog recheck

The user explicitly authorized six Staging-only migrations on Neon project `odd-violet-93299575`, branch `br-wandering-bonus-b32u1xg2`: 20261201, 20261202, 20261203, 20261204, 20261206, and 20261207. The earlier rollout record confirms those six were applied. Production was not changed.

A later read-only catalog check on the same branch found the following current state:

- `jas_si_runtime` is LOGIN.
- `jas_si_github_webhook_login` exists as NOLOGIN/NOINHERIT and is a MEMBER of `jas_si_runtime` with INHERIT=false and SET=false. It has direct EXECUTE on the four webhook inbox routines; `jas_si_runtime` itself has no EXECUTE on those four routines.
- `jas_si_github_reconciler` exists as NOLOGIN.
- `jas_si_github_reconciler_login` exists as NOLOGIN/NOINHERIT and is a MEMBER of `jas_si_github_reconciler` with INHERIT=false and SET=true. The reconciler adapter checks `session_user` and explicitly SET ROLE before using its capability.
- Neither dedicated login can authenticate yet; no passwords or dedicated service DSNs have been provisioned.
- The five GitHub integration tables exist. Their last observed row counts were zero; no live GitHub App OAuth, webhook, or Installation lifecycle has been exercised.

Important provenance qualification: the current catalog contains the two login roles and their expected membership/grant boundaries, which correspond to migrations 20261208 and 20261209 in this branch. However, the six-migration authorization record does not establish that those two later migration files were separately approved or applied, and role presence alone is not proof of which migration created them. No migration-history table was identified in the read-only inventory used for this check. Do not describe all eight migrations as applied until their execution provenance is independently established. Do not reapply either migration merely to reconcile documentation.

This evidence establishes catalog identity and ACL state only. It does not prove successful password authentication, host connectivity, OAuth, webhook delivery, or live reconciliation. Those require separately approved Staging credential configuration and independent lifecycle verification. Production remains untouched.
