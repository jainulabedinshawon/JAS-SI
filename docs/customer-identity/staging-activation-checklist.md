# JAS-SI Customer Onboarding — Staging Activation Checklist

**Latest verified audit update: 2026-11-27.** This section supersedes earlier environment/deployment snapshots below; older snapshots remain historical evidence.

## Latest verified state (2026-11-27)

- Current Main observed: `3922dc5a3f82b82da6d89e85b721fec9baa6a4ac`. Current Vercel Production deployment `dpl_8X3FLYpTRKw41qDE7Joo57brBozQ` is READY and Main-aligned. Production `/health`, `/pricing`, and `/plans` each returned HTTP 200. The health route is liveness only; it does not prove customer database or agent runtime readiness.
- Trusted Preview deployment `dpl_4wqihcCG7kwPadEVddb86EawbR3G` is READY at commit `2cf4caca96508b7c79699ccd50410ec18bdca4b8` on `feat/github-oauth-state-pkce-contract-v1`. Preview `/health` and `/customer` returned HTTP 200. These probes do not prove registration, email delivery, session, database, or API-key journeys.
- Vercel environment metadata was read with decryption disabled. `JAS_SI_CUSTOMER_DATABASE_URL`, `JAS_SI_CUSTOMER_API_KEY_DATABASE_URL`, `JAS_SI_CUSTOMER_TOKEN_PEPPER`, and `JAS_SI_GITHUB_WEBHOOK_DATABASE_URL` are Preview-only and restricted to branch `feat/github-oauth-state-pkce-contract-v1`. No secret values were decrypted or changed. This confirms the named-branch scope for these four variables only; it does not prove runtime use or the safety of other Preview variables.
- No customer SMTP host, port, username, password, sender, or public URL variables appeared in the current project environment inventory. Customer email verification and sign-in delivery therefore remain NOT CONFIGURED / NOT VERIFIED.
- The customer portal is served at Preview, but no registration, login, email, session, API-key creation, or customer-data mutation was performed. A protected authenticated customer API fetch could not be independently completed with the available inspection path; do not claim customer journey success.
- PR #153 is Open/Draft at head `7a717c13dbd6e4679c43508ef83e79e656c34ab2`, 26 commits ahead and 0 behind current Main. Its exact-head CI has 18/18 returned checks successful, including PostgreSQL 16 clean migration replay and Broker authorization/replay. A read-only Staging privilege audit found `jas_si_agent_task_owner` had unnecessary table-wide SELECT on all six `jas_si_tenants` columns, while the resolver needs only `tenant_id` and `status`. PR #153 now contains a corrective migration that narrows this privilege and passed clean PostgreSQL 16 replay; **it has not been applied to Neon Staging or Production**. Staging still lacks `jas_si_agent_broker_login`, and no Broker service is deployed.
- This PR #156 branch was last observed at `d156607cc4036e7860d012a7a2c35f03d26c6b1d`, 12 commits ahead and 1 behind current Main, with 9/9 exact-head checks successful. It remains Draft; its base is behind current Main and its documentation must not be treated as merge-ready until rechecked after this update.
- Neon Staging and Production branches are Ready but unprotected. Staging task/evidence tables have RLS and FORCE RLS enabled; task and evidence row counts are zero. The task-owner broad SELECT finding above remains live until the corrective migration is separately authorized and applied. Production has no Agent runtime roles or task/evidence schema.
- Render workspace `tea-dbpl9vmi0phs73cc9b0g` currently returns an empty service list. Worker, Verifier, and Broker are NOT DEPLOYED / NOT VERIFIED. No paid compute was created.
- Production `/plans` reports payment status `not_connected`; Free is purchasable, while Starter, Pro, and Enterprise remain non-purchasable. No provider-integrated durable ledger, independent payment verification, reconciliation, refunds/disputes, or entitlement enforcement is established.
- No Vercel environment value, Neon role/schema/grant/data, customer record, Production setting, Render service, payment setting, or live transaction was changed during this audit.

This is an operator handoff, not a declaration that customer onboarding or the Agent Runtime is live. Keep customer onboarding and Paid Plans gated until authenticated database connectivity, SMTP delivery, complete customer lifecycle, tenant isolation, and independent staging verification are established.

**Historical status (2026-11-14): onboarding code was merged and deployed; live customer activation was blocked by missing dedicated runtime credentials and SMTP configuration.**  
This checklist is an operator handoff. It is not authorization to change Vercel, Neon, Production, payment settings, or customer data.

## Historical Production evidence (2026-11-14)

Customer onboarding code from PR #36 is merged into `main` (merge commit `d5f68af0cb31f834472202ec1dea77994b9be81c`). The current Production deployment is READY at commit `e55bc006658647a97ce9e69c7f8fa62b70e9a660` (deployment `dpl_EY8AsWXwyvEFeRABTnPUoWdkqBZQ`).

Read-only live checks returned:
- `GET /health`: HTTP 200, API enabled.
- `GET /customer`: HTTP 200; the standalone portal HTML is served.
- `GET /openapi.json`: HTTP 200; customer identity, session, usage and API-key routes are registered.
- `GET /plans`: HTTP 200; Free exposes 100 technical units by default, while paid tiers are non-purchasable and payment status is `not_connected`.

These checks prove deployment and route availability only. They do not prove registration, email delivery, session creation, API-key issuance, or customer usage end-to-end.

A read-only Production Vercel environment metadata check found no `JAS_SI_CUSTOMER_*` variables. In Production Neon, `jas_si_customer_runtime` and `jas_si_customer_key_runtime` are NOLOGIN group roles, but no dedicated customer LOGIN principals were present in the inspected `jas_si_*` role set. SMTP host/sender/credentials are also absent. Therefore the portal is visible but its customer backend is not activated; do not invite customers or claim self-service onboarding is live.

No secrets were decrypted. No customer registration request, email, or test account was created during these checks.

### Historical Preview configuration snapshot (2026-11-15)

Read-only Vercel metadata now shows the dedicated customer identity DSN, customer API-key DSN, and customer session pepper scoped to Preview only. No customer SMTP host/sender/credential variables are configured. These partial Preview settings do not establish that email verification or login works. Production still has none of the dedicated customer identity/key variables. Do not enable customer signup or invite customers until SMTP, role boundaries, the complete journey, and independent staging checks pass.

## What is merged into main

- Customer registration, email verification, magic-link login, and secure session cookies.
- PostgreSQL-backed shared registration/login abuse limiting.
- Tenant-scoped API-key create/list/revoke routines.
- Tenant-scoped technical usage summary and keyset-paginated history.
- Free technical quota reservation.
- Public plan catalogue; paid tiers remain preview-only.
- Customer email adapter using SMTP STARTTLS (or SMTP-over-TLS on port 465).

Passing CI is evidence for tested code paths, not evidence that external runtime services or a live customer journey are configured.

Both layers are now PostgreSQL-backed and shared across application instances, with separate HMAC namespaces and dedicated least-privilege database boundaries:
- Customer registration/login email-abuse limiter: dedicated customer rate-limit table and runtime boundary.
- General versioned API ingress limiter: `jas_si_api_rate_limits`, migration `20261118_shared_api_rate_limits.sql`, and a separate `JAS_SI_API_RATE_LIMIT_PEPPER`.

The general API limiter applies to all `/v1/*` routes, including customer portal API routes; customer registration/login additionally retain the stricter email-abuse limiter. Preview/Production startup must fail unless the shared API limiter pepper, database connection, schema, and privilege boundary verify successfully. Tests cover cross-request behavior, trusted proxy handling, expiry/retry semantics, and denial of direct runtime table access. Live behavior behind the actual Vercel proxy remains unverified until an isolated Preview is configured and exercised.

## Configuration audit result

The latest read-only Production environment metadata check found no customer-specific variables. The following must be provisioned before activation; values must be stored as encrypted/sensitive Vercel variables and never committed:

- `JAS_SI_CUSTOMER_DATABASE_URL`
- `JAS_SI_CUSTOMER_API_KEY_DATABASE_URL`
- `JAS_SI_CUSTOMER_TOKEN_PEPPER`
- `JAS_SI_CUSTOMER_SMTP_HOST`
- `JAS_SI_CUSTOMER_SMTP_PORT`
- `JAS_SI_CUSTOMER_SMTP_USERNAME`
- `JAS_SI_CUSTOMER_SMTP_PASSWORD`
- `JAS_SI_CUSTOMER_SMTP_SENDER`
- `JAS_SI_CUSTOMER_PUBLIC_URL`

The inspected Production environment does contain `JAS_SI_API_RATE_LIMIT_PEPPER`, `JAS_SI_DATABASE_URL`, and `JAS_SI_API_KEY_PEPPER`. Those general API variables do not replace the dedicated customer identity and customer API-key database connections or the customer session pepper. Do not point the customer DSNs at a database owner, provisioner, superuser, or general API runtime connection.

No secret values were decrypted or read during this audit.

## Migration-chain integrity invariant (2026-11-26)

The Main-branch clean replay workflow treats every canonical security and Agent Worker/Verifier migration as required input. Missing migration files must fail CI before SQL execution; they must never be silently skipped as an optional migration. The workflow replays the complete ordered chain twice from a clean PostgreSQL 16 database and then checks the resulting least-privilege boundaries. A green replay is evidence only for the exact workflow commit and migration files in that checkout; it is not evidence that a live Neon branch has been migrated or that a production runtime is deployed.

The mandatory security/agent sequence begins with the customer identity/API-key ACL and audit/rate-limit writer boundaries (20261119–20261122), continues through task scope, task store and worker lifecycle (20261123–20261124), then proceeds through usage scope, failure handling, evidence finalization, verifier claims, default ACLs, active-tenant guard and inconclusive/human-review lifecycle (20261125–20261201). The workflow's explicit ordered list is authoritative; do not infer applied migration state from filenames or table presence alone.

## Agent host liveness and readiness verification

The Worker and independent Verifier supervisors expose local `/health` liveness and `/ready` readiness endpoints. Liveness only confirms the process HTTP handler is responding. Readiness remains HTTP 503 until the host completes a successful database-backed poll; a later poll failure returns readiness to 503. The Main Docker Container Verification workflow exercises the Worker health server inside the locked application image, checks the not-ready-to-ready transition, and verifies the image health check. Unit tests separately cover Worker and Verifier supervisor state transitions. These checks do not prove that a live Render service is deployed or that a real Staging DSN is configured.

## Staging prerequisites

Complete these in an isolated, disposable Neon staging branch — never against Production as part of this checklist:

1. Create separate least-privilege LOGIN principals for customer identity and customer API-key connections.
2. Grant each login only its corresponding NOLOGIN runtime group role. Do not grant provisioner, owner, general API runtime, or superuser memberships.
3. Apply the migrations in the exact dependency order documented in `customer-api-key-runtime-setup.md`, including the API-key authentication and usage-routine migrations. Apply `20261117_runtime_usage_routine_only.sql` only after `20261116_api_key_bound_usage_routines.sql`; verify the API still records usage and reads summary/quota/history through authenticated routines while both `jas_si_runtime` and `jas_si_provisioner` have no direct or inherited usage-table privileges. Inspect existing objects and ACLs; `IF NOT EXISTS` is not proof of schema correctness.
4. Verify the effective `current_user`, `session_user`, role flags, memberships, schema privileges, table/column ACLs, SECURITY DEFINER owners, fixed search paths, RLS policies, and cross-tenant denial.
5. Generate a fresh random customer session pepper (at least 32 UTF-8 bytes) in the approved secret manager. Do not reuse the API-key pepper.
6. Configure the dedicated customer DSNs and customer session pepper only for the exact PR preview branch after the isolated database roles and routines have been verified.
7. Configure SMTP credentials and sender identity using a verified sender domain. Use STARTTLS on the provider's supported submission port or implicit TLS on port 465. Never log tokens, recipients, passwords, or full DSNs.
8. Set the customer public URL to the exact HTTPS preview origin. Do not point preview links at the production customer portal.
9. Configure the dedicated API ingress pepper for the Preview branch and verify the shared limiter startup boundary; keep customer registration disabled until all identity, email, rate-limiter, session, API-key, usage, and tenant-isolation checks pass.
10. Run the customer journey in this order: register → receive email → verify → request login → receive email → sign in → view account → create API key → make authorized API request → view usage and history → revoke key → confirm revoked key is rejected → log out → confirm session is rejected.
11. Confirm SMTP delivery, generic responses for unknown emails, rate-limit behavior across instances, CSRF protection, cookie flags, tenant isolation, and audit evidence.
12. Capture sanitized evidence (test IDs, HTTP status codes, role names, migration versions, and timestamps); never capture credentials, one-time tokens, session cookies, or raw API keys.

## Required Vercel Preview variables

Only add these after the isolated staging database and sender identity exist. Scope every variable to the intended Preview branch; do not add them globally or to Production by default.

| Variable | Purpose |
|---|---|
| `JAS_SI_CUSTOMER_DATABASE_URL` | Customer identity + session + shared abuse-limiter runtime role |
| `JAS_SI_CUSTOMER_API_KEY_DATABASE_URL` | Separate customer API-key self-service runtime role |
| `JAS_SI_CUSTOMER_TOKEN_PEPPER` | Independent customer session/link/IP HMAC pepper |
| `JAS_SI_CUSTOMER_SMTP_HOST` | SMTP provider host |
| `JAS_SI_CUSTOMER_SMTP_PORT` | Submission port (587 or provider-approved TLS port; 465 uses implicit TLS) |
| `JAS_SI_CUSTOMER_SMTP_USERNAME` | Optional provider username |
| `JAS_SI_CUSTOMER_SMTP_PASSWORD` | Optional provider password; set together with username |
| `JAS_SI_CUSTOMER_SMTP_SENDER` | Verified sender address |
| `JAS_SI_CUSTOMER_PUBLIC_URL` | Exact HTTPS preview origin |

The existing Vercel `VERCEL_ENV` fallback determines Preview/Production cookie and trusted-proxy behavior unless `JAS_SI_ENVIRONMENT` is explicitly overridden. Do not override a Preview deployment to development or test.

## Billing and entitlement boundary

JAS-SI is designed to operate as an independent standalone SaaS first. Under ADR-002, each tenant has exactly one server-controlled commerce authority:
- `jas_si_standalone`: JAS-SI will own its provider adapter, order snapshots, verified provider-event inbox, minimal reconciliation ledger, subscription/payment lifecycle, and authoritative paid entitlement for that tenant.
- `jas_platform_linked`: JAS Platform owns checkout, payments, financial records and paid entitlements; JAS-SI consumes an authenticated, tenant-bound entitlement decision.

The authority is selected only from trusted server-side tenant configuration. A tenant must never have both authorities active. ADR-002 is the current architecture authority; the Billing Core v0.1 and manual TrxID documents are historical context where they conflict.

No payment provider, hosted checkout, financial ledger, paid entitlement or manual TrxID collection is active in this PR. The plan catalogue is descriptive; Starter, Pro and Enterprise remain non-purchasable until a provider is selected, sandbox reconciliation passes, prices/unit economics are approved, and separate production authorization is granted.

Do not collect card details in JAS-SI, publish unverified prices, accept browser-supplied payment claims, or mark an account paid from a client request. For standalone mode, only server-verified provider events or authenticated provider lookups may establish payment state. For Platform-linked mode, require an authenticated entitlement response with tenant binding, expiry/revocation semantics, replay protection, audit evidence and tests for downgrade/refund/chargeback outcomes. Never dual-write financial state.

## Explicit approval gates

This checklist does not authorize:
- Production schema migrations or role/grant changes.
- Production environment-variable changes or secret rotation.
- Vercel deployment/redeployment or project setting changes.
- PR merge.
- Payment-provider activation, charges, refunds, or live paid entitlements.

Those actions require a separate review and explicit approval. If a staging migration fails, stop, preserve logs/state, and use a reviewed recovery plan validated on a disposable database; do not improvise destructive rollback SQL.


## Master directive live-audit correction — 2026-11-27

This read-only audit snapshot supersedes conflicting earlier status statements. No secret values were decrypted.

### Current infrastructure evidence

- Main: `a561acf101137fa92e0fc50da4e06fc63edc0dda`.
- Vercel Production deployment `dpl_Kr2gGNMt6qXbnPtR2Pjb6etwtNqv` is READY on that Main SHA.
- Vercel Preview deployment `dpl_4wqihcCG7kwPadEVddb86EawbR3G` is READY on `feat/github-oauth-state-pkce-contract-v1`, SHA `2cf4caca96508b7c79699ccd50410ec18bdca4b8`. This proves deployment build, not runtime readiness.
- Production and Preview runtime log queries for the latest 30 minutes returned no records; health remains unverified.
- Preview customer database, customer API-key database, token pepper, and GitHub webhook database variables are Preview-only and branch-scoped to the inspected branch. Production-targeted customer DB/API-key DSNs and customer token pepper were not found. Secret values were not read.
- Render service inventory is empty. No Worker, Verifier, Broker, or reconciler service is deployed.

### GitHub PR state

- PR #100: Open, Draft, Mergeable; head `2cf4caca96508b7c79699ccd50410ec18bdca4b8`, base branch `feat/github-installation-user-ownership-proof-v1`. It is 288 commits ahead / 0 behind its base at comparison time. Historical PR narrative is not live runtime evidence.
- PR #153: Open, Draft, Mergeable; head `6a25b4758cd8192b6c5d5ec66bc7326f86c1e5c1`; 17 commits ahead / 2 behind Main at comparison time. Do not merge without dependency/rebase review and exact-head checks.
- PR #156: Open, Draft, Mergeable; head `fa9049be9bc9c6dc777543529df75f674c735eef`. Seven exact-head workflow runs were independently retrieved in this audit and all completed successfully (Dependency Lock, Vercel Python 3.12 Compatibility, Core Package Validation, Post-Merge Security Verification, Docker Container Verification, Agent Authorization Tests, Security Event Persistence Verification). No merge was performed.
- Main combined status reports Vercel success. PR #100 combined status reports Vercel success only; this is not equivalent to all workflow tests passing.

### Neon read-only catalog

Project `odd-violet-93299575`:
- Staging `br-wandering-bonus-b32u1xg2`: 18 application tables, 7 with RLS disabled.
- Production `br-silent-moon-b3mwkv8u`: 11 application tables, 7 with RLS disabled.
- Staging has Worker and Verifier LOGIN principals and their separate NOLOGIN capability roles. Memberships are SET-only (`inherit_option=false`, `set_option=true`).
- Staging GitHub webhook LOGIN is a member of `jas_si_runtime` with both inheritance and SET disabled; reconciler LOGIN has SET-only membership in its dedicated capability role.
- No dedicated Broker LOGIN exists. Production has no Worker, Verifier, Broker, GitHub webhook, or reconciler LOGIN principals.
- Staging RLS-disabled tables: `jas_si_api_rate_limits`, `jas_si_customer_accounts`, `jas_si_customer_auth_tokens`, `jas_si_customer_rate_limits`, `jas_si_customer_sessions`, `jas_si_github_oauth_attempts`, `jas_si_usage_events`.
- Production RLS-disabled tables: `jas_si_api_key_provisioning_runs`, `jas_si_api_rate_limits`, `jas_si_customer_accounts`, `jas_si_customer_auth_tokens`, `jas_si_customer_rate_limits`, `jas_si_customer_sessions`, `jas_si_usage_events`.
- Both branches report `protected=false`. RLS-disabled status is a hardening gap, not standalone proof of cross-tenant exposure. No role, grant, schema, policy, data, or credential was changed.

### Billing and commercial status

- Main `billing_core.py` is an in-memory domain/test foundation, not a durable production ledger.
- Main `billing_catalog.py` keeps Starter, Pro, Enterprise non-purchasable; payment status is `not_connected`.
- Neither Neon branch contains payment, ledger, subscription, refund/dispute, or entitlement tables.
- Durable provider verification, append-only ledger, reconciliation, and entitlement enforcement are not established. Paid plans must remain non-purchasable.

### Completion status

- Vercel Preview build: READY; runtime database readiness: UNVERIFIED.
- GitHub OAuth/webhook/installation lifecycle: NOT STAGING VERIFIED.
- Worker/Verifier/Broker runtime: NOT DEPLOYED.
- Tenant RLS hardening: INCOMPLETE.
- Durable payment/billing: NOT IMPLEMENTED as an integrated system.
- Paid Commercial Launch: BLOCKED.

No Production operation, migration, credential change, paid resource, financial transaction, customer action, or PR merge was performed.


## Follow-up database authorization review — 2026-11-27

A second read-only pass inspected table ACLs, RLS policy catalog, function ACLs and selected SECURITY DEFINER function bodies on both Neon branches.

### Customer table access boundary

- The following customer-related tables have RLS disabled and no row policies in either branch: `jas_si_customer_accounts`, `jas_si_customer_auth_tokens`, `jas_si_customer_sessions`, `jas_si_customer_rate_limits`, `jas_si_api_rate_limits`, and `jas_si_usage_events`. Staging additionally has RLS disabled on `jas_si_github_oauth_attempts`; Production does not contain that table.
- Despite RLS being disabled, the inspected application roles `jas_si_customer_runtime` and broad `jas_si_runtime` have no direct SELECT privilege on these customer tables. Customer Runtime also has no direct INSERT or UPDATE privilege on the inspected account/session/token tables.
- Direct account, token and session table SELECT is granted to the NOLOGIN `jas_si_customer_identity_owner` capability role; that is not a customer-facing LOGIN identity. The customer rate-limit tables are owned by their NOLOGIN dedicated owner role. `neondb_owner` retains owner-level privileges.
- The inspected customer-facing SECURITY DEFINER routines are owned by dedicated NOLOGIN owner roles, set `search_path=pg_catalog`, and are not executable by PUBLIC. The Customer Runtime capability role has EXECUTE on the intended session and customer identity routines, while API-key issuance/list/revocation routines are separately owned by `jas_si_customer_key_owner` and not executable by Customer Runtime in the catalog.
- `customer_authenticate_session` validates a non-null 32-byte session digest, unrevoked/unexpired session, active account and active tenant. `customer_usage_events` and `customer_usage_summary` derive tenant identity from the authenticated session and constrain usage queries by that tenant. `customer_api_key_issue/list/revoke` similarly derive tenant identity from an active session before accessing API-key records.
- These checks reduce the immediate direct-table exposure concern, but RLS remains a defense-in-depth gap and must not be dismissed. Future RLS enablement requires explicit per-owner policies and regression testing of every SECURITY DEFINER routine; enabling RLS without understanding function owners and FORCE RLS behavior could break legitimate flows or create accidental bypasses.

### Runtime principal readiness

- Staging has `jas_si_customer_runtime` as NOLOGIN, plus separate NOLOGIN identity/key/rate-limit owner roles. It does not have a dedicated customer-runtime LOGIN principal in the inspected role set.
- Production likewise has only the NOLOGIN `jas_si_customer_runtime` capability role and NOLOGIN owner roles; no customer-runtime LOGIN principal was present.
- Staging has GitHub webhook and reconciler LOGIN principals, both NOINHERIT and non-privileged; Production has neither.
- The GitHub task capability Broker role is present in Staging as NOLOGIN; no Broker LOGIN is present. Production has neither the Broker capability role nor Broker LOGIN.

### Migration-history limitation

- No application migration/version ledger table was found in either Neon branch by read-only table inventory. This does not mean migrations were not applied; it means the current live database cannot independently prove the ordered migration history from a conventional migration ledger.
- The live schema, role, grant and function catalogs are direct current-state evidence. CI migration replay is separate evidence and must not be presented as proof that the exact chain was applied to live Staging or Production.

### Security assessment correction

The earlier shorthand “seven RLS-disabled tables” remains factually correct, but must not be interpreted as evidence that ordinary application roles can directly read those tables. The catalog currently shows a restricted function-mediated access design. The remaining gap is defense-in-depth, missing customer-runtime LOGIN/configuration in Production, and absence of complete end-to-end runtime proof. No DDL, DML, grant, role, policy, secret, or migration was changed in this review.


## Agent runtime dependency and PR readiness review — 2026-11-27

A fresh GitHub read-only review checked PR #80 and its stacked runtime dependents #91–#93 against the current Main branch.

### Durable Agent Task Store PR #80

- PR #80 remains Open and Draft. Its current head is `1dd2d0cc2e854f18c414e39393629b65057854db`; its recorded base SHA is `9625905db7a8f9ffab151995e4b8a475b0de405a`.
- Main is currently `a561acf101137fa92e0fc50da4e06fc63edc0dda`. The comparison reports a diverged history: PR #80 is 234 commits ahead and 44 commits behind Main, with the old SHA as merge base. GitHub currently reports the PR as not mergeable.
- No PR-triggered workflow runs and no combined commit statuses were returned for the current PR #80 head. This is absence of CI evidence, not a passing result.
- PR #80 contains durable task storage, worker and verifier lifecycle adapters, multiple migrations, API routes, Render worker/verifier declarations and integration tests. It is a substantial stacked implementation, not a small isolated change.
- The migration replay workflow explicitly includes the future-dated `20261201_agent_task_verifier_inconclusive_lifecycle.sql`. The migration's retry-exhaustion-to-human-review behavior is aligned with fail-closed verification, but its date and inclusion order must be reviewed as part of canonical migration sequencing before any merge.
- The PR's Render manifest declares Worker and Verifier services only; it does not establish that either service has been deployed or that a Broker runtime exists.

### Stacked dependents

- PR #91 targets `feat/durable-agent-task-store-v1` (PR #80's branch).
- PR #92 targets PR #91's branch.
- PR #93 targets PR #92's branch.
- Each dependent is therefore blocked on reconciling and validating the root PR #80 against current Main. Their individual branch-level mergeability does not make them independently mergeable to Main.
- Do not retarget or merge the dependents directly to Main, and do not treat their branch mergeability as evidence that the entire stack is ready.

### Current decision

PR #80 and #91–#93 remain unmerged and Draft. The next safe engineering action is a controlled reconciliation of the root task-store branch with current Main, followed by exact-head CI (including clean PostgreSQL migration replay and agent-task tests), security review of the complete diff, and renewed dependent-branch checks. No branch rebase/force-push, migration, database write, deployment, or PR merge was performed during this audit.


## Continuation audit — live infrastructure and billing evidence (2026-11-27, evening Bangladesh time)

This continuation refreshed repository, PR, deployment, Neon branch, and Render service evidence.

### Repository and PR state

- Main remains at `a561acf101137fa92e0fc50da4e06fc63edc0dda`; the latest repository commit search returned this SHA.
- Main's combined status currently reports the Vercel check as successful. This is not a complete repository-wide CI matrix.
- PR #156 is Open/Draft at `0c5154acaf52d43e64b9208fa7c3f17eec22108e`; all seven returned PR workflows completed successfully at that exact head.
- PR #157 (bKash PRA SaaS exclusion) is Open/Draft, based on current Main, and reports mergeable. Its exact head is `d6be92827406f2bc9e7cf0621f9b23f4351dda13`; all seven returned PR workflows completed successfully at that exact head. The PR remains Draft and was not merged.
- PR #80 remains Open/Draft and non-mergeable; head `1dd2d0cc2e854f18c414e39393629b65057854db`, base SHA `9625905db7a8f9ffab151995e4b8a475b0de405a`. The #91–#93 stacked dependency chain remains rooted on this branch. No merge/rebase/force-push was attempted.
- PR #153 remains Draft; it is based on an older Broker prerequisite commit and is not evidence of an integrated or deployed Broker.

### Deployment and database

- Vercel production deployment is READY at Main SHA `a561acf101137fa92e0fc50da4e06fc63edc0dda`. This confirms deployment of that commit only; it does not establish Agent, customer-authenticated API, billing, or production end-to-end readiness.
- Neon project `odd-violet-93299575` currently reports staging branch `br-wandering-bonus-b32u1xg2` READY and production branch `br-silent-moon-b3mwkv8u` READY. Neither branch is protected in the current branch metadata.
- Read-only catalog counts returned 18 `jas_si_*` base tables in staging and 11 in production. Counts alone do not prove migration-chain consistency, RLS safety, runtime principal readiness, or payment readiness.
- Render workspace `tea-dbpl9vmi0phs73cc9b0g` returned an empty service list. Worker, Verifier, and Broker remain NOT DEPLOYED / NOT VERIFIED.

### Billing provider evidence

- PR #157 records the owner-provided written bKash support decision: PRA is not the SaaS API collection route; evaluate only a Regular Merchant Account or officially approved gateway with SaaS acceptance and server-side verification confirmed.
- No provider account, credentials, payment collection, paid service, or production checkout was activated.
- Durable append-only payment ledger, verified provider events, reconciliation, refund/dispute lifecycle, and entitlement enforcement remain NOT IMPLEMENTED / NOT STAGING VERIFIED. Paid plans remain non-purchasable.

### Execution outcome

This audit was read-only except for this documentation update on the existing PR #156 branch. No production migration, database write, service creation, deployment trigger, secret operation, or PR merge was performed.


## Exact-head CI and billing implementation inspection — 2026-11-27

### Documentation branch verification

The latest documentation branch head is `8cf32e16101dc837bcb5b5eaef477ce76febcb73`. A fresh GitHub workflow query now returns seven PR workflows, all completed successfully at that exact SHA:

- Core Package Validation — success
- Vercel Python 3.12 Compatibility — success
- Agent Authorization Tests — success
- Post-Merge Security Verification — success
- Security Event Persistence Verification — success
- Docker Container Verification — success
- Dependency Lock Verification — success

This is exact-head CI evidence for the documentation branch; it is not a merge or production verification.

### Billing code-to-infrastructure status

A current Main read of `src/jas_si_agent/billing_core.py` (blob SHA `87a6d9b2d8aa50732f8af18c6e75832389bed6c9`) confirms the module explicitly describes itself as an in-memory domain/test foundation, with no database, network, payment-provider, or credential handling.

The file contains domain primitives for immutable order snapshots, payment/order amount-currency matching, allowed state transitions, and an in-memory credit ledger with idempotency support. Its own module/class documentation explicitly states that the in-memory ledger is not durable, not multi-process safe, and requires transactional PostgreSQL persistence, row-level concurrency control, durable audit, and tenant authorization for production.

**Classification:** billing domain foundation is IMPLEMENTED in source and covered by existing CI/domain tests where applicable; a production payment adapter, durable financial ledger, provider event verification, reconciliation, refunds/disputes, and entitlement enforcement are NOT VERIFIED by this source file. No claim of integrated or staging-verified billing is made.

### Runtime priority remains unchanged

PR #80 remains the root durable-task integration blocker; its diverged/non-mergeable state prevents safe progression of stacked PRs #91–#93. Render still reports no services. No migration, deployment, payment account, credential, or financial operation was performed.
