# JAS-SI — Master Engineering, Product & SaaS Execution Directive

**Version:** 1.1  
**Status:** Binding execution directive; implementation and release status must always be evidence-based.  
**Scope:** Research integrity, core engineering, product delivery, standalone SaaS, security, operations and commercial readiness.

## 1. Mission and non-negotiable outcome

Build JAS-SI as a real, secure, useful, internationally accessible AI-intelligence product and standalone SaaS service—not merely a research repository, chatbot, demo, collection of modules, CI project or expanding codebase.

JAS-SI's core thesis remains:

> JAS-SI is a reality-based intelligence architecture in which AI reasons about what can be done, acts only within authorization, verifies what actually happened through independent evidence, and learns from verified outcomes under accountable governance.

The engineering objective is a customer-usable service that can be independently evaluated. Do not claim “#1”, production readiness, commercial readiness, feature completion or 100% completion without comparative evidence and explicit acceptance tests. “#1” is an aspiration, not a factual status.

## 2. Binding project principles

Preserve the established JAS-SI intelligence loop:

**Perceive → Understand → Reason → Simulate → Plan → Act → Verify → Learn**

Preserve the governance chain:

**Capability → Authorization → Action → Verification → Accountability**

Rules:
- Authorization gates Action.
- Simulation is not verification.
- An agent report is not proof of reality.
- Verification must use relevant evidence that is sufficiently independent of the claim being checked.
- Unknown or inconclusive outcomes must remain unknown; never relabel them as success.
- Learning must use verified outcomes and preserve failure evidence.
- STOP, PAUSE, revocation and correction must be enforced across the actual execution boundary, not merely represented in UI or helper functions.
- Keep capability, authorization, execution, evidence collection, verification, audit and learning connected through tested contracts.

## 3. Authority, baselines and change control

Before changing code, inspect and respect the repository's governing documents and current implementation.

- Preserve JAS-SI 1.0 baseline and Master Research & Engineering Workflow v2.2 FINAL/FROZEN.
- Benchmark v0.1 is NOT FROZEN until its specified gates and freeze criteria have passed.
- Do not silently change frozen research definitions, benchmark ground truth, statistical rules or evaluation order.
- Preserve JAS-JESI Master Version 1.0 methodology, production formula, weights, Python 3.10 baseline and validation sequence where applicable. JAS-SI experiments and synthetic Mini-JESI fixtures must not modify or be represented as validation of production JESI.
- Follow the current standalone-first commerce decision in `docs/billing/ADR-002-standalone-first-international-commerce.md`. Resolve conflicts in favor of the current ADR, not superseded historical billing documents.
- Proposals, documentation, code, tests, staging results and production evidence are distinct states. A newer file or commit does not automatically override a frozen decision.

## 4. Mandatory end-to-end audit scope

Start with a read-only, evidence-gathering audit. Review the current default branch, repository tree, all open and relevant closed PRs, branches, commits, CI runs, workflow artifacts, deployment configuration and available connected service evidence. Do not assume access to Vercel, database or production state unless the relevant connector or authenticated evidence is available. Clearly label inaccessible areas as NOT VERIFIED; never infer their state.

Audit these domains:

### A. Core architecture and execution
- Orchestrator, task lifecycle, context, persistent memory and recovery.
- Perception, reasoning, simulation, planning and tool interfaces.
- Authorization → execution → evidence collection → verification → audit → learning.
- Real execution boundary and external side effects.
- STOP/PAUSE, revocation, timeout, retry, idempotency, concurrency and crash recovery.
- API contracts, SDK compatibility, error semantics and integration boundaries.

### B. Security and data
- Tenant isolation, RLS, database roles, grants, ownership and privilege escalation.
- Customer identity, sessions, cookies, CSRF, email verification and token lifecycle.
- API key generation, storage, hashing, rotation, revocation, scope enforcement and leakage.
- Secret management, environment separation, rate limits and abuse controls.
- Migration ordering, drift, rollback/recovery, backups and least privilege.
- Audit integrity, append-only guarantees, event provenance and failure behavior.
- Data minimization, retention, privacy and safe logging.

### C. Benchmark and scientific validity
- Ground-truth leakage and oracle separation.
- Label validity, task ambiguity and evaluator correctness.
- Seed independence, deterministic replay and reproducibility.
- Baseline fairness, task coverage, sample-size assumptions and statistical validity.
- False-success definitions and denominators; undefined metrics must remain undefined.
- Evidence independence, adversarial authorization, prompt injection and external action-path coverage.
- P0–P10 protocol order, freeze criteria, artifact provenance and claims discipline.
- Separate unit, integration, pilot, benchmark and production evidence.

### D. Product, SaaS and customer journey
- Public landing page and developer console.
- Registration, email verification, sign-in, session persistence and logout.
- Customer portal, API-key self-service, revocation and rotation.
- Developer docs, OpenAPI contract, SDKs and usable quickstart.
- API authorization, verification, evidence integration and tenant-scoped access.
- Usage metering, idempotency, usage visibility, quota and entitlement enforcement.
- Free plan onboarding and actual usable free-tier service.
- Billing ownership, payment verification, paid entitlements, invoices/refunds only within the approved commerce boundary.
- Support, customer communication, service limits and operational status.

### E. Deployment and operations
- Vercel/project configuration, domains, environment variables and preview/production separation where access exists.
- Database connectivity, migration state, backup and recovery evidence.
- CI reliability, workflow permissions, concurrency, stale-push protection and artifact retention.
- Monitoring, alerting, logs, incident response, dependency/security scanning and rollback.
- Resource consumption, quotas, build frequency and deployment duplication.

## 5. Audit ledger and defect handling

Create and maintain one authoritative audit ledger. Classify each finding as:
- PASS — verified against explicit evidence.
- PARTIAL — some criteria pass; remaining criteria are listed.
- FAIL — defect or acceptance failure confirmed.
- MISSING — required capability or evidence does not exist.
- NOT VERIFIED — evidence or access is unavailable.
- BLOCKED — progress depends on a named external prerequisite or approval.

For every defect record:
1. Unique ID and severity (Critical/High/Medium/Low).
2. Affected component and exact file/route/migration/workflow.
3. Reproduction steps and observed evidence.
4. Expected behavior and impact.
5. Root cause, not just symptom.
6. Smallest safe correction.
7. Regression and security tests.
8. Independent retest result tied to exact commit SHA and CI run/artifact.
9. Deployment status and remaining risk.

Fix confirmed defects in focused, reviewable changes. Do not create a new implementation before inspecting and reusing the existing one. Avoid broad refactors during defect correction. Do not close a finding merely because a PR merged or CI passed; verify the original failure condition is resolved.

## 6. Standalone-first international SaaS strategy

JAS-SI must be independently usable and launchable as a standalone SaaS product. It must not wait for full JAS Platform integration.

### Standalone capabilities
- Independent customer identity and onboarding.
- Customer/developer portal.
- API and secure API-key lifecycle.
- Tenant isolation and service authorization.
- Usage metering and customer-visible usage.
- A real, bounded Free Plan with explicit limits and enforceable entitlements.
- Support and service documentation.
- Clear upgrade path to paid service when commercial prerequisites are met.

### International-first
International customers are the primary market objective. Prioritize international developer experience, clear English-language product documentation, reliable HTTPS access, time-zone-safe operations, transparent service limits, privacy/security practices and a maintainable global service architecture. Foreign-currency revenue is a commercial priority, not permission to claim that payment collection is active.

### Free launch vs paid commercial launch
Treat these as separate readiness milestones.

**Free launch** requires a real customer journey: account creation, verification, sign-in, API key issuance, successful bounded API use, usage visibility, quota enforcement, support information and security controls. The free plan must be usable, not just a pricing label.

**Paid commercial launch** additionally requires a verified merchant/payment-provider arrangement, secure checkout/payment flow, server-side payment verification, authoritative financial records, refunds/disputes handling where applicable, entitlement grant/revocation, reconciliation, customer receipts/invoices as required, support and legal/compliance review appropriate to the operating jurisdictions.

Until these conditions are actually configured and tested, paid plans must be marked unavailable/not purchasable. Never simulate payment success or grant paid entitlement based on a browser redirect, screenshot or caller-supplied claim.

## 7. Commerce and ownership boundary

Follow ADR-002:
- JAS-SI is a standalone tenant-scoped intelligence service.
- JAS Platform may optionally provide central commerce/entitlement authority in the future.
- Do not build a duplicate checkout, payment processor integration, subscription authority, refund engine or authoritative financial ledger inside JAS-SI where ADR-002 assigns those functions elsewhere.
- JAS-SI may own usage events, technical metering, service limits and entitlement enforcement based on trusted, authenticated entitlement data.
- Keep identity, billing, entitlement and usage as clearly separated domains with explicit, versioned integration contracts.
- Do not treat in-memory credit experiments as durable balances or proof of paid access.
- Manual payment may only be introduced through a separately reviewed, auditable and operationally supportable design; it is not automatically enabled by documentation.

## 8. Engineering execution order

Work one bounded unit at a time; verify it before starting unrelated feature work.

1. **P0 — Baseline and read-only audit:** establish exact default-branch commit, open PR/branch inventory, CI status, deployment/service access and current feature matrix.
2. **P1 — Critical defects and architecture integrity:** resolve security, data integrity, authorization bypass, migration drift and broken contracts.
3. **P2 — Core intelligence path:** connect orchestration, authorized execution, independent evidence, verification, audit and verified learning.
4. **P3 — API and tenant foundation:** validate identity, sessions, tenant context, key lifecycle, scopes, rate limits and API contracts.
5. **P4 — Standalone Free SaaS:** complete and test the full customer journey, developer experience, usage and free entitlements.
6. **P5 — Paid readiness assessment:** identify provider, jurisdiction, merchant, payment, financial, tax and operational prerequisites; implement only within approved ownership boundaries.
7. **P6 — Production readiness:** deployment, monitoring, recovery, incident response, security and operational validation.
8. **P7 — Benchmark and research:** complete protocol stages in their required order, independent retesting, freeze and comparative evaluation.
9. **P8 — Release decision:** separate internal prototype, private pilot, public free launch and paid commercial launch gates.

The order may be adjusted only when a confirmed critical dependency or security issue requires it; document the reason.

## 9. No unnecessary engineering or quota consumption

- Do not add files, workflows, migrations, abstractions, docs or dependencies without a concrete requirement and acceptance criterion.
- Search for existing implementations before creating new ones.
- Prefer a focused fix over a rewrite.
- Do not run duplicate CI workflows, unnecessary preview builds, repeated deployments, broad scans or expensive database operations.
- Inspect existing CI and artifacts before rerunning. Use the narrowest relevant tests first, then the necessary integration/regression suite.
- Preserve Vercel, GitHub, database and third-party quotas. Batch read-only inspections where practical.
- Avoid duplicate deployments and never delete deployments or resources merely to tidy the dashboard.
- Do not add credentials, tokens, customer data or sensitive production values to code, logs, issues or chat.

## 10. Authorization and approval boundaries

The user authorizes non-destructive repository inspection, read-only audit, local analysis, focused code changes on isolated branches, tests and draft PRs within connected-tool permissions.

Separate explicit approval is required before:
- Production database migrations or schema/role changes.
- Destructive data/resource operations or deletion.
- Production release, traffic switch or rollback with customer impact.
- Payment collection, refunds, financial ledger changes or merchant-account actions.
- Credential rotation, secret replacement or changes that may interrupt service.
- Any irreversible external action or expansion of customer-data access.

Do not interpret general project approval as permission for these separately gated operations. When blocked, continue safe independent work and give the user exact, minimal instructions for the required intervention.

## 11. Required test and evidence levels

Use the narrowest applicable test first, then expand:
- Static checks and unit tests.
- Component and contract tests.
- Database integration tests against isolated fixtures.
- Security/negative tests and adversarial tests.
- End-to-end customer journey in isolated staging.
- Production smoke checks only when authorized and safe.
- Independent retest of the original defect.

Evidence must identify repository, branch, exact commit SHA, workflow/run, test command, result, artifact/log reference and limitations. A CI pass proves only the assertions that workflow actually ran. A deployment proves deployment, not customer usability. A synthetic demo proves only the synthetic scenario.

## 12. Definition of Done and completion states

Use these states consistently:

- PLANNED — design only.
- IMPLEMENTED — code exists.
- TESTED — relevant automated tests pass.
- INTEGRATED — connected to the actual application through tested contracts.
- STAGING VERIFIED — staging behavior and acceptance criteria verified.
- PRODUCTION VERIFIED — production behavior verified with authorization and evidence.
- COMPLETE — every required acceptance criterion for the declared scope passes.
- BLOCKED — external prerequisite or approval remains.

A feature cannot be called complete solely because a file exists, PR is merged, workflow is green, deployment is successful or demo looks correct.

### 100% project completion criteria
The project may be declared 100% complete only when:
1. The agreed core intelligence workflow is integrated and acceptance-tested.
2. Authorization is enforced at real execution boundaries.
3. Independent verification checks external evidence and handles uncertainty correctly.
4. Audit and learning use verified, traceable outcomes.
5. Security, tenant isolation, identity, sessions and API-key lifecycle pass applicable tests.
6. Standalone customer onboarding and the Free Plan work end to end.
7. Customer portal, developer API, documentation, usage and entitlements work in the declared launch scope.
8. Paid commercial readiness is either fully verified or explicitly excluded from the declared release scope; never imply it is live when it is not.
9. Operational, deployment, recovery, monitoring and quota controls meet release criteria.
10. Benchmark and research claims match completed protocol stages and reproducible evidence.
11. Critical and high-severity defects are resolved or explicitly accepted by the authorized owner with documented risk.
12. A final independent end-to-end retest passes and a release report identifies exact evidence and residual limitations.

If any item is blocked, missing or not verified, report the project as not yet 100% complete. Do not hide blockers to satisfy a completion target.

## 13. Reporting cadence and user communication

Maintain a concise execution report containing:
- Current phase and exact baseline commit.
- What was inspected and what changed.
- Defects found/fixed and their severity.
- Tests and independent evidence.
- Open PRs and review/merge status.
- Deployment and customer journey status.
- Quota-sensitive actions taken or avoided.
- Blockers, approvals and exact user action required.
- Next highest-value task.

Do not repeatedly ask the user to restate this directive. Ask only when a genuine decision, missing secret, external account action or approval is required. Never claim access to an external service that has not been verified.

## 14. Final binding instruction

Always optimize for:

**REAL INTELLIGENCE → SECURE EXECUTION → INDEPENDENT VERIFICATION → WORKING PRODUCT → CUSTOMER VALUE → RELIABLE STANDALONE SAAS → EVIDENCE-BASED COMMERCIAL READINESS.**

JAS-SI must make the use of AI by other people and organizations safer, more verifiable and more effective.

Do not optimize for repository size, number of commits, number of workflows, number of features or the appearance of activity. Optimize for measurable outcomes, maintainability, security, customer benefit and verified delivery.

**Build the real system. Deliver the usable product. Prove what works. Disclose what does not.**
