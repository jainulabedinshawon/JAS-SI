# JAS-SI Product Positioning and Evidence-Based Readiness Assessment v0.1

**Status:** Product strategy proposal; not a certification, benchmark result, or claim of production readiness.  
**Assessment date:** 2026-11-10  
**Repository baseline reviewed:** `c051d41b6c3e658c853c45fdbfdaab5a820cfeb8`

## 1. Executive assessment

JAS-SI has a credible product thesis but is not yet a complete customer-ready product.

**Recommended category:** AI agent authorization, evidence integrity, and outcome assurance infrastructure.

**Recommended initial positioning:** a complementary control and evidence layer for engineering agents that operate on GitHub repositories and CI workflows. It should answer:
1. Was the proposed operation authorized for this tenant, actor, resource, and scope?
2. What independently observable state changed?
3. Does the evidence support the agent's success claim?
4. Can a reviewer reconstruct the decision and evidence chain?

Do not position the current release as a general autonomous agent platform, a full agent observability suite, or a system that independently proves arbitrary real-world outcomes.

## 2. What is implemented in the reviewed main baseline

| Capability | Evidence in code/docs | Current boundary |
|---|---|---|
| Tenant-scoped API-key authentication | `api.py`, PostgreSQL registry and security tests | Operator-issued keys; no public self-service key lifecycle |
| Authorization evaluation | `POST /v1/authorize` | Evaluates a decision; response explicitly says `executed: false`; no action executor |
| Outcome claim evaluation | `POST /v1/verify`, `verification.py` | Evidence is caller-submitted; API sets `collected_independently=False`, so supplied evidence is not treated as independently collected |
| GitHub evidence integrity | `POST /v1/github/evidence`, `verify_router.py` | Fetches immutable commit/file data and checks Git blob integrity; explicitly does not verify semantic truth or prove an action occurred |
| Audit persistence | PostgreSQL security event store and fail-closed paths | Useful audit foundation; operational retention, external anchoring and full customer audit UX remain to be demonstrated |
| Developer portal | root HTML route and docs | Static landing page; no authenticated customer console |
| Demo | `/demo` | Synthetic browser-only walkthrough; does not call API, GitHub, or evidence collectors |
| PHP SDK | merged PR #28 and its CI history | SDK client for existing API contract; does not add action execution or independent evidence collection |
| Usage metering | contract document merged in PR #29 | Specification only; no durable usage-event store, usage endpoints or dashboard |
| Billing / entitlements | architecture specification | JAS Platform contract is not implemented; no live entitlement decision or settlement integration |

## 3. Product strengths

1. **Clear trust problem:** reported agent success is not equivalent to verified success. This is understandable to engineering, security, and platform buyers.
2. **Authorization is explicit:** capability and permission are separated; API key scopes and tenant attribution already exist in the backend.
3. **Fail-closed audit behavior:** critical authorization/verification responses are withheld if required audit persistence fails.
4. **Immutable GitHub evidence path:** commit SHA and Git blob integrity checks provide a concrete, narrow evidence capability.
5. **Correct commerce boundary:** JAS Platform remains the financial authority; JAS-SI is responsible for measured service usage and technical evidence.
6. **Research discipline:** the repository distinguishes proposed architecture, implementation, and benchmark evidence; benchmark v0.1 is explicitly not frozen.

## 4. Product weaknesses and launch blockers

### P0 — Required before a paid customer pilot
- Deploy the current reviewed `main` commit and prove public unauthenticated access to the portal, plus authenticated access to protected APIs. The latest known Production deployment is behind `main`; the combined commit status reports a Vercel build-rate-limit failure.
- Publish a real customer onboarding path: tenant provisioning, secure one-time API-key delivery, rotation/revocation, recovery and support workflow.
- Implement durable, append-only, idempotent usage events and tenant-scoped usage APIs. Until then, show usage as unavailable, never fabricated.
- Implement a real interactive demo that calls a non-production API and clearly separates live API responses from synthetic examples.
- Establish customer-accessible data isolation, audit history, error semantics, service limits, support and privacy documentation.
- Validate runtime database roles, backups/restore, monitoring, distributed rate limiting and operational response.

### P1 — Required for the core product promise
- Build independent evidence collectors. Do not accept a caller's `collected_independently=true` flag as proof. Collectors should independently query GitHub Actions job/run results, repository commit/tree state, deployment state, and test artifacts using scoped read-only credentials.
- Bind evidence to a specific action/request, tenant, immutable resource version, collector identity, collection time, and integrity digest.
- Define source trust, freshness, replay protection, provenance, contradictory evidence and unknown-state rules.
- Add a policy/evidence evaluation engine that can distinguish integrity, authenticity, freshness, relevance and semantic correctness. Git blob integrity alone is not outcome truth.
- Run the frozen benchmark protocol: 24 tasks × 10 seeds per condition (240 planned runs per system/condition), with baseline and ablation comparisons. Publish raw artifacts, confidence intervals, false-success rate, verification accuracy, failure detection and unauthorized-action rate. The benchmark is currently NOT FROZEN; no performance superiority claim is allowed.

### P2 — Scale and enterprise readiness
- Distributed rate limiting and abuse controls.
- Tenant-level usage/entitlement reconciliation and platform outage policy.
- SSO/SCIM, audit export, retention controls and enterprise deployment options only after demand and security review.
- SDKs and integrations beyond PHP based on customer demand.

## 5. Competitive landscape and differentiation

The adjacent market is already mature. Public 2026 comparisons describe LangSmith, Arize, Braintrust, Langfuse, W&B Weave and Opik as offering combinations of tracing, offline/online evaluation, trajectory/session evaluation, production monitoring, human review and CI/CD workflows. Credo AI describes agent registries, risk assessment, policy/governance workflows, evidence retrieval, monitoring and human escalation.

Therefore, JAS-SI must NOT claim novelty for generic orchestration, tracing, evaluation, human review, policy gates, audit logs, or AI governance.

Potential differentiation to test:
- **Authorization-to-evidence continuity:** one auditable chain from a scoped authorization decision to independent external evidence and a final verified state.
- **False-success assurance:** explicitly optimize and benchmark detection of false success, unsupported success and unknown outcomes rather than only output quality or trace visibility.
- **Evidence provenance and independence:** show who collected evidence, from which independent system, at what immutable version/time, under what scope, and why it is sufficient.
- **Vendor-neutral verification adapters:** start with GitHub Actions + Git repository state + deployment provider, then add other systems only after repeatable validation.

These are hypotheses, not established differentiators. Prove them with head-to-head experiments on the same tasks and evidence sources. JAS-SI should initially complement observability/evaluation products rather than attempt to replace them.

### Public comparison references
- Arize, “7 best AI agent evaluation platforms compared for 2026” (Aug 13, 2026): https://arize.com/resources/llm-and-agent-evaluation-platforms/
- LangChain, “LangSmith vs Arize” (Sep 10, 2026): https://www.langchain.com/resources/langsmith-vs-arize
- Credo AI product capabilities: https://www.credo.ai/product

These are vendor/industry sources, not independent proof of JAS-SI capability. Re-check vendor claims during a formal procurement comparison.

## 6. Ideal first customer and use case

**Initial buyer:** a software company or platform team operating coding/deployment agents with access to GitHub and CI/CD.

**First use case:** an agent proposes or performs a repository task; JAS-SI evaluates authorization, then independently reads the resulting commit, CI workflow and deployment evidence to determine whether the claimed outcome is supported.

**Buyer value:** fewer false completion reports, better auditability, stronger separation between agent claims and system-of-record evidence, and a clear authorization record.

Do not sell autonomous execution as a current capability. The initial product can be a control/verification API and dashboard that integrates with an existing agent runtime.

## 7. Readiness scorecard (qualitative, not a benchmark)

| Dimension | Assessment | Reason |
|---|---:|---|
| Problem clarity | 8/10 | Distinct, costly failure mode |
| Architecture coherence | 7/10 | Clear boundaries and evidence-first thesis |
| Current implementation breadth | 4/10 | Auth, audit, API and GitHub integrity exist; core workflow incomplete |
| Independent outcome verification | 2/10 | No independent outcome collector; API evidence is caller-submitted |
| Customer experience | 2/10 | Static portal/demo; no self-service onboarding or usage view |
| Commercial integration | 1/10 | Metering contract only; Platform entitlement API absent |
| Benchmark maturity | 1/10 | Protocol in development; not frozen; no comparative results |
| Differentiation proof | 2/10 | Promising hypothesis; no head-to-head benchmark |
| Customer readiness overall | 2/10 | Not ready for public paid launch |

Scores are engineering judgment based on the reviewed repository state, not measured product metrics or external certification.

## 8. Release acceptance gates

A customer-ready release requires all of the following:
1. Public production dashboard and API routes return expected responses on the current main commit; customer access is tested outside the owner account.
2. Customer onboarding and API-key lifecycle work end-to-end with tenant isolation.
3. Real demo uses a non-production backend and shows actual API/evidence results; synthetic fixtures remain separately labelled.
4. Usage records are durable, append-only, idempotent, tenant-scoped and reconciled to Platform acknowledgements.
5. JAS Platform entitlement checks are authenticated, replay-safe, versioned and tested for deny/timeout/retry/revocation.
6. Independent evidence collectors produce provenance-bound artifacts and reject unsupported or contradictory claims.
7. Security, backup/restore, rate-limit, privacy and operational tests pass.
8. Formal benchmark is frozen, reproducible and reported with raw evidence and uncertainty.
9. Documentation clearly lists limitations, data handling, SLA/support and pricing/entitlement semantics.

## 9. Decision

**Continue, but narrow the first product.** Build JAS-SI first as an evidence-backed authorization and outcome-assurance layer for GitHub-based engineering agents. Do not attempt to launch a broad agent platform before the independent evidence chain, customer onboarding, metering and benchmark are real.

The product idea is worth pursuing. The current implementation is a credible foundation, not yet a strong finished product. The strongest path to a defensible product is measurable false-success reduction backed by independently collected, provenance-bound evidence.
