# JAS-SI Billing Core — Architecture Specification v0.1

**Status:** Superseded by [ADR-002 — Standalone-first, international commerce ownership](ADR-002-standalone-first-international-commerce.md). Retained as historical v0.1 context; do not implement its JAS Platform-only ownership assumptions.  
**Target repository:** `jainulabedinshawon/JAS-SI`  
**Scope:** International and Bangladesh customer billing.  
**Implementation status:** Historical design only. ADR-002 is the current authority for ownership and rollout. No payment integration, provider account, secret, or live payment is activated.

> [!IMPORTANT]
> ## Binding project-ownership decision
>
> Historical v0.1 decision (superseded by ADR-002): this section recorded the earlier JAS Platform-only ownership boundary. The current approved direction is tenant-scoped standalone JAS-SI commerce with optional JAS Platform-linked authority; see ADR-002.
>
> - **JAS Platform owns commerce:** customer billing accounts, product/price catalog, checkout, payment-provider integrations, payment verification, subscriptions, invoices, refunds, disputes, settlement, reconciliation and the authoritative financial ledger.
> - **JAS-SI owns intelligence-service consumption:** tenant-bound AI usage events, metering dimensions, quota/credit consumption requests, authorization/evidence service entitlements, and a narrow integration contract with JAS Platform.
> - **JAS-SI must not create a second checkout, payment, subscription, refund or financial-ledger authority.** It must never treat a browser redirect or a caller-supplied payment claim as proof of payment.
> - JAS-SI may enforce a signed/server-authenticated entitlement snapshot or consume an authoritative entitlement decision from JAS Platform. The source of truth for paid status and purchased balance remains JAS Platform.
> - The in-memory credit ledger in PR #26 is a domain experiment only. It is neither durable nor authoritative and must not be used to collect money, grant paid entitlements, or represent a production customer balance.
>
> The provider, order, payment, subscription, refund and settlement sections below are requirements for the **JAS Platform commerce owner** if adopted. For JAS-SI, only the usage-metering and entitlement-integration portions are in scope. Any conflicting statement below is superseded by this ownership decision.
>
> **Implementation boundary:** no provider account, checkout endpoint, payment webhook, financial schema, subscription engine or refund workflow is to be added to JAS-SI under this specification.


## 1. Executive decision

**JAS Platform is the sole commerce and financial authority. JAS-SI is a metered intelligence service that consumes platform-issued entitlements.** These are separate deployable systems with a narrow authenticated integration contract; they must not share or duplicate financial ownership.

JAS Platform owns:
- product and price catalog;
- checkout/order lifecycle and provider adapters;
- verified payment state, subscriptions and invoices;
- authoritative financial/credit ledger;
- payment refunds, disputes, settlement and reconciliation;
- authoritative entitlement grants, expiry and revocation.

JAS-SI owns:
- tenant-bound service usage measurement and idempotent usage-event persistence;
- pre-execution entitlement/quota checks against JAS Platform;
- final usage reporting and usage dashboard read models;
- JAS-SI authorization, verification and evidence-integrity decisions;
- sanitized technical audit records correlated to platform entitlement decisions.

JAS-SI must not implement a second checkout, payment, subscription, refund, financial ledger or authoritative purchased-credit balance. The PR #26 in-memory credit ledger remains a domain experiment only and is not a production billing component.

A paid entitlement never bypasses JAS-SI authorization. Platform entitlement decides whether the customer has service quota; JAS-SI authorization decides whether a requested action is allowed; independent verification decides whether its reported outcome is supported by evidence.

## 2. Architecture

```text
Customer / Developer Console
          |
          +------------------------------+
          |                              |
          v                              v
JAS Platform Commerce                JAS-SI API
Catalog / Checkout / Payments        API Key -> Tenant Context
Subscriptions / Invoices                  |
Financial Ledger                          v
Entitlement Authority               Entitlement Adapter
          |                         (server-to-server)
          +------ signed/authenticated decision ------+
                                                       |
                                                       v
                                              Authorization Gate
                                                       |
                                                       v
                                              Metered Service Call
                                                       |
                                      +----------------+----------------+
                                      |                                 |
                                      v                                 v
                              Usage Event Store                 Verification / Audit
                                      |
                                      v
                              Usage Dashboard

Payment providers -> JAS Platform only:
hosted checkout / signed webhook / IPN -> verified payment -> platform ledger
                                                       |
                                                       v
                                            entitlement grant/update
```

Provider callbacks are accepted only by JAS Platform and are untrusted until signature/authenticity, merchant account, transaction identity, order reference, amount, currency and expected state are validated. JAS-SI never consumes a browser redirect or caller-supplied payment claim as proof of payment.

## 3. Market and provider strategy

The architecture must support two market profiles without embedding provider-specific assumptions in the core.

### International profile
- ISO currency code stored per order; never infer currency from a browser locale.
- Hosted checkout; JAS-SI must not collect or store card PAN/CVV.
- Support one-time credit packs first; recurring subscriptions only after provider-specific lifecycle, tax, refund and payout behavior is verified.
- Webhook signature verification, event deduplication, subscription event ordering and reconciliation are mandatory.

### Bangladesh profile
- BDT pricing and local payment methods through a locally approved merchant account.
- Hosted checkout or provider-controlled payment UI.
- Validate payment server-to-server; an IPN/browser redirect alone is not proof of settlement.
- Record provider transaction ID, bank/payment channel references and settlement status.
- Local recurring-payment support is not assumed; launch one-time purchases first unless the selected provider proves reliable recurring mandate support.

### Provider selection record — intentionally not hardcoded

The current working candidates are Paddle for international SaaS payments and SSLCOMMERZ for Bangladesh-local payments. Neither is an approved or connected merchant integration. Selection remains conditional on provider onboarding, legal-entity eligibility, payout support, commercial terms and sandbox validation.

Before choosing a provider, compare:
1. merchant onboarding eligibility for the actual legal entity and country;
2. merchant-of-record / tax responsibility and supported products;
3. payout country, currency, method, minimum, timing and fees;
4. recurring subscription and cancellation behavior;
5. signed webhook/IPN and server-side transaction validation;
6. refunds, disputes, chargebacks and sandbox quality;
7. settlement reports and reconciliation API/export.

Implement adapter contracts first. Do not create provider accounts, credentials, webhooks or live integrations as part of this specification.

## 4. Core domain model

All customer-facing billing records are bound to a server-derived JAS-SI tenant. A request body, query parameter or caller-controlled header must never choose the billing tenant.

**JAS Platform-owned commerce records (not JAS-SI migrations):**
- `jas_platform_billing_accounts`: customer billing account and tenant mapping.
- `jas_platform_products` / `jas_platform_prices`: product catalog, market, currency and immutable price versions.
- `jas_platform_checkout_orders` / `jas_platform_payment_transactions`: order snapshots and verified provider transactions.
- `jas_platform_provider_customers` / `jas_platform_webhook_events`: provider references and deduplicated verified-event inbox.
- `jas_platform_subscriptions` / `jas_platform_entitlements`: commercial lifecycle and authoritative feature/quota grants.
- `jas_platform_credit_accounts` / `jas_platform_credit_ledger`: authoritative purchased-credit balances and append-only grants/reservations/captures/releases/reversals.
- `jas_platform_refunds` / `jas_platform_billing_audit_events`: refunds, disputes and financial audit trail.

**JAS-SI-owned service-consumption records (candidate schema, not yet implemented):**
- `jas_si_usage_events`: tenant-bound idempotent measurements, metering dimensions, quantity, unit, operation outcome and platform correlation IDs.
- `jas_si_usage_reservations` (optional local mirror): references to platform reservation IDs and lifecycle state; never an independent credit balance.
- `jas_si_usage_daily` (derived read model): tenant-scoped dashboard aggregates rebuilt from authoritative usage events.

Do not create the JAS Platform-owned tables in the JAS-SI repository or database. Use UUID primary keys, tenant-scoped indexes and unique idempotency constraints for JAS-SI usage events. Monetary amounts remain integer minor units in JAS Platform only; JAS-SI usage quantities use explicit integer/decimal units with a versioned metering definition and must not invent a monetary charge. The initial provider-neutral domain prototype's `BDT`, `USD`, `EUR` and `GBP` allowlist is a design/test constraint, not proof of merchant or provider support.

## 5. Order and payment state machine

**Ownership: JAS Platform only.** These order/payment states and provider-facing transitions must not be implemented in JAS-SI.

Canonical order states:
- `created`
- `pending_payment`
- `paid`
- `payment_failed`
- `expired`
- `partially_refunded`
- `refunded`
- `disputed`

Only explicit, validated transitions are allowed. A payment failure cannot later be interpreted as paid without a new verified provider event and valid transition. A refund/dispute does not erase history; it creates a compensating ledger event and updates entitlements according to the refund policy.

The browser success/cancel redirect is UX only. It must never mark an order paid or grant credits.

## 6. Provider adapter contract

**Ownership: JAS Platform only.** JAS-SI does not receive or verify payment-provider webhooks.

Each adapter implements a narrow interface:
- `create_checkout(order_snapshot, customer_reference, return_urls)`
- `verify_webhook(headers, raw_body)`
- `parse_verified_event(verified_payload)`
- `fetch_transaction(provider_transaction_id)`
- `request_refund(transaction_id, amount_minor, currency, idempotency_key)` (optional until supported)
- `fetch_settlement_report(period)` (optional until supported)

Normalized verified events should contain:
- provider and provider-account identity;
- immutable provider event ID and event type;
- provider transaction/subscription/customer references;
- our internal order reference;
- amount in minor units and currency;
- provider event timestamp and observed timestamp;
- normalized status;
- cryptographic verification result and payload digest.

Never let an adapter grant credits directly. It can only submit a verified normalized event to the Billing Core state-transition service.

## 7. Webhook/IPN processing and idempotency

**Ownership: JAS Platform only.** This section specifies the Platform's trusted payment-ingestion boundary, not a JAS-SI endpoint.

1. Receive the raw request body and headers over HTTPS.
2. Verify signature/authenticity before trusting payload fields.
3. Validate provider account/environment and event identity.
4. Persist a deduplicated inbox record with a unique constraint on (provider, provider_account, event_id).
5. Load the referenced order from our database; do not trust amount, tenant, currency or credit quantity from callback payload alone.
6. Compare provider transaction amount/currency/order reference with the immutable order snapshot.
7. Fetch/validate the transaction server-to-server when the provider's protocol requires it.
8. Apply a permitted state transition and append money/credit ledger entries in one database transaction.
9. Mark the inbox event processed in the same transaction.
10. Return provider-appropriate acknowledgement only after durable acceptance; safely retry transient failures.

Duplicate or out-of-order events must not duplicate credit. Store only the minimum necessary payload data; prefer payload digest and sanitized normalized fields over retaining sensitive raw payloads.

## 8. Credit ledger and usage metering

**Ownership split:** the authoritative credit ledger and financial reservations belong to JAS Platform. JAS-SI measures service usage, keeps idempotent technical usage records and reports actual consumption to the Platform. JAS-SI must not implement the financial ledger described in this section.

The credit ledger is append-only. No balance is edited directly and no historical entry is deleted.

Entry types:
- `grant` — verified purchase or approved promotional grant;
- `reserve` — atomically reserve estimated usage before work;
- `capture` — finalize actual usage;
- `release` — return unused reservation;
- `expire` — expire credits under an explicitly published policy;
- `refund_reversal` — reverse unused purchased credits where policy requires;
- `adjustment` — controlled, reason-coded operator correction.

Every ledger entry includes tenant, unique idempotency key, amount, entry type, source order/usage/refund, actor/system identity, timestamp and audit correlation ID.

Usage flow:
1. Authenticate API key and derive tenant from trusted server-side key registry.
2. Check tenant status, plan entitlement and allowed feature.
3. Atomically reserve the maximum/estimated credit cost using row locking or a safe conditional update.
4. Execute only the API operation already authorized by JAS-SI.
5. Calculate actual metered usage; capture actual amount and release unused reservation.
6. If work fails, apply the published failure charging policy; never silently charge estimated usage.
7. Persist usage and ledger references for audit/reconciliation.

Prevent overspend under concurrency. A cached balance is a projection only; ledger entries are authoritative. Define a consistent credit unit and pricing version before public sale.

### 8.1 PostgreSQL transaction protocol (implementation requirement)

The in-memory prototype is not a concurrency or durability guarantee. The production design must serialize balance-changing operations per tenant (or per tenant credit account) and commit the ledger entry, idempotency record and balance projection together.

**Minimum database constraints**
- Unique (tenant_id, idempotency_key) on credit-ledger operations; use a stable operation namespace so unrelated operation types cannot accidentally reuse a key.
- Unique (provider, provider_account_id, provider_event_id) on the webhook inbox.
- Unique provider transaction identity within the provider account.
- Foreign keys from grants/reversals to their source order/payment and from captures/releases to their reservation/usage operation.
- CHECK constraints for positive operation quantities, valid entry types and nonnegative projection values where applicable.
- Tenant-scoped foreign keys or equivalent ownership enforcement so a source record from another tenant cannot be referenced.

**Atomic reservation algorithm**
1. Begin a database transaction.
2. Resolve the tenant from trusted authentication context; never accept it from the request body.
3. Insert or claim the idempotency operation. On conflict, load the existing operation: return its prior result only if the canonical request fingerprint matches; otherwise reject with an idempotency conflict.
4. Lock the tenant's credit-account row using SELECT ... FOR UPDATE. Create it safely if absent, with a unique tenant constraint.
5. Re-read the authoritative available balance (or a transactionally maintained projection whose every mutation is coupled to ledger insertion). Reject if available credits are insufficient.
6. Insert the reservation ledger entry and update the balance projection/version in the same transaction.
7. Commit. Only after commit may the application begin the billable operation.

**Capture and release algorithm**
- Lock the same tenant credit-account row first, using one consistent lock order across all ledger operations.
- Lock or otherwise serialize the referenced reservation, then calculate its remaining reservable quantity from its linked reserve/capture/release entries.
- Reject capture/release greater than that reservation's remaining quantity; partial capture and partial release are permitted only within the remaining amount.
- Append the capture/release entry and update the projection/version atomically. A retry with the same idempotency key and same canonical request returns the original result; a changed request is rejected.
- If work fails after reservation, execute an idempotent release. Define and monitor a timeout/recovery worker for abandoned reservations; never silently discard them.

**Payment-to-credit grant algorithm**
- Verify the provider event outside the database transaction using the adapter's authenticated protocol, then begin a transaction.
- Insert/claim the unique inbox event; lock the internal order and relevant payment/credit-account rows in the documented global lock order.
- Revalidate order state, immutable amount/currency snapshot and provider transaction identity inside the transaction.
- Apply the permitted payment transition, create at most one source-bound credit grant/entitlement, append audit records, and mark the inbox event processed in that same transaction.
- If any required write fails, roll back all state changes; acknowledge the provider only after durable acceptance. Duplicate deliveries must return the already-processed outcome without repeating grants.

**Isolation, retries and recovery**
- A tenant-account row lock is the baseline serialization mechanism for a single credit account. If future sharding or multiple credit accounts are introduced, define the lock partition and global lock order before implementation.
- Use database-enforced unique constraints as the final defense against duplicate operations; application-level check-then-insert is insufficient.
- Retry serialization failures/deadlocks only by retrying the entire transaction with a bounded policy and the same idempotency key. Never retry only the final ledger insert.
- Keep external network calls (provider API, model execution) outside database transactions. Persist intent/state, call externally, then finalize with a new idempotent transaction.
- Treat the balance projection as a cacheable read model, not independent truth. Provide a reconciliation query/job that compares it with ledger-derived totals and raises an alert on mismatch.
- Add concurrency tests using independent database connections/processes (not only threads or an in-memory lock): many simultaneous reservations against a fixed balance must never produce a negative balance or total reservations above the grant.

This protocol is a design requirement, not evidence of an implemented PostgreSQL schema or tested production behavior. The in-memory prototype remains explicitly non-durable and non-multi-process-safe.

## 9. Subscription and entitlement rules

**Ownership:** subscription lifecycle and entitlement grants/revocations are JAS Platform responsibilities. JAS-SI only consumes authenticated entitlement decisions/snapshots.

- A subscription is a provider-backed commercial contract; an entitlement is the JAS-SI permission/quota resulting from a verified contract state.
- Keep subscription status separate from payment status.
- Grant/renew entitlement only after verified initial payment or verified provider subscription event according to the selected provider's contract.
- Handle renewal failure, grace period, pause, cancellation, expiry, upgrade/downgrade and refund explicitly.
- Cancellation stops future renewal; it does not silently erase already-paid access unless the published terms require it.
- Entitlement checks must be tenant-scoped and performed server-side.
- Never use a paid plan as authorization to perform an otherwise prohibited action.

## 10. Refunds, disputes and reconciliation

**Ownership: JAS Platform only.** JAS-SI does not process refunds, disputes, settlement or financial reconciliation.

- Refunds and chargebacks create compensating records; never delete original payment or credit entries.
- Refund eligibility must be calculated from the original order and its remaining unconsumed purchased-credit grant, not from the tenant's total balance (which may include other purchases or promotional credits).
- If a refund or chargeback exceeds the unused portion of its original grant, do not silently force the credit balance negative and do not confiscate unrelated grants. Record the provider-side financial event, place the affected billing account/entitlement into a clearly defined review or restricted state, and create a reason-coded recoverable balance/debt record linked to the original order. The exact customer-facing restriction, appeal and recovery policy must be approved before live launch.
- Partial refunds must be bounded by the original captured payment amount; repeated or out-of-order refund events must be idempotent and reconciled against provider transaction state.
- Reconcile provider transactions and settlement reports against internal orders/payments daily.
- Flag missing, duplicated, amount-mismatched, currency-mismatched and orphaned transactions for manual review.
- Separate gross sales, provider fees, refunds, tax withheld, chargebacks and net payout.
- Payout received in a bank account is distinct from customer payment confirmation.

## 11. API and service-to-service contract (proposed; not implemented)

### JAS Platform public commerce API — Platform-owned
These routes belong in JAS Platform, not in the JAS-SI FastAPI app:
- `GET /v1/billing/catalog`
- `POST /v1/billing/checkout-sessions`
- `GET /v1/billing/orders/{order_id}`
- `GET /v1/billing/credits`
- `GET /v1/billing/subscription`
- `POST /v1/billing/subscription/cancel`
- `POST /v1/billing/webhooks/{provider}` (provider-authenticated, not customer API-key authenticated)

### JAS-SI customer API — usage visibility only
Candidate routes:
- `GET /v1/usage`: authenticated tenant's usage events and period totals.
- `GET /v1/usage/summary`: tenant-scoped aggregate by feature, period and status.
- `GET /v1/entitlements`: read-only view of the last successfully confirmed platform entitlement snapshot, with source/version and freshness metadata.

These routes must derive tenant identity from the authenticated API key/session. A caller-supplied tenant ID is never authoritative. Until persisted metering exists, the dashboard must show “unavailable”, not fabricated usage or credits.

### JAS-SI ↔ JAS Platform internal consumption contract
The exact wire schema and authentication mechanism require a separately reviewed API contract. The minimum logical operations are:
1. **Authorize/reserve:** JAS-SI sends tenant (derived from auth), feature, requested quantity, idempotency key and request correlation. JAS Platform validates entitlement/quota and returns allow/deny, reservation ID, policy/version, permitted quantity and expiry. JAS-SI does not calculate paid balance.
2. **Settle usage:** after the service call, JAS-SI reports measured actual quantity, outcome, reservation ID, idempotency key and evidence/audit correlation. JAS Platform applies the authoritative quota/credit settlement.
3. **Release reservation:** on a failed or cancelled operation, JAS-SI releases unused reservation using the same reservation ID and an idempotent operation key.
4. **Refresh entitlement:** JAS-SI may refresh a signed/authenticated entitlement snapshot; stale/expired snapshots must follow a documented fail-closed or bounded-grace policy.

The Platform response should include a stable decision ID, tenant binding, feature, allow/deny, quota unit, permitted amount, reservation ID, expiry, entitlement version and policy version. Responses must be authenticated, replay-resistant and idempotent. JAS-SI must persist the decision/reservation references and usage outcome so the two systems can reconcile. Network retries use the same idempotency key; a changed request fingerprint is rejected.

This is a cross-service saga, not a distributed SQL transaction. External network calls must occur outside JAS-SI database transactions. Define timeout recovery and a reconciliation process for reservations whose final usage report was not received. JAS Platform remains the source of truth for entitlements and balances; JAS-SI remains the source of truth for measured service execution and technical evidence.

Operator-only Platform functions (refund review, product/price administration, reconciliation and controlled financial adjustments) remain outside the JAS-SI public API.

## 12. Security, privacy and audit requirements

- No card PAN/CVV storage; use provider-hosted checkout/tokenization.
- Secrets only in an approved secret manager; never in frontend bundles, source, logs, screenshots or repository history.
- TLS required; strict webhook body/signature handling; replay protection.
- Verify tenant ownership on every order, subscription, invoice, usage and credit lookup.
- Use constant-time signature comparison where applicable and provider-recommended algorithms.
- Rate-limit checkout creation and webhook abuse; distributed rate limiting before multi-worker commercial scale.
- Keep webhook payloads and logs free of credentials, payment instrument data and unnecessary personal data.
- Append sanitized billing audit events; fail closed before granting financial entitlements if required durable persistence fails.
- Operator refunds/adjustments require least privilege, reason codes and independent audit.
- Retention, tax, privacy and consumer terms require jurisdiction-specific legal review.

## 13. Testing and acceptance gates

Before any real-money integration:
1. Unit-test order and subscription state machines.
2. Test signature failure, malformed payload, replay, duplicate event and out-of-order event.
3. Test amount/currency/order/tenant mismatch; all must deny entitlement.
4. Test provider timeout, retry, duplicate webhook and database outage.
5. Test atomic credit reservation with concurrent requests; no overspend.
6. Test grant/capture/release/refund idempotency and append-only ledger invariants.
7. Test tenant isolation for orders, invoices, usage and credits.
8. Test provider sandbox end-to-end, including failed payment, cancellation and refund.
9. Reconcile provider sandbox records with internal ledger.
10. Verify no secret or payment data leakage in application, CI and audit logs.

Required invariants:
- One verified successful payment can grant at most one entitlement/credit grant.
- No unverified event can grant credit.
- No client-supplied amount, currency, tenant or credit quantity is authoritative.
- Ledger balance equals the sum of valid ledger entries.
- No cross-tenant billing data access.
- Every financial state change has a durable audit reference.
- No Production payment or database change without explicit approval.

## 14. Delivery phases

**Phase A — Specification (this document):** cross-project ownership, service-consumption contract, threat model and acceptance gates.

**Phase B — JAS Platform commerce core:** Platform team implements catalog, order lifecycle, payment verification, authoritative entitlement/credit ledger and test doubles in the Platform repository; no external provider calls until separately approved.

**Phase C — JAS-SI usage metering:** implement tenant-bound usage-event persistence, idempotency, metering dimensions and dashboard read models in JAS-SI. Connect to a mock entitlement adapter first; no money or financial balance stored in JAS-SI.

**Phase D — JAS Platform provider sandboxes:** implement one Bangladesh and one international adapter in JAS Platform only after merchant onboarding and provider selection are confirmed.

**Phase E — JAS Platform reconciliation and operational controls:** refunds, disputes, settlement reporting and financial operator workflows remain Platform-owned. JAS-SI provides technical usage/evidence correlation.

**Phase F — Controlled live launch:** separate explicit approval for merchant onboarding, live credentials, webhook registration, production migrations and real-money processing.

## 15. Explicit exclusions

This specification does not authorize:
- creating or changing Production/Neon schemas;
- applying migrations to any shared database;
- creating payment-provider merchant accounts;
- storing live API keys, webhook secrets or bank details;
- enabling real-money checkout or payouts;
- changing existing JAS-SI authorization methodology;
- merging PR #24 or changing its scope.

**Design principle:** A provider report is an input; a verified payment is a fact established by independent provider validation; an entitlement is a controlled consequence; and the credit ledger is the accountable record.
