# JAS-SI Billing Core — Architecture Specification v0.1

**Status:** Proposed architecture; design only.  
**Target repository:** `jainulabedinshawon/JAS-SI`  
**Scope:** International and Bangladesh customer billing.  
**Implementation status:** No payment integration, database migration, provider account, secret, or live payment has been created by this document.

## 1. Executive decision

Build one provider-neutral Billing Core shared by all markets, with separate payment-provider adapters and one authoritative internal money/credit ledger.

The Billing Core is responsible for:
- product and price catalog;
- checkout/order lifecycle;
- verified payment state;
- subscription and entitlement lifecycle;
- credit grants, reservations, captures, releases and reversals;
- usage metering;
- refunds, disputes and reconciliation;
- durable, sanitized billing audit events.

Payment providers collect money and report provider-side events. They do **not** own JAS-SI customer entitlements or credit balances. Only the Billing Core may grant or remove JAS-SI entitlements, after server-side verification.

The existing JAS-SI authorization, verification and evidence-integrity engine remains independent of billing. Billing decides whether an account has an active entitlement/quota; existing authorization decides whether an action is permitted. A paid plan must never bypass JAS-SI authorization.

## 2. Architecture

```text
Customer / Developer Console
          |
          v
Billing API + Order/Subscription Services
          |
          +---- Product & Price Catalog
          +---- Entitlement Service
          +---- Usage Meter / Credit Service
          +---- Refund & Reconciliation
          |
          v
Provider Adapter Interface
          |
          +---- International provider adapter(s)
          +---- Bangladesh provider adapter(s)
          |
          v
Provider hosted checkout / signed webhook / IPN
          |
          v
Verified Event Inbox -> Idempotent State Transition
          |
          v
PostgreSQL: Orders + Payments + Ledger + Usage + Audit
          |
          v
Tenant entitlement / credit balance consumed by API
```

Provider callbacks are untrusted input until signature/authenticity, merchant account, transaction identity, order reference, amount, currency and expected state are validated.

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

Proposed tables (names are provisional):
- `jas_si_billing_accounts`: tenant binding, billing status, legal/customer metadata reference.
- `jas_si_products`: stable product identity and product type.
- `jas_si_prices`: market, currency, amount in minor units, billing interval, credit quantity, effective dates.
- `jas_si_checkout_orders`: immutable order snapshot, tenant, price, quantity, amount, currency, status, expiry and idempotency key.
- `jas_si_payment_transactions`: provider, provider account, provider transaction ID, amount, currency, status and verified timestamps.
- `jas_si_provider_customers`: provider customer IDs mapped to billing account; no payment credentials.
- `jas_si_webhook_events`: provider event ID, payload digest, received/processed state, timestamps and safe diagnostic metadata.
- `jas_si_subscriptions`: provider subscription ID, plan, period, status, cancel-at-period-end and lifecycle version.
- `jas_si_entitlements`: tenant, feature/quota, source order/subscription, validity window and status.
- `jas_si_credit_accounts`: tenant/currency-independent credit unit balance projection and version.
- `jas_si_credit_ledger`: append-only grants, reservations, captures, releases, expirations and reversals.
- `jas_si_usage_events`: idempotent usage records, metering dimensions, quantity and calculated charge.
- `jas_si_refunds`: provider refund ID, original transaction, amount, currency, reason and status.
- `jas_si_billing_audit_events`: sanitized financial lifecycle events.

Use UUID primary keys, foreign keys, unique provider transaction/event constraints and tenant-scoped indexes. Monetary amounts are integer minor units (e.g. paisa/cents), never floating point. The initial provider-neutral domain prototype accepts only `BDT`, `USD`, `EUR` and `GBP`; this is a deliberately narrow implementation allowlist, not a claim that any provider or merchant account supports all four. Expand it only after confirming each currency's minor-unit exponent, provider support and market eligibility. Each order stores an immutable price/currency/credit snapshot so later catalog edits cannot alter an existing purchase.

## 5. Order and payment state machine

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

- A subscription is a provider-backed commercial contract; an entitlement is the JAS-SI permission/quota resulting from a verified contract state.
- Keep subscription status separate from payment status.
- Grant/renew entitlement only after verified initial payment or verified provider subscription event according to the selected provider's contract.
- Handle renewal failure, grace period, pause, cancellation, expiry, upgrade/downgrade and refund explicitly.
- Cancellation stops future renewal; it does not silently erase already-paid access unless the published terms require it.
- Entitlement checks must be tenant-scoped and performed server-side.
- Never use a paid plan as authorization to perform an otherwise prohibited action.

## 10. Refunds, disputes and reconciliation

- Refunds and chargebacks create compensating records; never delete original payment or credit entries.
- Refund eligibility must be calculated from the original order and its remaining unconsumed purchased-credit grant, not from the tenant's total balance (which may include other purchases or promotional credits).
- If a refund or chargeback exceeds the unused portion of its original grant, do not silently force the credit balance negative and do not confiscate unrelated grants. Record the provider-side financial event, place the affected billing account/entitlement into a clearly defined review or restricted state, and create a reason-coded recoverable balance/debt record linked to the original order. The exact customer-facing restriction, appeal and recovery policy must be approved before live launch.
- Partial refunds must be bounded by the original captured payment amount; repeated or out-of-order refund events must be idempotent and reconciled against provider transaction state.
- Reconcile provider transactions and settlement reports against internal orders/payments daily.
- Flag missing, duplicated, amount-mismatched, currency-mismatched and orphaned transactions for manual review.
- Separate gross sales, provider fees, refunds, tax withheld, chargebacks and net payout.
- Payout received in a bank account is distinct from customer payment confirmation.

## 11. API surface (proposed)

Customer-facing:
- `GET /v1/billing/catalog`
- `POST /v1/billing/checkout-sessions`
- `GET /v1/billing/orders/{order_id}`
- `GET /v1/billing/credits`
- `GET /v1/billing/usage`
- `GET /v1/billing/subscription`
- `POST /v1/billing/subscription/cancel`

Provider-facing:
- `POST /v1/billing/webhooks/{provider}`

Operator-only (not public API):
- reconciliation, refund review, product/price administration and controlled adjustments.

All customer endpoints require authenticated tenant context and appropriate scopes. Webhook endpoints use provider signature/authenticity rather than customer API keys. Do not create a public API-key or billing-admin endpoint without a separate threat model.

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

**Phase A — Specification (this document):** domain model, state machines, adapter contract, threat model and acceptance gates.

**Phase B — Provider-neutral core:** implement catalog, order lifecycle, ledger primitives and test doubles only; no external provider calls.

**Phase C — Usage metering:** tenant-bound reservation/capture and quota enforcement, behind feature flags in isolated test environments.

**Phase D — Provider sandboxes:** implement one Bangladesh and one international adapter only after onboarding and provider selection are confirmed.

**Phase E — Reconciliation and operational controls:** refunds, disputes, settlement reporting, audit and operator workflows.

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
