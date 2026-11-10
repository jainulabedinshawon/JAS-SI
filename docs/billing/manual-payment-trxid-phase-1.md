# JAS-SI Manual Payment Phase 1 — TrxID Reconciliation

**Status:** Approved product direction; implementation design only. No payment number, live checkout, transaction acceptance, paid entitlement, or production migration is enabled by this document.

## Decision

Use manual bank/mobile-financial-service transfer as a temporary, low-fixed-cost payment collection workflow before integrating a hosted gateway. It is a manual reconciliation process, not a payment gateway and not a zero-risk substitute for one.

Potential channels: bKash, Nagad and Rocket. A channel is enabled only after the business confirms the correct account type, account ownership, provider terms, permitted commercial use, and exact receiving number. Never publish a personal number by default. Prefer a merchant/business account where the provider requires one for commercial collection.

## Customer journey

1. Customer signs in to the JAS-SI customer portal.
2. Customer selects a published, purchasable plan or a server-issued order/quote. A preview-only plan cannot be checked out.
3. Server creates a unique payment reference and snapshots the expected amount, currency (BDT), plan/units and expiry. The customer cannot change these values in the submission.
4. Checkout shows only enabled receiving channels and the operator-verified receiving number, account type, exact amount and payment reference.
5. Customer transfers the exact amount and submits channel, TrxID, sender number (masked at display), amount and optional receipt reference.
6. Server stores the submission as `pending_review`. A TrxID submission is a claim, not proof of payment.
7. An authorized operator independently checks the provider's official merchant/business statement or transaction record. A screenshot alone is insufficient evidence.
8. Operator marks the submission `verified` or `rejected`, recording reviewer identity, timestamp, reason code and a private evidence reference. Duplicate TrxIDs are rejected across the relevant channel/account.
9. Only a separate, idempotent entitlement-settlement transaction may activate the exact order's plan/units. A payment status update alone must never add quota.
10. Customer sees status and a receipt/reference after reconciliation. Refunds, reversals and chargebacks suspend or reverse entitlements through an audited compensating event, never by deleting history.

## State machine

`created -> pending_review -> verified -> settled`

Alternative terminal paths: `rejected`, `expired`, `cancelled`. A verified payment that cannot be settled remains visibly `verified_unsettled` and raises an operator alert; it must not be silently marked complete. Reconciliation is idempotent by payment ID and order ID.

## Minimum data contract

- payment_id, tenant_id, customer_account_id, order_id, provider/channel
- receiving_account_id (server-side configured identifier; never expose secrets)
- expected_amount_minor, submitted_amount_minor, currency=BDT
- transaction_id normalized and hashed/uniqueness protected per channel and receiving account
- sender_contact encrypted or minimized; never log raw phone or transaction data
- status, submitted_at, reviewed_at, reviewer_id, reason_code
- evidence_reference (private storage key only; no public file URL)
- idempotency key, created_at, updated_at, immutable audit events

Store money in integer minor units (poisha), never floating point. Do not accept customer-supplied tenant, order amount, plan units, status, reviewer or entitlement values.

## Abuse, fraud and privacy controls

- Require an active authenticated customer session and CSRF protection for browser submissions.
- Rate-limit submission and operator review separately; protect against enumeration and brute-force TrxID attempts.
- Unique constraint for (provider, receiving_account_id, normalized_transaction_id); duplicate submissions must not create multiple payment records.
- Exact amount and currency must match the server-side order. Partial, excess, expired and mismatched payments go to manual exception handling.
- Operator MFA and separate least-privilege reviewer role are required before enabling a public review console.
- Dual control for high-value payments, refunds and account-number changes.
- Never store payment PIN, OTP, password, card details or unnecessary full screenshots.
- Retain records only under a published accounting/privacy retention policy; restrict evidence access and audit every read.
- Display no provider number until account ownership and channel eligibility are confirmed by the business owner.

## Entitlement rule

The payment submission endpoint cannot grant units. A verified payment is not itself an entitlement. The settlement service must atomically:
1. lock the order/payment,
2. confirm verified status and exact expected amount,
3. ensure the order has not already settled,
4. append a unique settlement event,
5. activate only the order's server-defined plan/units,
6. commit all steps together.

No overage, credit wallet or automatic top-up is part of Phase 1. Technical usage telemetry remains separate from the financial ledger.

## Rollout stages

- **M0 — Catalogue/order readiness:** publish only plans with reviewed prices and fixed quota definitions. Current Starter/Pro/Enterprise catalogue is preview-only and therefore cannot be purchased.
- **M1 — Offline operational rehearsal:** use synthetic transactions and test accounts; verify duplicate, wrong amount, expired order, replay, rejection and reconciliation paths.
- **M2 — Limited manual collection:** enable one verified business receiving account, manual operator review, daily reconciliation and a published refund/contact policy.
- **M3 — Hosted gateway:** add provider adapters (Bangladesh and international) only after volumes, provider contracts and fees justify it.

## Current blockers before real-money activation

- Business owner has not supplied/confirmed merchant/business account details or permission to publish them.
- No approved price list, server-issued order/quote contract, paid plan entitlement ledger or settlement transaction exists.
- No operator identity/MFA/reviewer role or evidence storage policy has been approved.
- No refund, reversal, chargeback, customer support or accounting process has been approved.
- No live bKash/Nagad/Rocket transaction verification integration exists.

Therefore this phase may be developed and tested with synthetic records, but live collection and paid entitlement activation remain disabled. A personal Send Money number should not be assumed to be a permitted or suitable commercial checkout method.
