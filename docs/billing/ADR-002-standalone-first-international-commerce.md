# ADR-002 — Standalone-first, international commerce ownership

**Status:** Accepted project direction; design and sandbox work only.  
**Date:** 2026-11-13  
**Scope:** JAS-SI standalone SaaS and future JAS Platform linking.  
**Production authorization:** Not granted by this ADR. No merchant account, provider credential, live checkout, payment collection, financial migration, or production release is authorized here.

## Context

The previous Billing Core v0.1 document made JAS Platform the sole commerce authority and explicitly prohibited payment-provider integration in JAS-SI. That boundary conflicts with the approved product requirement: JAS-SI must launch and sell as an independent SaaS without waiting for JAS Platform.

The product must therefore support standalone commercial operation now and optional central commerce later, without two systems granting the same tenant paid access or maintaining competing financial ledgers.

## Decision

### 1. Tenant-scoped commerce authority

Each tenant has exactly one server-controlled commerce authority:

- **`jas_si_standalone`** — JAS-SI owns its standalone catalog/prices, order snapshots, provider adapter, verified provider-event inbox, minimal financial/settlement ledger, subscription/payment lifecycle, and authoritative paid entitlement for that tenant.
- **`jas_platform_linked`** — JAS Platform owns checkout, payments, financial ledger and paid entitlements. JAS-SI consumes authenticated entitlement decisions/snapshots and continues to own service execution, technical usage and verification evidence.

The authority is resolved from trusted tenant configuration, never from a request body, query parameter, browser redirect, customer-controlled header or API-key scope. A tenant cannot have both authorities active. Switching authority requires an audited, explicit migration that reconciles open orders, subscriptions, refunds, balances and entitlements; no automatic dual-write or implicit cutover.

### 2. Ownership boundaries

JAS-SI always owns:
- customer identity, tenant membership and API-key security;
- API admission, authorization, execution and independent verification;
- append-only technical usage events and usage reporting;
- the entitlement enforcement interface and decision audit trail.

In standalone mode, JAS-SI additionally owns its commerce integration and the minimal records required to reconcile provider-confirmed transactions to entitlements. A Merchant of Record (MoR) remains the legal seller/collector and handles the tax/compliance responsibilities in its agreement; JAS-SI must not store card PAN/CVV or claim to hold customer funds.

In Platform-linked mode, JAS Platform is the only commerce/financial authority. JAS-SI must not create duplicate orders, collect payment, issue refunds, or independently grant paid entitlements for linked tenants.

### 3. Payment trust and entitlement invariants

- Only server-verified, authenticated provider events or provider API lookups can establish payment state. A browser redirect, client payload, screenshot or customer-supplied transaction reference is never proof of payment.
- Hosted checkout only; no card data enters JAS-SI.
- Store monetary amounts as integer minor units and always store an explicit ISO-4217 currency. Never infer a charge currency from browser locale.
- Preserve immutable order/price snapshots; do not mutate historical order amounts when catalogue prices change.
- Verify webhook signatures against the raw request bytes, enforce timestamp/replay bounds where supported, deduplicate provider event IDs, and process events idempotently.
- Verify provider merchant/account identity, order reference, amount, currency, product/price and expected lifecycle state before entitlement settlement.
- Payment verification and entitlement settlement are separate, atomic/idempotent transitions. A paid-looking status must never itself grant quota.
- Refunds, disputes, chargebacks, cancellations and subscription expiry produce audited compensating entitlement events; never delete financial or usage history.
- Reconcile provider events and settlement reports against local order/ledger state. Missing or inconsistent evidence blocks activation and raises an operational alert.

### 4. International-first market policy

- Default commercial catalogue currency: USD, subject to final unit-economics approval.
- Store customer display currency separately from charge currency and settlement/payout currency.
- Localized price display may be offered only from an explicit provider/price-book result; browser locale alone never selects a price.
- Capture provider gross amount, tax, provider fee, refunds, net payable, settlement currency, payout reference and exchange-rate metadata where supplied.
- Do not promise USD retention or a specific FX conversion outcome until the merchant account, payout method and receiving bank route have been verified. Foreign-exchange and tax obligations must be confirmed with the relevant bank/advisers.
- Start with one-time purchases or fixed recurring plans supported by the selected provider; do not implement metered monetary billing until usage economics and provider reconciliation are proven.

## Provider assessment (13 Nov 2026)

### Primary candidate: Paddle

Paddle is the leading candidate for international SaaS because it acts as Merchant of Record, supports global checkout, subscriptions and tax handling, and documents Bangladesh (`BD`) in its supported-market table. Its published standard checkout fee is 5% + USD 0.50 per transaction. Payouts are monthly, with a configurable minimum threshold starting at USD 100, and use bank wire or Payoneer. USD is a supported payout currency; BDT is not in Paddle's published payout-currency list, so the actual Bangladesh receiving-bank route, conversion and fees must be verified before activation.

Official references:
- Supported countries and BD market: https://developer.paddle.com/concepts/sell/supported-countries-locales/
- Supplier country restrictions: https://www.paddle.com/help/start/account-verification/which-countries-are-supported-by-paddle
- Standard pricing: https://www.paddle.com/pricing
- Payout timing/methods: https://www.paddle.com/help/start/intro-to-paddle/when-and-how-do-i-get-paid
- Payout currencies and conversion margin: https://www.paddle.com/help/manage/get-paid/can-i-be-paid-in-my-local-currency

### Fallback candidate: Lemon Squeezy

Lemon Squeezy's official supported-country page explicitly lists Bangladesh for bank payouts. Its documentation says transactions are processed in USD, supports localized price display, and converts bank payouts to the local currency at the mid-market rate at payout time. Payouts are scheduled twice monthly after a 13-day holding period. This is a viable fallback if Paddle onboarding or the actual Bangladesh payout route is not approved, but its payout conversion behavior may not satisfy a requirement to retain proceeds in USD.

Official references:
- Supported countries (Bangladesh bank payout): https://docs.lemonsqueezy.com/help/getting-started/supported-countries
- Getting paid and payout schedule: https://docs.lemonsqueezy.com/help/getting-started/getting-paid
- USD processing and payout conversion: https://docs.lemonsqueezy.com/help/payments/currencies

### Stripe

Do not make Stripe the default assumption for a Bangladesh-registered merchant. Bangladesh is not listed in Stripe's current supported business-account countries: https://stripe.com/global. A foreign-country Stripe account requires a genuine eligible legal entity, tax ID, physical location and bank account in that country; do not use nominee, borrowed or fabricated business details: https://support.stripe.com/questions/requirements-to-open-a-stripe-account-in-another-country.

**Provider selection remains conditional.** These public documents establish candidate eligibility signals, not approval of this specific business, its legal entity, payout bank, product category or account. Do not create an account, submit an application, or configure credentials without the business owner's explicit choice and action.

## Implementation sequence

1. Keep paid catalogue entries non-purchasable while the commerce authority and provider account are unverified.
2. Define provider-neutral order, provider-event, financial-ledger, subscription and entitlement contracts; no real-money operations.
3. Implement deterministic fake-provider tests for signature failure, replay, duplicate event, amount/currency mismatch, wrong merchant, out-of-order events, refund/dispute, retry and reconciliation.
4. Implement a provider sandbox adapter only after a provider is selected and sandbox credentials are supplied.
5. Add staging-only schema and isolated runtime roles after migration replay, RLS/privilege review and rollback evidence.
6. Run a full sandbox customer journey and independent entitlement reconciliation.
7. Obtain separate explicit approval before any production migration, live merchant activation, payment collection, financial change or production release.

## Consequences

This decision preserves standalone commercial independence while retaining a clean future JAS Platform linking path. It replaces the previous single-owner assumption with an explicit per-tenant authority boundary. It does not activate payments, set paid prices, or claim commercial readiness.
