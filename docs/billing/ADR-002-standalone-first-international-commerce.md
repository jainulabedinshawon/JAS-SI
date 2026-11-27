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

## Provider assessment (26 Nov 2026)

This is a public-document due-diligence snapshot, not a provider selection, merchant approval, payout confirmation, or authorization to activate an account. Re-check official terms before any application or integration.

### International candidate: Paddle

Paddle remains the leading international candidate for a Bangladesh-based SaaS merchant. Its current official supported-country documentation lists Bangladesh (BD), and its supplier support page excludes a published set of unsupported countries that does not include Bangladesh. Paddle's published pay-as-you-go Checkout fee is 5% + USD 0.50 per transaction, with no monthly fee stated on its pricing page. Paddle provides Merchant-of-Record checkout, subscriptions, tax handling and buyer support.

Payouts are made by wire transfer or Payoneer. The published minimum payout threshold starts at USD 100; bank/provider charges may still apply. Public eligibility does not establish that this specific business, legal entity, product, bank route or payout account will be approved. The actual Bangladesh receiving-bank route, any SWIFT/intermediary fees, FX conversion and settlement currency must be confirmed before selection.

Official references:
- Supported countries and Bangladesh (BD): https://developer.paddle.com/concepts/sell/supported-countries-locales/
- Supplier country eligibility: https://www.paddle.com/help/start/account-verification/which-countries-are-supported-by-paddle
- Current Checkout pricing: https://www.paddle.com/pricing
- Payout methods and threshold: https://www.paddle.com/help/manage/get-paid/when-and-how-do-i-get-paid
- Payout fees: https://www.paddle.com/help/manage/get-paid/is-there-a-fee-taken-for-payouts
- FX and payout currency: https://www.paddle.com/help/manage/get-paid/can-i-be-paid-in-my-local-currency

### Bangladesh local candidate: bKash Personal Retail Account (PRA)

bKash's official PRA documentation describes PRA as a business account for micro/small retail and f-commerce businesses. It permits receiving customer payments through a PRA QR, the bKash Payment Gateway, or USSD. The published receive-payment limits are BDT 30,000 per transaction, BDT 30,000 per day, and BDT 500,000 per month; limits and terms may change.

bKash's official online-business page says a business without a trade licence may open a PRA and register interest in its online payment system. The PRA onboarding requirements include an NID, a mobile number registered to that NID with no prior bKash account, and proof of SIM ownership. The same NID may already be used for a personal bKash account, but a previously used bKash number cannot be converted to PRA.

**JAS-SI eligibility is not yet established.** The public PRA description focuses on micro/small retail and f-commerce goods/services. It does not explicitly confirm that a software/SaaS subscription business is an accepted PRA business category, nor does it establish that an individual PRA receives production API credentials, webhook access, automated server-to-server transaction verification, recurring billing, or settlement capabilities appropriate for SaaS. Obtain written confirmation from bKash before relying on PRA for JAS-SI checkout. Treat QR/USSD/manual receipt as collection methods only; do not activate paid entitlements from screenshots, SMS, customer claims, or browser redirects.

The published BDT 500,000 monthly receive limit is a material scale constraint. Confirm current limits, fees, eligible business category, Payment Gateway/API access, server-side transaction query/validation, settlement route, refunds/disputes, and recurring-payment support directly with bKash. No PRA account, merchant application, API credential, or payment configuration is created or approved by this assessment.

Official references:
- PRA description, requirements, payment channels and limits: https://www.bkash.com/en/page/personal-retail-account
- bKash online-business registration and PRA option without a trade licence: https://www.bkash.com/en/business/online-business

### Bangladesh local candidate: SSLCOMMERZ

SSLCOMMERZ is a local hosted-gateway candidate with official API documentation for session initiation, IPN notification and server-side Order Validation API checks. Its currently published Basic package lists a non-refundable BDT 25,500 one-time setup fee, 2.5% per successful standard transaction and 3.5% for AMEX. These published charges make it incompatible with the current zero-cost activation constraint; no account or integration should be activated now.

Before any future selection, confirm the merchant's eligibility, current contract/fees, supported payment channels and currencies, settlement schedule, refunds/disputes, recurring-payment capability and bank settlement details directly with SSLCOMMERZ. The public API flow requires validating the IPN with the Order Validation API; a browser redirect or IPN alone is not proof of settled payment.

Official references:
- Current pricing: https://sslcommerz.com/pricing/
- Developer integration and IPN/Order Validation flow: https://developer.sslcommerz.com/

### Removed from new-integration shortlist: Lemon Squeezy

Lemon Squeezy's current official documentation states that it is no longer accepting new sign-ups and will shut down on 31 March 2027. Although its supported-country documentation lists Bangladesh bank payouts, it is not a viable new integration candidate for JAS-SI. Do not build a new adapter against a service that is winding down.

Official references:
- Getting paid / shutdown notice: https://docs.lemonsqueezy.com/help/getting-started/getting-paid
- Supported countries / shutdown notice: https://docs.lemonsqueezy.com/help/getting-started/supported-countries
- Currency behavior: https://docs.lemonsqueezy.com/help/payments/currencies

### Not available as a Bangladesh-registered default: Stripe

Bangladesh is not listed in Stripe's current supported business-account countries. Opening an account in another country requires a genuine eligible legal entity, tax ID, physical location, phone number, government-issued ID and physical bank account in that country. Do not use nominee, borrowed or fabricated business details.

Official references:
- Global availability: https://stripe.com/global
- Requirements for an account in another country: https://support.stripe.com/questions/requirements-to-open-a-stripe-account-in-another-country

**Current assessment:** Paddle is the international candidate to investigate first, subject to merchant onboarding and payout approval. For Bangladesh, bKash PRA is a low-setup-cost candidate worth confirming with bKash, but SaaS-category eligibility, API/webhook access, server-side verification, recurring billing and the BDT 500,000 monthly receive cap must be resolved; SSLCOMMERZ remains a paid hosted-gateway alternative whose setup fee conflicts with the current zero-cost activation constraint. Lemon Squeezy is removed because of its announced shutdown; Stripe is not an eligible default for a Bangladesh-registered merchant. No provider has been selected or approved. No merchant account, application, credential, sandbox/live transaction, production checkout or payment configuration is authorized by this assessment.

## User-approved provider evaluation priorities (27 Nov 2026)

This section records the project owner's current evaluation order. These are **provider candidates and work priorities, not approved merchant accounts, connected integrations, or authorization for payment collection**. Reconfirm provider terms, country/business eligibility, fees, settlement routes, and technical access before onboarding.

1. **Paddle — international SaaS subscription candidate.** Confirm seller onboarding eligibility for this Bangladesh-based business, product acceptance, KYC, payout method, receiving-bank route, FX, fees, refunds/disputes, subscription lifecycle events, and sandbox access. Public country support is not merchant approval.
2. **Payoneer — international B2B invoice/receivables candidate.** Confirm account eligibility, business receiving/payment-request access, fees, withdrawal route, and API/Checkout eligibility separately. Do not treat a Payoneer receiving account or invoice request as a general self-serve SaaS subscription checkout. Checkout API access is a separate approval question.
3. **bKash — Bangladesh local candidate.** Confirm PRA or Merchant eligibility for software/SaaS, written business-category approval, API credentials, raw-body webhook/signature contract, server-to-server transaction validation, settlement, refunds/disputes, recurring support, and current limits. PRA eligibility must not be inferred from personal-account eligibility.
4. **Nagad — Bangladesh local candidate.** Confirm Merchant onboarding, accepted SaaS business category, official API documentation, server-side transaction verification, webhook authenticity/replay controls, settlement, fees, refunds/disputes, and recurring-payment support. No API or merchant capability is assumed until documented by Nagad.
5. **EBL Visa Debit — expense-payment method only.** Eligibility for international e-commerce or business expenses depends on the issuing bank's approval, applicable passport/endorsement requirements, permitted quota, recurring-charge rules, FX treatment and transaction limits. Confirm these requirements with the bank before relying on the card for business expenses. A debit card is not a customer-payment gateway and must not be represented as one.
6. **Fasset — deferred.** Do not make it a primary checkout or treasury dependency at this stage. Reconsider only after business/jurisdiction eligibility, regulatory and bank acceptability, product scope, pricing, and fiat-only settlement are independently confirmed.

### Shared payment implementation contract

All approved providers must use one provider-neutral JAS-SI payment boundary:
- immutable order and price snapshots; integer minor-unit amounts and explicit ISO-4217 currency;
- provider-specific webhook authentication over raw request bytes, bounded timestamps, replay protection, and durable idempotent event intake;
- server-to-server transaction verification wherever the provider exposes it; webhook or redirect alone is not final proof;
- verification of merchant/account, provider transaction/event IDs, order/customer/tenant binding, amount, currency, product, and lifecycle status;
- append-only financial events with reversal/adjustment entries rather than deletion, plus settlement and provider-event reconciliation;
- separate, atomic/idempotent entitlement activation and revocation, including refund, partial refund, dispute, chargeback, reversal, cancellation, and failed renewal;
- customer-visible payment history and invoice/receipt only when supported by verified records.

### Commercial activation gate

Keep Starter, Pro, and Enterprise non-purchasable until provider approval, sandbox validation, durable ledger, independent verification, reconciliation, refund/dispute handling, entitlement activation/revocation, tenant isolation, and quota enforcement have passed staging verification. Free Launch remains distinct from Paid Commercial Launch. No provider onboarding, credential creation, live transaction, production migration, or paid service activation is authorized by this evaluation order.

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
