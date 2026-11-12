# JAS-SI Standalone Billing and Pricing v1.0

**Status:** Free technical quota and a basic customer portal are implemented on the PR #36 Draft branch; paid billing remains preview-only and has no live checkout or entitlement ledger.  
**Decision:** JAS-SI owns its initial Free plan, technical usage quota, plan catalogue and customer-facing billing status. JAS Platform integration is a later adapter phase.

## Product strategy

JAS-SI competes on low-friction adoption and low total cost:
- Free entry with a real but bounded monthly technical-usage allowance.
- Starter and Pro tiers designed for materially lower cost than comparable high-priced services.
- Enterprise pricing negotiated against actual usage and support requirements.
- Clear usage visibility and no surprise monetary charges.

## What is implemented in this phase

- A public plan catalogue with Free, Starter, Pro and Enterprise tiers.
- Free monthly allowance configurable through `JAS_SI_FREE_MONTHLY_UNITS` (default 100 technical units).
- Atomic quota reservation against tenant-scoped durable usage events.
- Paid tiers are visible as preview-only; no invented price or purchasable state.
- No payment is collected and no paid entitlement is granted.
- Quota reservations are currently charged as technical request units; an operation that passes authentication and schema validation consumes one unit even if the subsequent business evaluation fails.

## Important limitations

The Free quota is enforced at authenticated API admission against durable tenant usage events. PostgreSQL serializes each tenant's monthly reservations with a transaction-scoped advisory lock, checks exact idempotency replays before consuming a new unit, and denies over-limit requests before the API handler runs. The quota is measured by UTC calendar month. The configured allowance is a technical API-call cap, not a monetary credit.

Paid plan prices must be set only after measuring compute, database, network, support, fraud and payment costs for representative workloads. Prices must be configured in integer minor currency units with explicit BDT/USD currency selection; no browser locale inference.

## Next implementation gates

1. Persist tenant plan assignment and billing-period boundaries before enabling any paid tier.
2. Extend the existing basic customer portal (account, API-key and technical-usage sections) with a read-only tenant-scoped entitlement/plan-status view sourced from the authoritative commerce owner. Invoice, receipt and payment records remain owned by JAS Platform; the current portal is not a complete billing dashboard and does not support checkout.
3. Keep payment-provider adapter, sandbox checkout, webhook verification and payment reconciliation work in JAS Platform. JAS-SI implements only an authenticated entitlement-consumption adapter; no provider integration or payment state machine belongs in this repository.
4. Test tenant entitlement changes, quota enforcement, expiry and revocation in JAS-SI. JAS Platform must test payment reconciliation, plan downgrade, refunds and chargebacks before paid checkout.
5. Publish paid prices only after cost model and unit economics review.

## Non-goals

No payment gateway, checkout, subscription charge, refund, invoice, card-data handling, production migration, or JAS Platform integration is enabled by this phase.
