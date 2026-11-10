# JAS-SI Standalone Billing and Pricing v1.0

**Status:** Implementation foundation; limited preview only.  
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
- Pure quota-decision primitive with explicit allow/deny and remaining-unit result.
- Paid tiers are visible as preview-only; no invented price or purchasable state.
- No payment is collected and no paid entitlement is granted.

## Important limitations

The Free quota is enforced at authenticated API admission against durable tenant usage events. PostgreSQL serializes each tenant's monthly reservations with a transaction-scoped advisory lock, checks exact idempotency replays before consuming a new unit, and denies over-limit requests before the API handler runs. The quota is measured by UTC calendar month. The configured allowance is a technical API-call cap, not a monetary credit.

Paid plan prices must be set only after measuring compute, database, network, support, fraud and payment costs for representative workloads. Prices must be configured in integer minor currency units with explicit BDT/USD currency selection; no browser locale inference.

## Next implementation gates

1. Persist tenant plan assignment and billing-period boundaries before enabling any paid tier.
2. Add tenant-scoped customer billing/plan endpoints and a customer dashboard.
3. Define provider-neutral payment adapter interfaces; implement sandbox only after provider eligibility and commercial terms are verified.
4. Test tenant plan changes, payment reconciliation, plan downgrade and refund/chargeback handling before paid checkout.
5. Publish paid prices only after cost model and unit economics review.

## Non-goals

No payment gateway, checkout, subscription charge, refund, invoice, card-data handling, production migration, or JAS Platform integration is enabled by this phase.
