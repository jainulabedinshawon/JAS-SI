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

The quota primitive is not yet wired to durable tenant-period usage or request authorization. Therefore the 100-unit catalogue value is a published/configurable product proposal, **not an enforced production quota**. Until enforcement is implemented and independently tested, operators must not advertise the Free limit as a hard service cap.

Paid plan prices must be set only after measuring compute, database, network, support, fraud and payment costs for representative workloads. Prices must be configured in integer minor currency units with explicit BDT/USD currency selection; no browser locale inference.

## Next implementation gates

1. Persist tenant plan assignment and billing-period boundaries.
2. Atomically reserve/consume quota against the durable usage ledger; prevent concurrent overspend.
3. Apply the quota gate to every metered API operation, fail closed on ledger outage, and preserve idempotent retries.
4. Add tenant-scoped customer billing/plan/usage endpoints and dashboard.
5. Define provider-neutral payment adapter interfaces; implement sandbox only after provider eligibility and commercial terms are verified.
6. Test duplicate requests, concurrency, month rollover, timezone boundaries, tenant isolation, outage, plan downgrade and quota exhaustion.
7. Publish paid prices only after cost model and unit economics review.

## Non-goals

No payment gateway, checkout, subscription charge, refund, invoice, card-data handling, production migration, or JAS Platform integration is enabled by this phase.
