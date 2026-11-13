# JAS-SI Standalone Billing and Pricing v1.0

**Status:** Free technical quota and a basic customer portal are implemented on the PR #36 Draft branch; paid billing remains preview-only and has no live checkout or entitlement ledger.  
**Decision:** JAS-SI is independently sellable. In standalone mode, JAS-SI owns its commerce integration and paid entitlements; for a tenant explicitly linked to JAS Platform, JAS Platform is the sole commerce authority and JAS-SI consumes authenticated entitlement decisions. The authority is mutually exclusive per tenant. See [ADR-002](ADR-002-standalone-first-international-commerce.md).

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
2. Implement the tenant-scoped commerce-authority interface: standalone JAS-SI or linked JAS Platform, never both.
3. Define provider-neutral order, event, ledger and entitlement contracts, then deterministic fake-provider tests before any live provider integration.
4. Select an international Merchant of Record only after business onboarding and Bangladesh payout-route verification. Paddle is the primary candidate; Lemon Squeezy is the fallback (see ADR-002).
5. Add a sandbox provider adapter, staging-only migration and independent reconciliation tests after credentials are supplied.
6. Publish USD prices only after cost, tax, FX, payout and unit-economics review.

## Non-goals

No live payment gateway, checkout, subscription charge, refund, invoice, card-data handling, production migration, or merchant account is enabled by this phase. Sandbox/fake-provider work may proceed only after its contract and security tests are defined.
