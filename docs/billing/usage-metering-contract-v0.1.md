# JAS-SI Usage Metering Contract v0.1

**Status:** Technical metering and Free quota enforcement implementation under review. This is not a monetary billing ledger or paid entitlement system.

## 1. Ownership boundary
- Standalone JAS-SI measures technical service consumption, enforces the default Free monthly quota, and maintains immutable tenant-bound usage events.
- Paid plans remain preview-only. No subscription, payment, invoice, purchased credit, or monetary balance is currently active.
- A future JAS Platform adapter may become the authority for cross-product paid entitlements and financial records; that integration is not active in this phase.
- JAS-SI must never infer payment from a browser redirect, customer-supplied claim, or local credit counter.
- An entitlement decision may permit or deny a service request; it never overrides JAS-SI authorization.

## 2. Event contract
A technical usage event is atomically reserved by the server after API-key authentication and request-schema validation, before the metered API handler executes. Tenant and API-key identifiers are derived from authenticated API-key registry context, never accepted from request JSON. One admitted operation consumes one technical unit even if its subsequent evaluation fails; failed authentication and invalid requests do not consume quota.

| Field | Type | Rule |
|---|---|---|
| event_id | UUID | Server generated, immutable |
| tenant_id | UUID | From authenticated key context |
| api_key_id | UUID | From authenticated key context |
| request_id | string | Server correlation ID; never a credential |
| idempotency_key | string | Optional client-supplied Idempotency-Key; server request ID fallback; bounded length |
| operation | enum | Server allow-list: authorization.evaluate, outcome.submit, github.evidence.verify |
| units | positive integer | Server calculated; never customer supplied |
| occurred_at | UTC timestamp | Server time |
| recorded_at | UTC timestamp | Database insertion time |
| schema_version | integer | Starts at 1 |
| metadata | object | Strict allow-list; no prompts, evidence contents, API keys, payment data, or arbitrary request bodies |

The uniqueness boundary is (tenant_id, idempotency_key). The key is bound to the authenticated api_key_id, server-calculated SHA-256 fingerprint of the exact request body, operation, and units. Repeating the same key from the same API key with the same request body returns the original event. Reusing a key with a different API key, request body, operation, or units is a conflict and must not silently overwrite or double count. When a client supplies an Idempotency-Key, it is used for retry-safe replay; if omitted, JAS-SI uses its server-generated request ID, so separate retries are counted as separate technical requests. This optional-header behavior applies to the current technical telemetry and must be revisited before any customer-billable operation is introduced. The request fingerprint is stored as a digest only; raw request bodies are not persisted in usage events.

## 3. Accounting semantics
1. Authenticate the API key and derive tenant context.
2. Validate request schema and enforce rate limits.
3. Calculate the exact request-body SHA-256 fingerprint; do not persist the raw body.
4. In one PostgreSQL transaction, take a tenant-scoped advisory lock, check exact idempotency replay, count UTC-calendar-month usage, and append the usage event if the request is within the Free allowance.
5. If quota is exhausted, return HTTP 429 before the operation handler; if durable quota storage is unavailable, fail closed with HTTP 503.
6. Execute the JAS-SI authorization/verification operation and persist its security audit event.
7. Return the usage event ID and quota headers; never return a local monetary balance.

Exact replay returns the original event without consuming another unit, including when the tenant has since reached the quota. Reuse of the same key with a different API key, body, operation, or units is a conflict. Failed authentication, rate-limited requests, and schema-invalid input do not consume quota. A syntactically valid admitted request consumes one technical unit even if its later authorization/verification evaluation fails. Internal health checks and synthetic demo traffic are excluded.

## 4. Storage and query rules
- Append-only event table; no update/delete API.
- Unique idempotency constraint and tenant/time index.
- Runtime role receives only minimum INSERT/SELECT privileges required.
- Customer queries must be tenant-scoped using authenticated tenant context; a tenant identifier in query parameters must never authorize access.
- Usage summaries aggregate recorded units by operation and time window. They are usage reports, not invoices or payment balances.
- Reconciliation compares JAS-SI usage events with JAS Platform entitlement-consumption acknowledgements using stable event IDs/idempotency keys.

## 5. JAS Platform integration boundary
The integration requires a reviewed, versioned server-to-server contract with service authentication and key rotation; tenant identity mapping; entitlement check/reserve and settle/release semantics; idempotency and replay behavior; authoritative denial/expiry/suspension states; timeout, retry, conflict and outage behavior; and reconciliation.

Until that contract exists, the adapter may run only as a test fake. It must not grant paid quota or claim a real customer entitlement.

## 6. API and dashboard requirements
Current API surfaces: public read-only `GET /plans`; authenticated `GET /v1/usage` tenant-scoped technical usage summary; metered authorization, outcome and GitHub evidence operations. Paginated event history and the customer-facing billing/plan dashboard remain future work.

The future customer dashboard must display the UTC quota period and reset time; monthly limit, used units and remaining units; units by operation; event count and last recorded event; data freshness; and a clear distinction between measured technical usage and any future Platform-provided paid entitlement.

No fake balance, fake invoice, or mock paid status is permitted.

## 7. Security, correctness and test gates
Required before production: cross-tenant isolation; duplicate idempotency replay and conflicting-key tests; transaction rollback and storage outage tests; concurrent duplicate submissions; timestamp and time-window boundary tests; append-only privilege checks; no secret/prompt/payment-data leakage; entitlement timeout/denial/replay tests against a contract fake; reconciliation mismatch detection; usage summary correctness against seeded PostgreSQL events.

## 8. Explicit non-goals
This contract does not add checkout, payment provider adapters, subscriptions, refunds, invoices, settlement, a financial ledger, or a JAS-SI-owned paid-credit balance. Those remain JAS Platform responsibilities.