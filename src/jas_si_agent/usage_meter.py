"""Tenant-scoped PostgreSQL usage metering (technical units, not money)."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any


class UsageMeterError(RuntimeError):
    """Raised when durable usage accounting cannot be completed."""


class PostgresUsageMeter:
    """Append-only usage recorder and tenant-scoped read model."""

    def __init__(self, dsn: str) -> None:
        if not isinstance(dsn, str) or not dsn.strip():
            raise ValueError("PostgreSQL DSN is required")
        self._dsn = dsn.strip()

    def verify_schema(self) -> bool:
        import psycopg
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT to_regclass('public.jas_si_usage_events')")
                row = cur.fetchone()
                return bool(row and row[0])

    def record(
        self, *, tenant_id: str, api_key_id: str, request_id: str,
        idempotency_key: str, operation: str, units: int = 1,
    ) -> dict[str, Any]:
        allowed = {
            "authorization.evaluate", "outcome.submit",
            "github.evidence.verify",
        }
        if operation not in allowed or units != 1:
            raise ValueError("Unsupported operation or units")
        if not idempotency_key or len(idempotency_key) > 128:
            raise ValueError("A 1-128 character idempotency key is required")
        try:
            tenant = uuid.UUID(tenant_id)
            key_id = uuid.UUID(api_key_id)
        except (TypeError, ValueError):
            raise ValueError("Authenticated tenant and API key IDs must be UUIDs") from None

        event_id = uuid.uuid4()
        occurred_at = datetime.now(timezone.utc)
        try:
            import psycopg
            from psycopg.types.json import Jsonb
            with psycopg.connect(self._dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """INSERT INTO jas_si_usage_events
                           (event_id, tenant_id, api_key_id, request_id,
                            idempotency_key, operation, units, occurred_at)
                           VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                           ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
                           RETURNING event_id, operation, units, occurred_at""",
                        (event_id, tenant, key_id, request_id[:64],
                         idempotency_key, operation, units, occurred_at),
                    )
                    row = cur.fetchone()
                    if row is None:
                        cur.execute(
                            """SELECT event_id, operation, units, occurred_at
                               FROM jas_si_usage_events
                               WHERE tenant_id=%s AND idempotency_key=%s""",
                            (tenant, idempotency_key),
                        )
                        row = cur.fetchone()
                        if row is None or row[1] != operation or row[2] != units:
                            raise UsageMeterError(
                                "Idempotency key conflicts with a different usage event"
                            )
                        replayed = True
                    else:
                        replayed = False
            return {
                "event_id": str(row[0]), "operation": row[1], "units": row[2],
                "occurred_at": row[3].isoformat(), "replayed": replayed,
            }
        except UsageMeterError:
            raise
        except Exception as exc:
            raise UsageMeterError("Unable to persist usage event") from exc

    def summary(self, *, tenant_id: str, since: datetime) -> dict[str, Any]:
        tenant = uuid.UUID(tenant_id)
        try:
            import psycopg
            with psycopg.connect(self._dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """SELECT operation, COUNT(*), COALESCE(SUM(units),0),
                                  MAX(occurred_at)
                           FROM jas_si_usage_events
                           WHERE tenant_id=%s AND occurred_at >= %s
                           GROUP BY operation ORDER BY operation""",
                        (tenant, since),
                    )
                    rows = cur.fetchall()
            return {
                "tenant_id": str(tenant), "since": since.isoformat(),
                "units": sum(int(row[2]) for row in rows),
                "events": sum(int(row[1]) for row in rows),
                "by_operation": [
                    {"operation": row[0], "events": int(row[1]),
                     "units": int(row[2]),
                     "last_recorded_at": row[3].isoformat() if row[3] else None}
                    for row in rows
                ],
                "billing_status": "not_connected",
                "note": "Measured technical usage only; no monetary balance or entitlement is inferred.",
            }
        except Exception as exc:
            raise UsageMeterError("Unable to read tenant usage") from exc
