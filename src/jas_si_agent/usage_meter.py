"""Tenant-scoped PostgreSQL usage metering with atomic monthly quota enforcement."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any


class UsageMeterError(RuntimeError):
    """Raised when durable usage accounting cannot be completed."""


class UsageQuotaExceeded(UsageMeterError):
    """Raised when a tenant has exhausted its current UTC-month allowance."""

    def __init__(self, *, monthly_limit: int, used_units: int, requested_units: int, resets_at: datetime):
        self.monthly_limit = monthly_limit
        self.used_units = used_units
        self.requested_units = requested_units
        self.resets_at = resets_at
        super().__init__("The tenant monthly usage quota has been exceeded")


def _utc_month_window(now: datetime) -> tuple[datetime, datetime]:
    if now.tzinfo is None:
        raise ValueError("Quota clock must be timezone-aware")
    current = now.astimezone(timezone.utc)
    start = current.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if start.month == 12:
        end = start.replace(year=start.year + 1, month=1)
    else:
        end = start.replace(month=start.month + 1)
    return start, end


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
        idempotency_key: str, operation: str, request_fingerprint: str,
        monthly_limit: int, units: int = 1,
    ) -> dict[str, Any]:
        allowed = {
            "authorization.evaluate", "outcome.submit",
            "github.evidence.verify",
        }
        if operation not in allowed or units != 1:
            raise ValueError("Unsupported operation or units")
        if not isinstance(idempotency_key, str) or not idempotency_key or len(idempotency_key) > 128:
            raise ValueError("A 1-128 character idempotency key is required")
        if (
            not isinstance(request_fingerprint, str)
            or len(request_fingerprint) != 64
            or any(char not in "0123456789abcdef" for char in request_fingerprint)
        ):
            raise ValueError("A lowercase SHA-256 request fingerprint is required")
        if not isinstance(monthly_limit, int) or isinstance(monthly_limit, bool) or not 1 <= monthly_limit <= 1_000_000:
            raise ValueError("Monthly quota must be between 1 and 1000000 units")
        if not isinstance(request_id, str) or not request_id:
            raise ValueError("A server-generated request ID is required")
        try:
            tenant = uuid.UUID(tenant_id)
            key_id = uuid.UUID(api_key_id)
        except (TypeError, ValueError):
            raise ValueError("Authenticated tenant and API key IDs must be UUIDs") from None

        now = datetime.now(timezone.utc)
        period_start, period_end = _utc_month_window(now)
        event_id = uuid.uuid4()
        try:
            import psycopg
            with psycopg.connect(self._dsn) as conn:
                with conn.cursor() as cur:
                    # Serialize quota reservations for one tenant until commit.
                    cur.execute(
                        "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                        (str(tenant),),
                    )

                    # Exact retries do not consume another unit, even at quota.
                    cur.execute(
                        """SELECT event_id, api_key_id, operation, units,
                                  request_fingerprint, occurred_at
                           FROM jas_si_usage_events
                           WHERE tenant_id=%s AND idempotency_key=%s""",
                        (tenant, idempotency_key),
                    )
                    existing = cur.fetchone()
                    if existing is not None:
                        if (
                            existing[1] != key_id
                            or existing[2] != operation
                            or existing[3] != units
                            or existing[4] != request_fingerprint
                        ):
                            raise UsageMeterError(
                                "Idempotency key conflicts with a different usage event"
                            )
                        cur.execute(
                            """SELECT COALESCE(SUM(units), 0)
                               FROM jas_si_usage_events
                               WHERE tenant_id=%s AND occurred_at >= %s
                                 AND occurred_at < %s""",
                            (tenant, period_start, period_end),
                        )
                        used = int(cur.fetchone()[0])
                        return {
                            "event_id": str(existing[0]), "operation": existing[2],
                            "units": existing[3], "occurred_at": existing[5].isoformat(),
                            "replayed": True, "monthly_limit": monthly_limit,
                            "used_units": used,
                            "remaining_units": max(0, monthly_limit - used),
                            "period_start": period_start.isoformat(),
                            "resets_at": period_end.isoformat(),
                        }

                    cur.execute(
                        """SELECT COALESCE(SUM(units), 0)
                           FROM jas_si_usage_events
                           WHERE tenant_id=%s AND occurred_at >= %s
                             AND occurred_at < %s""",
                        (tenant, period_start, period_end),
                    )
                    used = int(cur.fetchone()[0])
                    if used + units > monthly_limit:
                        raise UsageQuotaExceeded(
                            monthly_limit=monthly_limit,
                            used_units=used,
                            requested_units=units,
                            resets_at=period_end,
                        )

                    cur.execute(
                        """INSERT INTO jas_si_usage_events
                           (event_id, tenant_id, api_key_id, request_id,
                            idempotency_key, operation, units, occurred_at,
                            request_fingerprint)
                           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                           RETURNING event_id, operation, units, occurred_at""",
                        (event_id, tenant, key_id, request_id[:64],
                         idempotency_key, operation, units, now,
                         request_fingerprint),
                    )
                    row = cur.fetchone()
            return {
                "event_id": str(row[0]), "operation": row[1], "units": row[2],
                "occurred_at": row[3].isoformat(), "replayed": False,
                "monthly_limit": monthly_limit, "used_units": used + units,
                "remaining_units": max(0, monthly_limit - used - units),
                "period_start": period_start.isoformat(),
                "resets_at": period_end.isoformat(),
            }
        except (UsageMeterError, ValueError):
            raise
        except Exception as exc:
            raise UsageMeterError("Unable to persist and enforce tenant usage quota") from exc

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
                "note": "Measured technical usage only; no monetary balance or paid entitlement is inferred.",
            }
        except Exception as exc:
            raise UsageMeterError("Unable to read tenant usage") from exc
