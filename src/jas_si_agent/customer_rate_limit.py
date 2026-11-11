"""PostgreSQL-backed shared rate limiting for customer email endpoints.

The bucket key is a keyed digest of the client IP. The raw address is never
stored, and the atomic UPSERT keeps limits consistent across serverless workers.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
from datetime import datetime, timedelta, timezone
from math import ceil


class CustomerRateLimitError(RuntimeError):
    """The shared rate-limit service cannot make a reliable decision."""


class PostgresCustomerRateLimiter:
    def __init__(self, dsn: str, pepper: bytes) -> None:
        if not isinstance(dsn, str) or not dsn.strip():
            raise CustomerRateLimitError("Database DSN is required")
        if not isinstance(pepper, bytes) or len(pepper) < 32:
            raise CustomerRateLimitError("Rate-limit pepper must contain at least 32 bytes")
        self._dsn = dsn.strip()
        self._pepper = pepper

    def _bucket_key(self, client_ip: str) -> bytes:
        try:
            normalized = ipaddress.ip_address(client_ip).compressed
        except ValueError:
            raise CustomerRateLimitError("A valid client IP address is required") from None
        return hmac.new(
            self._pepper,
            b"jas-si/customer-email-rate-limit/v1:" + normalized.encode("ascii"),
            hashlib.sha256,
        ).digest()

    def verify_schema(self) -> bool:
        import psycopg

        with psycopg.connect(self._dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """SELECT current_user, r.rolsuper, r.rolbypassrls,
                              r.rolcanlogin,
                              EXISTS (
                                  SELECT 1 FROM pg_auth_members AS membership
                                  WHERE membership.member = r.oid
                              ) AS has_inherited_role,
                              to_regclass('public.jas_si_customer_rate_limits')
                       FROM pg_roles AS r
                       WHERE r.rolname = current_user"""
                )
                row = cursor.fetchone()
        return bool(
            row
            and row[0] == "jas_si_customer_runtime"
            and not row[1]
            and not row[2]
            and not row[3]
            and not row[4]
            and row[5]
        )

    def check(
        self,
        client_ip: str,
        *,
        limit: int,
        window_seconds: int,
    ) -> tuple[bool, int]:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise CustomerRateLimitError("Rate limit must be a positive integer")
        if (
            isinstance(window_seconds, bool)
            or not isinstance(window_seconds, int)
            or window_seconds < 1
        ):
            raise CustomerRateLimitError("Rate-limit window must be a positive integer")

        import psycopg

        bucket_key = self._bucket_key(client_ip)
        now = datetime.now(timezone.utc)
        try:
            with psycopg.connect(self._dsn) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO jas_si_customer_rate_limits
                            (bucket_key, window_started_at, request_count, updated_at)
                        VALUES (%s, NOW(), 1, NOW())
                        ON CONFLICT (bucket_key) DO UPDATE SET
                            window_started_at = CASE
                                WHEN jas_si_customer_rate_limits.window_started_at
                                     <= NOW() - (%s * INTERVAL '1 second')
                                THEN NOW()
                                ELSE jas_si_customer_rate_limits.window_started_at
                            END,
                            request_count = CASE
                                WHEN jas_si_customer_rate_limits.window_started_at
                                     <= NOW() - (%s * INTERVAL '1 second')
                                THEN 1
                                ELSE jas_si_customer_rate_limits.request_count + 1
                            END,
                            updated_at = NOW()
                        RETURNING request_count, window_started_at
                        """,
                        (bucket_key, window_seconds, window_seconds),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        raise CustomerRateLimitError("Rate-limit decision was not returned")
                    count, window_started_at = row
            allowed = count <= limit
            retry_after = max(
                1,
                ceil(
                    (
                        window_started_at
                        + timedelta(seconds=window_seconds)
                        - now
                    ).total_seconds()
                ),
            )
            return allowed, retry_after
        except CustomerRateLimitError:
            raise
        except Exception as exc:
            raise CustomerRateLimitError(
                "Shared customer rate-limit decision failed"
            ) from exc
