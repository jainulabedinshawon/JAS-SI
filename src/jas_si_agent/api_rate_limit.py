"""PostgreSQL-backed shared sliding-window rate limiting for public API routes.

Only a keyed IP digest is persisted. Atomic decisions are made by a narrowly
privileged SECURITY DEFINER routine so serverless workers share one limit.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress


class ApiRateLimitError(RuntimeError):
    """A reliable shared API rate-limit decision could not be made."""


class PostgresApiRateLimiter:
    def __init__(self, dsn: str, pepper: bytes) -> None:
        if not isinstance(dsn, str) or not dsn.strip():
            raise ApiRateLimitError("Database DSN is required")
        if not isinstance(pepper, bytes) or len(pepper) < 32:
            raise ApiRateLimitError("API rate-limit pepper must contain at least 32 bytes")
        self._dsn = dsn.strip()
        self._pepper = pepper

    def _bucket_key(self, client_ip: str) -> bytes:
        try:
            normalized = ipaddress.ip_address(client_ip).compressed
        except ValueError:
            raise ApiRateLimitError("A valid client IP address is required") from None
        return hmac.new(
            self._pepper,
            b"jas-si/api-rate-limit/v1:" + normalized.encode("ascii"),
            hashlib.sha256,
        ).digest()

    def verify_schema(self) -> bool:
        import psycopg

        try:
            with psycopg.connect(self._dsn) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """SELECT current_user,
                                  pg_catalog.to_regclass('public.jas_si_api_rate_limits') IS NOT NULL,
                                  pg_catalog.to_regprocedure('public.jas_si_api_rate_limit_check(bytea,integer,integer)') IS NOT NULL,
                                  pg_catalog.has_function_privilege(current_user,
                                    'public.jas_si_api_rate_limit_check(bytea,integer,integer)','EXECUTE'),
                                  NOT pg_catalog.has_table_privilege(current_user,
                                    'public.jas_si_api_rate_limits','SELECT'),
                                  NOT pg_catalog.has_table_privilege(current_user,
                                    'public.jas_si_api_rate_limits','INSERT'),
                                  NOT pg_catalog.has_table_privilege(current_user,
                                    'public.jas_si_api_rate_limits','UPDATE'),
                                  NOT pg_catalog.has_table_privilege(current_user,
                                    'public.jas_si_api_rate_limits','DELETE'),
                                  NOT pg_catalog.has_table_privilege(current_user,
                                    'public.jas_si_api_rate_limits','TRUNCATE'),
                                  pg_catalog.pg_get_userbyid(
                                    (SELECT relowner FROM pg_catalog.pg_class
                                     WHERE oid=pg_catalog.to_regclass('public.jas_si_api_rate_limits'))
                                  ) = 'jas_si_api_rate_limit_owner'"""
                    )
                    row = cursor.fetchone()
            return bool(row and row[1] and row[2] and row[3]
                        and all(row[4:10]))
        except Exception as exc:
            raise ApiRateLimitError("API rate-limit schema verification failed") from exc

    def check(
        self, client_ip: str, *, limit: int, window_seconds: int
    ) -> tuple[bool, int, int]:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ApiRateLimitError("Rate limit must be a positive integer")
        if isinstance(window_seconds, bool) or not isinstance(window_seconds, int) or window_seconds < 1:
            raise ApiRateLimitError("Rate-limit window must be a positive integer")
        import psycopg

        try:
            with psycopg.connect(self._dsn) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT allowed, remaining, retry_after_seconds "
                        "FROM public.jas_si_api_rate_limit_check(%s, %s, %s)",
                        (self._bucket_key(client_ip), limit, window_seconds),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        raise ApiRateLimitError("Rate-limit decision was not returned")
                    return bool(row[0]), int(row[1]), int(row[2])
        except ApiRateLimitError:
            raise
        except Exception as exc:
            raise ApiRateLimitError("Shared API rate-limit decision failed") from exc
