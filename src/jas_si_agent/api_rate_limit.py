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
                        """SELECT
                              current_user = 'jas_si_runtime'
                              AND rate_table.oid IS NOT NULL
                              AND routine.oid IS NOT NULL
                              AND pg_catalog.pg_get_userbyid(rate_table.relowner)
                                  = 'jas_si_api_rate_limit_owner'
                              AND pg_catalog.pg_get_userbyid(routine.proowner)
                                  = 'jas_si_api_rate_limit_owner'
                              AND routine.prosecdef
                              AND routine.proconfig @> ARRAY['search_path=pg_catalog']
                              AND pg_catalog.has_function_privilege(
                                  current_user,routine.oid,'EXECUTE')
                              AND NOT EXISTS (
                                  SELECT 1 FROM pg_catalog.aclexplode(
                                      COALESCE(routine.proacl,
                                        pg_catalog.acldefault('f',routine.proowner))
                                  ) acl
                                  WHERE acl.grantee=0
                                    AND acl.privilege_type='EXECUTE'
                              )
                              AND NOT pg_catalog.has_table_privilege(
                                  current_user,rate_table.oid,'SELECT')
                              AND NOT pg_catalog.has_table_privilege(
                                  current_user,rate_table.oid,'INSERT')
                              AND NOT pg_catalog.has_table_privilege(
                                  current_user,rate_table.oid,'UPDATE')
                              AND NOT pg_catalog.has_table_privilege(
                                  current_user,rate_table.oid,'DELETE')
                              AND NOT pg_catalog.has_table_privilege(
                                  current_user,rate_table.oid,'TRUNCATE')
                              AND NOT pg_catalog.has_any_column_privilege(
                                  current_user,rate_table.oid,'SELECT')
                              AND NOT pg_catalog.has_any_column_privilege(
                                  current_user,rate_table.oid,'INSERT')
                              AND NOT pg_catalog.has_any_column_privilege(
                                  current_user,rate_table.oid,'UPDATE')
                           FROM (
                               SELECT c.oid,c.relowner
                                 FROM pg_catalog.pg_class c
                                WHERE c.oid=pg_catalog.to_regclass(
                                  'public.jas_si_api_rate_limits')
                           ) rate_table
                           CROSS JOIN (
                               SELECT p.oid,p.proowner,p.prosecdef,p.proconfig,p.proacl
                                 FROM pg_catalog.pg_proc p
                                WHERE p.oid=pg_catalog.to_regprocedure(
                                  'public.jas_si_api_rate_limit_check(bytea,integer,integer)')
                           ) routine"""
                    )
                    row = cursor.fetchone()
            return bool(row and row[0])
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
