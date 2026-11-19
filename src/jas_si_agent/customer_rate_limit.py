"""PostgreSQL-backed shared rate limiting for customer email endpoints.

The bucket key is a keyed digest of the client IP. The raw address is never
stored, and the atomic UPSERT keeps limits consistent across serverless workers.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress


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
        """Require the dedicated database-owned rate-limit boundary."""
        import psycopg

        try:
            with psycopg.connect(self._dsn) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """SELECT
                              current_user = 'jas_si_customer_runtime'
                              AND rate_table.oid IS NOT NULL
                              AND pg_catalog.pg_get_userbyid(rate_table.relowner)
                                  = 'jas_si_customer_rate_limit_owner'
                              AND routine.oid IS NOT NULL
                              AND pg_catalog.pg_get_userbyid(routine.proowner)
                                  = 'jas_si_customer_rate_limit_owner'
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
                                  'public.jas_si_customer_rate_limits')
                           ) rate_table
                           CROSS JOIN (
                               SELECT p.oid,p.proowner,p.prosecdef,p.proconfig,p.proacl
                                 FROM pg_catalog.pg_proc p
                                WHERE p.oid=pg_catalog.to_regprocedure(
                                  'public.jas_si_customer_rate_limit_check(bytea,integer,integer)')
                           ) routine"""
                    )
                    row = cursor.fetchone()
            return bool(row and row[0])
        except Exception as exc:
            raise CustomerRateLimitError(
                "Customer rate-limit schema verification failed"
            ) from exc

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
        try:
            with psycopg.connect(self._dsn) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT allowed,retry_after_seconds "
                        "FROM public.jas_si_customer_rate_limit_check(%s::bytea,%s::integer,%s::integer)",
                        (bucket_key, limit, window_seconds),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        raise CustomerRateLimitError("Rate-limit decision was not returned")
                    allowed, retry_after = row
            return bool(allowed), int(retry_after)
        except CustomerRateLimitError:
            raise
        except Exception as exc:
            raise CustomerRateLimitError(
                "Shared customer rate-limit decision failed"
            ) from exc
