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
                    """SELECT effective.rolname, effective.rolsuper, effective.rolbypassrls,
                          effective.rolcanlogin, effective.rolcreatedb,
                          effective.rolcreaterole, effective.rolreplication,
                          effective.rolinherit,
                          EXISTS (SELECT 1 FROM pg_auth_members AS membership
                                  WHERE membership.member = effective.oid) AS effective_has_memberships,
                          login.rolname, login.rolsuper, login.rolbypassrls,
                          login.rolcanlogin, login.rolinherit,
                          login.rolcreatedb, login.rolcreaterole, login.rolreplication,
                          (SELECT count(*) FROM pg_auth_members AS membership
                           WHERE membership.member = login.oid) AS login_membership_count,
                          EXISTS (SELECT 1 FROM pg_auth_members AS membership
                                  WHERE membership.member = login.oid
                                    AND membership.roleid = effective.oid
                                    AND NOT membership.admin_option
                                    AND NOT membership.inherit_option
                                    AND membership.set_option) AS login_has_only_settable_runtime_membership,
                          rate_table.oid IS NOT NULL,
                          pg_catalog.pg_get_userbyid(rate_table.relowner) <> effective.rolname,
                          pg_catalog.has_schema_privilege(effective.rolname,'public','USAGE'),
                          NOT pg_catalog.has_schema_privilege(effective.rolname,'public','CREATE'),
                          pg_catalog.has_table_privilege(effective.rolname,rate_table.oid,'SELECT'),
                          pg_catalog.has_table_privilege(effective.rolname,rate_table.oid,'INSERT'),
                          pg_catalog.has_table_privilege(effective.rolname,rate_table.oid,'UPDATE'),
                          NOT pg_catalog.has_table_privilege(effective.rolname,rate_table.oid,'DELETE'),
                          NOT pg_catalog.has_table_privilege(effective.rolname,rate_table.oid,'TRUNCATE'),
                          NOT pg_catalog.has_table_privilege(effective.rolname,rate_table.oid,'REFERENCES'),
                          NOT pg_catalog.has_table_privilege(effective.rolname,rate_table.oid,'TRIGGER'),
                          NOT EXISTS (
                              SELECT 1
                                FROM pg_catalog.aclexplode(
                                    COALESCE(rate_table.relacl,
                                      pg_catalog.acldefault('r',rate_table.relowner))
                                ) acl
                               WHERE acl.grantee IN (0,effective.oid)
                                 AND (
                                     acl.grantee=0
                                     OR acl.privilege_type NOT IN ('SELECT','INSERT','UPDATE')
                                     OR acl.is_grantable
                                 )
                          ),
                          NOT EXISTS (
                              SELECT 1
                                FROM pg_catalog.pg_attribute column_info
                                CROSS JOIN LATERAL pg_catalog.aclexplode(column_info.attacl) acl
                               WHERE column_info.attrelid=rate_table.oid
                                 AND column_info.attnum>0 AND NOT column_info.attisdropped
                                 AND acl.grantee IN (0,effective.oid)
                          )
                       FROM pg_catalog.pg_roles AS effective
                       JOIN pg_catalog.pg_roles AS login ON login.rolname = session_user
                       LEFT JOIN pg_catalog.pg_class AS rate_table
                         ON rate_table.oid=pg_catalog.to_regclass('public.jas_si_customer_rate_limits')
                       WHERE effective.rolname = current_user"""
                )
                row = cursor.fetchone()
        return bool(
            row
            and row[0] == "jas_si_customer_runtime"
            and not any(row[1:9])
            and row[9] != row[0]
            and not row[10] and not row[11] and row[12]
            and not row[13] and not row[14] and not row[15] and not row[16]
            and row[17] == 1 and row[18]
            and row[19] and row[20]
            and row[21] and row[22]
            and row[23] and row[24] and row[25]
            and row[26] and row[27] and row[28] and row[29]
            and row[30] and row[31]
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
