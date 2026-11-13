"""Tenant-scoped PostgreSQL usage metering with atomic monthly quota enforcement."""
from __future__ import annotations

import json
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

    def record_authenticated(
        self, *, api_key_id: str, candidate_digest: bytes, required_scope: str,
        request_id: str, idempotency_key: str, operation: str,
        request_fingerprint: str, monthly_limit: int, units: int = 1,
    ) -> dict[str, Any]:
        """Reserve usage through a DB routine that validates the bearer key and derives tenant."""
        try:
            key_id = uuid.UUID(api_key_id)
        except (TypeError, ValueError):
            raise ValueError("Authenticated API key ID must be a UUID") from None
        if not isinstance(candidate_digest, bytes) or len(candidate_digest) != 32:
            raise ValueError("Authenticated API-key digest must be 32 bytes")
        if required_scope not in {"authorization:check", "outcomes:submit", "github:evidence:verify"}:
            raise ValueError("Unsupported server-mapped usage scope")
        if operation not in {"authorization.evaluate", "outcome.submit", "github.evidence.verify"}:
            raise ValueError("Unsupported usage operation")
        if units != 1:
            raise ValueError("Usage units must be exactly one")
        if not isinstance(idempotency_key, str) or not 1 <= len(idempotency_key) <= 128:
            raise ValueError("A 1-128 character idempotency key is required")
        if not isinstance(request_fingerprint, str) or len(request_fingerprint) != 64 or any(c not in "0123456789abcdef" for c in request_fingerprint):
            raise ValueError("A lowercase SHA-256 request fingerprint is required")
        if not isinstance(monthly_limit, int) or isinstance(monthly_limit, bool) or not 1 <= monthly_limit <= 1_000_000:
            raise ValueError("Monthly quota must be between 1 and 1000000 units")
        if not isinstance(request_id, str) or not 1 <= len(request_id) <= 64:
            raise ValueError("A server-generated request ID is required")
        try:
            import psycopg
            with psycopg.connect(self._dsn) as conn, conn.cursor() as cur:
                cur.execute(
                    """SELECT event_id,operation,units,occurred_at,replayed,
                              monthly_limit,used_units,remaining_units,period_start,resets_at
                       FROM public.jas_si_api_key_usage_reserve(
                         %s::uuid,%s::bytea,%s::text,%s::text,%s::text,%s::text,%s::text,%s::bigint,%s::bigint)""",
                    (key_id,candidate_digest,required_scope,request_id,idempotency_key,
                     operation,request_fingerprint,units,monthly_limit),
                )
                row = cur.fetchone()
                if row is None:
                    raise UsageMeterError("API-key usage reservation returned no result")
            return {
                "event_id": str(row[0]), "operation": row[1], "units": int(row[2]),
                "occurred_at": row[3].isoformat(), "replayed": bool(row[4]),
                "monthly_limit": int(row[5]), "used_units": int(row[6]),
                "remaining_units": int(row[7]), "period_start": row[8].isoformat(),
                "resets_at": row[9].isoformat(),
            }
        except UsageMeterError:
            raise
        except Exception as exc:
            if getattr(exc, "sqlstate", None) == "P0001":
                try:
                    detail = json.loads(exc.diag.message_detail or "{}")
                    raise UsageQuotaExceeded(
                        monthly_limit=int(detail["monthly_limit"]),
                        used_units=int(detail["used_units"]),
                        requested_units=int(detail["requested_units"]),
                        resets_at=datetime.fromisoformat(detail["resets_at"]),
                    ) from None
                except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                    raise UsageMeterError("Usage quota routine returned invalid quota metadata") from None
            if getattr(exc, "sqlstate", None) in {"23505", "28000", "42501", "22023"}:
                raise UsageMeterError("API-key usage request was rejected by the database") from None
            raise UsageMeterError("Unable to reserve API-key-bound usage") from exc

    def summary_authenticated(
        self, *, api_key_id: str, candidate_digest: bytes, since: datetime,
        tenant_id_for_response: str,
    ) -> dict[str, Any]:
        """Read usage summary after PostgreSQL independently validates the API key."""
        try:
            key_id = uuid.UUID(api_key_id)
            response_tenant = uuid.UUID(tenant_id_for_response)
        except (TypeError, ValueError):
            raise ValueError("Authenticated API key and response tenant IDs must be UUIDs") from None
        if not isinstance(candidate_digest, bytes) or len(candidate_digest) != 32:
            raise ValueError("Authenticated API-key digest must be 32 bytes")
        if since.tzinfo is None:
            raise ValueError("Usage summary timestamp must be timezone-aware")
        try:
            import psycopg
            with psycopg.connect(self._dsn) as conn, conn.cursor() as cur:
                cur.execute(
                    """SELECT operation,event_count,total_units,last_recorded_at
                       FROM public.jas_si_api_key_usage_summary(%s::uuid,%s::bytea,'usage:read',%s::timestamptz)""",
                    (key_id,candidate_digest,since),
                )
                rows = cur.fetchall()
            items = [
                {"operation": row[0], "events": int(row[1]), "units": int(row[2]),
                 "last_recorded_at": row[3].isoformat() if row[3] else None}
                for row in rows
            ]
            return {
                "tenant_id": str(response_tenant), "since": since.isoformat(),
                "units": sum(item["units"] for item in items),
                "events": sum(item["events"] for item in items),
                "by_operation": items, "billing_status": "not_connected",
                "note": "Measured technical usage only; no monetary balance or paid entitlement is inferred.",
            }
        except Exception as exc:
            if getattr(exc, "sqlstate", None) in {"28000", "42501", "22023"}:
                raise UsageMeterError("API-key usage read was rejected by the database") from None
            raise UsageMeterError("Unable to read API-key-bound usage summary") from exc

    def quota_status_authenticated(
        self, *, api_key_id: str, candidate_digest: bytes, monthly_limit: int,
    ) -> dict[str, Any]:
        """Read quota after PostgreSQL independently validates usage:read scope."""
        try:
            key_id = uuid.UUID(api_key_id)
        except (TypeError, ValueError):
            raise ValueError("Authenticated API key ID must be a UUID") from None
        if not isinstance(candidate_digest, bytes) or len(candidate_digest) != 32:
            raise ValueError("Authenticated API-key digest must be 32 bytes")
        if not isinstance(monthly_limit, int) or isinstance(monthly_limit, bool) or not 1 <= monthly_limit <= 1_000_000:
            raise ValueError("Monthly quota must be between 1 and 1000000 units")
        try:
            import psycopg
            with psycopg.connect(self._dsn) as conn, conn.cursor() as cur:
                cur.execute(
                    """SELECT period,period_start,resets_at,monthly_limit,
                              used_units,remaining_units,exhausted
                       FROM public.jas_si_api_key_usage_quota(%s::uuid,%s::bytea,'usage:read',%s::bigint)""",
                    (key_id,candidate_digest,monthly_limit),
                )
                row = cur.fetchone()
                if row is None:
                    raise UsageMeterError("API-key quota routine returned no result")
            return {
                "period": row[0], "period_start": row[1].isoformat(),
                "resets_at": row[2].isoformat(), "monthly_limit": int(row[3]),
                "used_units": int(row[4]), "remaining_units": int(row[5]),
                "exhausted": bool(row[6]),
            }
        except UsageMeterError:
            raise
        except Exception as exc:
            if getattr(exc, "sqlstate", None) in {"28000", "42501", "22023"}:
                raise UsageMeterError("API-key quota read was rejected by the database") from None
            raise UsageMeterError("Unable to read API-key-bound quota") from exc

    def events_authenticated(
        self, *, api_key_id: str, candidate_digest: bytes, limit: int = 50,
        before: datetime | None = None, before_event_id: str | None = None,
    ) -> dict[str, Any]:
        """Read an API-key-bound keyset page; tenant identity is derived in PostgreSQL."""
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise ValueError("Usage history limit must be between 1 and 100")
        try:
            key_id = uuid.UUID(api_key_id)
            cursor_id = uuid.UUID(before_event_id) if before_event_id else None
        except (TypeError, ValueError):
            raise ValueError("Invalid API key or usage history cursor UUID") from None
        if not isinstance(candidate_digest, bytes) or len(candidate_digest) != 32:
            raise ValueError("Authenticated API-key digest must be 32 bytes")
        if (before is None) != (cursor_id is None):
            raise ValueError("Both usage history cursor fields must be provided together")
        if before is not None and before.tzinfo is None:
            raise ValueError("Usage history cursor timestamp must be timezone-aware")
        try:
            import psycopg
            with psycopg.connect(self._dsn) as conn, conn.cursor() as cur:
                cur.execute(
                    """SELECT event_id,request_id,operation,units,occurred_at
                       FROM public.jas_si_api_key_usage_events(%s::uuid,%s::bytea,'usage:read',%s::integer,%s::timestamptz,%s::uuid)""",
                    (key_id,candidate_digest,limit,
                     before.astimezone(timezone.utc) if before else None,cursor_id),
                )
                rows = cur.fetchall()
            has_more = len(rows)>limit
            page = rows[:limit]
            items = [{"event_id":str(r[0]),"request_id":r[1],"operation":r[2],
                      "units":int(r[3]),"occurred_at":r[4].isoformat()} for r in page]
            next_cursor = None
            if has_more and page:
                next_cursor={"before":page[-1]["occurred_at"],"before_event_id":page[-1]["event_id"]}
            return {"items":items,"next_cursor":next_cursor}
        except Exception as exc:
            if getattr(exc, "sqlstate", None) in {"28000", "42501", "22023"}:
                raise UsageMeterError("API-key usage history read was rejected by the database") from None
            raise UsageMeterError("Unable to read API-key-bound usage history") from exc


    def verify_api_key_usage_routines(self) -> bool:
        """Fail closed unless all key-bound usage routines and owner grants are hardened."""
        import psycopg
        query = """WITH expected(signature) AS (
            VALUES
              ('public.jas_si_api_key_usage_reserve(uuid,bytea,text,text,text,text,text,bigint,bigint)'),
              ('public.jas_si_api_key_usage_summary(uuid,bytea,text,timestamptz)'),
              ('public.jas_si_api_key_usage_quota(uuid,bytea,text,bigint)'),
              ('public.jas_si_api_key_usage_events(uuid,bytea,text,integer,timestamptz,uuid)')
        ), resolved AS (
            SELECT signature,pg_catalog.to_regprocedure(signature) AS oid
              FROM expected
        ), inspected AS (
            SELECT p.oid,p.prosecdef,p.proconfig,owner.rolname,
                   owner.rolcanlogin,owner.rolsuper,owner.rolcreatedb,
                   owner.rolcreaterole,owner.rolreplication,owner.rolbypassrls,
                   owner.rolinherit,
                   pg_catalog.has_function_privilege('jas_si_runtime',p.oid,'EXECUTE') AS runtime_execute,
                   EXISTS (
                       SELECT 1 FROM pg_catalog.aclexplode(
                           COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))
                       ) acl WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'
                   ) AS public_execute,
                   EXISTS (
                       SELECT 1 FROM pg_catalog.pg_auth_members m
                        WHERE m.member=owner.oid OR m.roleid=owner.oid
                   ) AS owner_has_membership
              FROM resolved r
              JOIN pg_catalog.pg_proc p ON p.oid=r.oid
              JOIN pg_catalog.pg_roles owner ON owner.oid=p.proowner
        )
        SELECT
          (SELECT pg_catalog.count(*) FROM inspected)=4
          AND COALESCE(pg_catalog.bool_and(
              prosecdef
              AND proconfig @> ARRAY['search_path=pg_catalog']::text[]
              AND rolname='jas_si_api_key_usage_owner'
              AND NOT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb
              AND NOT rolcreaterole AND NOT rolreplication
              AND NOT rolbypassrls AND NOT rolinherit
              AND NOT owner_has_membership
              AND runtime_execute AND NOT public_execute
          ),false)
          AND pg_catalog.has_schema_privilege('jas_si_api_key_usage_owner','public','USAGE')
          AND NOT pg_catalog.has_schema_privilege('jas_si_api_key_usage_owner','public','CREATE')
          AND pg_catalog.has_column_privilege('jas_si_api_key_usage_owner','public.jas_si_api_keys','key_id','SELECT')
          AND pg_catalog.has_column_privilege('jas_si_api_key_usage_owner','public.jas_si_api_keys','tenant_id','SELECT')
          AND pg_catalog.has_column_privilege('jas_si_api_key_usage_owner','public.jas_si_api_keys','secret_digest','SELECT')
          AND pg_catalog.has_column_privilege('jas_si_api_key_usage_owner','public.jas_si_api_keys','pepper_version','SELECT')
          AND pg_catalog.has_column_privilege('jas_si_api_key_usage_owner','public.jas_si_api_keys','scopes','SELECT')
          AND pg_catalog.has_column_privilege('jas_si_api_key_usage_owner','public.jas_si_api_keys','status','SELECT')
          AND pg_catalog.has_column_privilege('jas_si_api_key_usage_owner','public.jas_si_api_keys','expires_at','SELECT')
          AND pg_catalog.has_column_privilege('jas_si_api_key_usage_owner','public.jas_si_tenants','tenant_id','SELECT')
          AND pg_catalog.has_column_privilege('jas_si_api_key_usage_owner','public.jas_si_tenants','status','SELECT')
          AND pg_catalog.has_column_privilege('jas_si_api_key_usage_owner','public.jas_si_usage_events','event_id','SELECT')
          AND pg_catalog.has_column_privilege('jas_si_api_key_usage_owner','public.jas_si_usage_events','tenant_id','SELECT')
          AND pg_catalog.has_column_privilege('jas_si_api_key_usage_owner','public.jas_si_usage_events','api_key_id','SELECT')
          AND pg_catalog.has_column_privilege('jas_si_api_key_usage_owner','public.jas_si_usage_events','request_id','SELECT')
          AND pg_catalog.has_column_privilege('jas_si_api_key_usage_owner','public.jas_si_usage_events','idempotency_key','SELECT')
          AND pg_catalog.has_column_privilege('jas_si_api_key_usage_owner','public.jas_si_usage_events','operation','SELECT')
          AND pg_catalog.has_column_privilege('jas_si_api_key_usage_owner','public.jas_si_usage_events','units','SELECT')
          AND pg_catalog.has_column_privilege('jas_si_api_key_usage_owner','public.jas_si_usage_events','occurred_at','SELECT')
          AND pg_catalog.has_column_privilege('jas_si_api_key_usage_owner','public.jas_si_usage_events','request_fingerprint','SELECT')
          AND pg_catalog.has_column_privilege('jas_si_api_key_usage_owner','public.jas_si_usage_events','event_id','INSERT')
          AND pg_catalog.has_column_privilege('jas_si_api_key_usage_owner','public.jas_si_usage_events','tenant_id','INSERT')
          AND pg_catalog.has_column_privilege('jas_si_api_key_usage_owner','public.jas_si_usage_events','api_key_id','INSERT')
          AND pg_catalog.has_column_privilege('jas_si_api_key_usage_owner','public.jas_si_usage_events','request_id','INSERT')
          AND pg_catalog.has_column_privilege('jas_si_api_key_usage_owner','public.jas_si_usage_events','idempotency_key','INSERT')
          AND pg_catalog.has_column_privilege('jas_si_api_key_usage_owner','public.jas_si_usage_events','operation','INSERT')
          AND pg_catalog.has_column_privilege('jas_si_api_key_usage_owner','public.jas_si_usage_events','units','INSERT')
          AND pg_catalog.has_column_privilege('jas_si_api_key_usage_owner','public.jas_si_usage_events','occurred_at','INSERT')
          AND pg_catalog.has_column_privilege('jas_si_api_key_usage_owner','public.jas_si_usage_events','request_fingerprint','INSERT')
          AND NOT EXISTS (
              SELECT 1
                FROM pg_catalog.pg_class c
                CROSS JOIN LATERAL pg_catalog.aclexplode(
                    COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))
                ) acl
               WHERE c.oid IN (
                   'public.jas_si_api_keys'::regclass,
                   'public.jas_si_tenants'::regclass,
                   'public.jas_si_usage_events'::regclass
               )
                 AND acl.grantee IN (
                     0,
                     (SELECT oid FROM pg_catalog.pg_roles
                       WHERE rolname='jas_si_api_key_usage_owner')
                 )
          )
          AND NOT EXISTS (
              SELECT 1
                FROM pg_catalog.pg_class c
                JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
                JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid
                CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
               WHERE n.nspname='public'
                 AND c.relname IN ('jas_si_api_keys','jas_si_tenants','jas_si_usage_events')
                 AND a.attnum>0 AND NOT a.attisdropped
                 AND acl.grantee IN (
                     0,
                     (SELECT oid FROM pg_catalog.pg_roles
                       WHERE rolname='jas_si_api_key_usage_owner')
                 )
                 AND NOT (
                     (c.relname='jas_si_api_keys'
                      AND a.attname IN ('key_id','tenant_id','secret_digest','pepper_version','scopes','status','expires_at')
                      AND acl.privilege_type='SELECT' AND NOT acl.is_grantable)
                  OR (c.relname='jas_si_tenants'
                      AND a.attname IN ('tenant_id','status')
                      AND acl.privilege_type='SELECT' AND NOT acl.is_grantable)
                  OR (c.relname='jas_si_usage_events'
                      AND a.attname IN ('event_id','tenant_id','api_key_id','request_id','idempotency_key','operation','units','occurred_at','request_fingerprint')
                      AND acl.privilege_type IN ('SELECT','INSERT') AND NOT acl.is_grantable)
                 )
          )
        FROM inspected
        """
        try:
            with psycopg.connect(self._dsn) as conn, conn.cursor() as cur:
                cur.execute(query)
                row = cur.fetchone()
                return bool(row and row[0])
        except Exception:
            return False
