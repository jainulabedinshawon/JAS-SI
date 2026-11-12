from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

class CustomerIdentityError(ValueError):
    """Invalid customer identity or failed identity operation."""


class CustomerIdentityConflict(CustomerIdentityError):
    """A customer identity already exists or conflicts with registration."""

@dataclass(frozen=True)
class CustomerLink:
    account_id: uuid.UUID
    email: str
    purpose: str
    token: str
    expires_at: datetime

@dataclass(frozen=True)
class CustomerAccount:
    account_id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    organization_name: str
    status: str

@dataclass(frozen=True)
class CustomerSession:
    account: CustomerAccount
    token: str
    expires_at: datetime

def normalize_email(email: str) -> str:
    value = email.strip().lower() if isinstance(email, str) else ""
    if len(value) > 254 or not _EMAIL_RE.fullmatch(value):
        raise CustomerIdentityError("A valid email address is required")
    return value

def normalize_organization_name(name: str) -> str:
    value = " ".join(name.split()) if isinstance(name, str) else ""
    if not value or len(value) > 160:
        raise CustomerIdentityError("Organization name must contain 1 to 160 characters")
    return value

class PostgresCustomerIdentityStore:
    """JAS-SI-owned customer accounts, one-time links and browser sessions."""
    def __init__(self, dsn: str, pepper: bytes, *, verification_ttl: timedelta = timedelta(hours=24), login_ttl: timedelta = timedelta(minutes=15), session_ttl: timedelta = timedelta(days=7)) -> None:
        if not isinstance(dsn, str) or not dsn.strip():
            raise CustomerIdentityError("Database DSN is required")
        if not isinstance(pepper, bytes) or len(pepper) < 32:
            raise CustomerIdentityError("Customer token pepper must contain at least 32 bytes")
        if min(verification_ttl.total_seconds(), login_ttl.total_seconds(), session_ttl.total_seconds()) <= 0:
            raise CustomerIdentityError("Token and session TTLs must be positive")
        self._dsn, self._pepper = dsn.strip(), pepper
        self._verification_ttl, self._login_ttl, self._session_ttl = verification_ttl, login_ttl, session_ttl

    def _digest(self, token: str) -> bytes:
        return hmac.new(self._pepper, token.encode("utf-8"), hashlib.sha256).digest()

    @staticmethod
    def _new_token() -> str:
        return secrets.token_urlsafe(32)

    def verify_schema(self) -> bool:
        """Fail closed unless connected as the dedicated least-privilege identity role."""
        import psycopg
        with psycopg.connect(self._dsn) as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT effective.rolname, effective.rolsuper, effective.rolbypassrls,
                          effective.rolcanlogin,
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
                          to_regclass('public.jas_si_customer_accounts'),
                          to_regclass('public.jas_si_customer_auth_tokens'),
                          to_regclass('public.jas_si_customer_sessions'),
                          to_regclass('public.jas_si_customer_rate_limits')
                   FROM pg_roles AS effective
                   JOIN pg_roles AS login ON login.rolname = session_user
                   WHERE effective.rolname = current_user"""
            )
            row = cur.fetchone()
            return bool(
                row
                and row[0] == "jas_si_customer_runtime"
                and not row[1] and not row[2] and not row[3] and not row[4]
                and row[5] != row[0]
                and not row[6] and not row[7] and row[8]
                and not row[9] and not row[10] and not row[11] and not row[12]
                and row[13] == 1 and row[14] and all(row[15:])
            )

    def verify_security_boundary(self) -> bool:
        """Fail closed until the complete database-owned identity boundary exists.

        Removing direct table grants is necessary but not sufficient: all five
        SECURITY DEFINER routines, their trusted owner, hardened search_path,
        runtime EXECUTE grants, and absence of PUBLIC EXECUTE are required too.
        """
        import psycopg
        with psycopg.connect(self._dsn) as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT
                       to_regclass('public.jas_si_customer_accounts') IS NOT NULL,
                       to_regclass('public.jas_si_customer_auth_tokens') IS NOT NULL,
                       to_regclass('public.jas_si_customer_sessions') IS NOT NULL,
                       to_regclass('public.jas_si_tenants') IS NOT NULL,
                       has_table_privilege(current_user, 'public.jas_si_customer_accounts', 'SELECT') OR EXISTS (SELECT 1 FROM pg_attribute AS column_info WHERE column_info.attrelid = 'public.jas_si_customer_accounts'::regclass AND column_info.attnum > 0 AND NOT column_info.attisdropped AND has_column_privilege(current_user, 'public.jas_si_customer_accounts', column_info.attname, 'SELECT'))
                         OR has_table_privilege(current_user, 'public.jas_si_customer_accounts', 'INSERT') OR EXISTS (SELECT 1 FROM pg_attribute AS column_info WHERE column_info.attrelid = 'public.jas_si_customer_accounts'::regclass AND column_info.attnum > 0 AND NOT column_info.attisdropped AND has_column_privilege(current_user, 'public.jas_si_customer_accounts', column_info.attname, 'INSERT'))
                         OR has_table_privilege(current_user, 'public.jas_si_customer_accounts', 'UPDATE') OR EXISTS (SELECT 1 FROM pg_attribute AS column_info WHERE column_info.attrelid = 'public.jas_si_customer_accounts'::regclass AND column_info.attnum > 0 AND NOT column_info.attisdropped AND has_column_privilege(current_user, 'public.jas_si_customer_accounts', column_info.attname, 'UPDATE'))
                         OR has_table_privilege(current_user, 'public.jas_si_customer_accounts', 'DELETE')
                         OR has_table_privilege(current_user, 'public.jas_si_customer_accounts', 'TRUNCATE')
                         OR has_table_privilege(current_user, 'public.jas_si_customer_accounts', 'REFERENCES')
                         OR has_any_column_privilege(current_user, 'public.jas_si_customer_accounts', 'REFERENCES')
                         OR has_table_privilege(current_user, 'public.jas_si_customer_accounts', 'TRIGGER'),
                       has_table_privilege(current_user, 'public.jas_si_customer_auth_tokens', 'SELECT') OR EXISTS (SELECT 1 FROM pg_attribute AS column_info WHERE column_info.attrelid = 'public.jas_si_customer_auth_tokens'::regclass AND column_info.attnum > 0 AND NOT column_info.attisdropped AND has_column_privilege(current_user, 'public.jas_si_customer_auth_tokens', column_info.attname, 'SELECT'))
                         OR has_table_privilege(current_user, 'public.jas_si_customer_auth_tokens', 'INSERT') OR EXISTS (SELECT 1 FROM pg_attribute AS column_info WHERE column_info.attrelid = 'public.jas_si_customer_auth_tokens'::regclass AND column_info.attnum > 0 AND NOT column_info.attisdropped AND has_column_privilege(current_user, 'public.jas_si_customer_auth_tokens', column_info.attname, 'INSERT'))
                         OR has_table_privilege(current_user, 'public.jas_si_customer_auth_tokens', 'UPDATE') OR EXISTS (SELECT 1 FROM pg_attribute AS column_info WHERE column_info.attrelid = 'public.jas_si_customer_auth_tokens'::regclass AND column_info.attnum > 0 AND NOT column_info.attisdropped AND has_column_privilege(current_user, 'public.jas_si_customer_auth_tokens', column_info.attname, 'UPDATE'))
                         OR has_table_privilege(current_user, 'public.jas_si_customer_auth_tokens', 'DELETE')
                         OR has_table_privilege(current_user, 'public.jas_si_customer_auth_tokens', 'TRUNCATE')
                         OR has_table_privilege(current_user, 'public.jas_si_customer_auth_tokens', 'REFERENCES')
                         OR has_any_column_privilege(current_user, 'public.jas_si_customer_auth_tokens', 'REFERENCES')
                         OR has_table_privilege(current_user, 'public.jas_si_customer_auth_tokens', 'TRIGGER'),
                       has_table_privilege(current_user, 'public.jas_si_customer_sessions', 'SELECT') OR EXISTS (SELECT 1 FROM pg_attribute AS column_info WHERE column_info.attrelid = 'public.jas_si_customer_sessions'::regclass AND column_info.attnum > 0 AND NOT column_info.attisdropped AND has_column_privilege(current_user, 'public.jas_si_customer_sessions', column_info.attname, 'SELECT'))
                         OR has_table_privilege(current_user, 'public.jas_si_customer_sessions', 'INSERT') OR EXISTS (SELECT 1 FROM pg_attribute AS column_info WHERE column_info.attrelid = 'public.jas_si_customer_sessions'::regclass AND column_info.attnum > 0 AND NOT column_info.attisdropped AND has_column_privilege(current_user, 'public.jas_si_customer_sessions', column_info.attname, 'INSERT'))
                         OR has_table_privilege(current_user, 'public.jas_si_customer_sessions', 'UPDATE') OR EXISTS (SELECT 1 FROM pg_attribute AS column_info WHERE column_info.attrelid = 'public.jas_si_customer_sessions'::regclass AND column_info.attnum > 0 AND NOT column_info.attisdropped AND has_column_privilege(current_user, 'public.jas_si_customer_sessions', column_info.attname, 'UPDATE'))
                         OR has_table_privilege(current_user, 'public.jas_si_customer_sessions', 'DELETE')
                         OR has_table_privilege(current_user, 'public.jas_si_customer_sessions', 'TRUNCATE')
                         OR has_table_privilege(current_user, 'public.jas_si_customer_sessions', 'REFERENCES')
                         OR has_any_column_privilege(current_user, 'public.jas_si_customer_sessions', 'REFERENCES')
                         OR has_table_privilege(current_user, 'public.jas_si_customer_sessions', 'TRIGGER'),
                       has_table_privilege(current_user, 'public.jas_si_tenants', 'INSERT')
                         OR has_any_column_privilege(current_user, 'public.jas_si_tenants', 'INSERT')
                """
            )
            row = cur.fetchone()
            direct_table_access_removed = bool(
                row and all(row[:4]) and not any(row[4:])
            )
            cur.execute(
                """WITH required(signature) AS (
                       VALUES
                         ('customer_register(text,text,text,uuid,uuid,uuid,bytea,timestamptz)'),
                         ('customer_issue_link(text,text,uuid,bytea,timestamptz)'),
                         ('customer_consume_link(bytea,text,uuid,bytea,timestamptz)'),
                         ('customer_authenticate_session(bytea)'),
                         ('customer_revoke_session(bytea)')
                   ),
                   routines AS (
                       SELECT signature,
                              to_regprocedure('public.' || signature) AS routine_oid
                       FROM required
                   )
                   SELECT count(procedure.oid) = 5
                      AND bool_and(
                          procedure.prosecdef
                          AND owner.rolname = 'jas_si_customer_identity_owner'
                          AND NOT owner.rolcanlogin
                          AND NOT owner.rolsuper
                          AND NOT owner.rolcreatedb
                          AND NOT owner.rolcreaterole
                          AND NOT owner.rolreplication
                          AND NOT owner.rolbypassrls
                          AND NOT owner.rolinherit
                          AND NOT EXISTS (
                              SELECT 1 FROM pg_catalog.pg_auth_members AS membership
                              WHERE membership.member = owner.oid OR membership.roleid = owner.oid
                          )
                          AND procedure.proconfig @> ARRAY['search_path=pg_catalog']
                          AND has_function_privilege(current_user, procedure.oid, 'EXECUTE')
                          AND NOT EXISTS (
                              SELECT 1
                              FROM aclexplode(
                                  COALESCE(
                                      procedure.proacl,
                                      acldefault('f', procedure.proowner)
                                  )
                              ) AS privilege
                              WHERE privilege.grantee = 0
                                AND privilege.privilege_type = 'EXECUTE'
                          )
                      )
                   FROM routines
                   LEFT JOIN pg_proc AS procedure
                     ON procedure.oid = routines.routine_oid
                   LEFT JOIN pg_roles AS owner
                     ON owner.oid = procedure.proowner"""
            )
            routines_ready = bool(cur.fetchone()[0])
        return direct_table_access_removed and routines_ready


    def verify_usage_read_boundary(self) -> bool:
        """Fail closed unless usage reads are session-bound database routines only."""
        import psycopg
        with psycopg.connect(self._dsn) as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT current_user = 'jas_si_customer_runtime'
                          AND to_regclass('public.jas_si_usage_events') IS NOT NULL
                          AND NOT (
                              has_table_privilege(current_user,'public.jas_si_usage_events','SELECT')
                              OR has_any_column_privilege(current_user,'public.jas_si_usage_events','SELECT')
                              OR has_table_privilege(current_user,'public.jas_si_usage_events','INSERT')
                              OR has_any_column_privilege(current_user,'public.jas_si_usage_events','INSERT')
                              OR has_table_privilege(current_user,'public.jas_si_usage_events','UPDATE')
                              OR has_any_column_privilege(current_user,'public.jas_si_usage_events','UPDATE')
                              OR has_table_privilege(current_user,'public.jas_si_usage_events','DELETE')
                              OR has_table_privilege(current_user,'public.jas_si_usage_events','TRUNCATE')
                              OR has_table_privilege(current_user,'public.jas_si_usage_events','REFERENCES')
                              OR has_any_column_privilege(current_user,'public.jas_si_usage_events','REFERENCES')
                              OR has_table_privilege(current_user,'public.jas_si_usage_events','TRIGGER')
                          )
                          AND has_column_privilege('jas_si_customer_identity_owner','public.jas_si_usage_events','tenant_id','SELECT')
                          AND has_column_privilege('jas_si_customer_identity_owner','public.jas_si_usage_events','event_id','SELECT')
                          AND has_column_privilege('jas_si_customer_identity_owner','public.jas_si_usage_events','request_id','SELECT')
                          AND has_column_privilege('jas_si_customer_identity_owner','public.jas_si_usage_events','operation','SELECT')
                          AND has_column_privilege('jas_si_customer_identity_owner','public.jas_si_usage_events','units','SELECT')
                          AND has_column_privilege('jas_si_customer_identity_owner','public.jas_si_usage_events','occurred_at','SELECT')"""
            )
            direct_boundary_ready = bool(cur.fetchone()[0])
            cur.execute(
                """WITH required(signature) AS (
                       VALUES
                         ('customer_usage_summary(bytea,timestamptz)'),
                         ('customer_usage_events(bytea,integer,timestamptz,uuid)')
                   ),
                   routines AS (
                       SELECT signature,to_regprocedure('public.'||signature) AS routine_oid
                       FROM required
                   )
                   SELECT count(procedure.oid)=2
                      AND bool_and(
                          procedure.prosecdef
                          AND owner.rolname='jas_si_customer_identity_owner'
                          AND NOT owner.rolcanlogin
                          AND NOT owner.rolsuper
                          AND NOT owner.rolcreatedb
                          AND NOT owner.rolcreaterole
                          AND NOT owner.rolreplication
                          AND NOT owner.rolbypassrls
                          AND NOT owner.rolinherit
                          AND NOT EXISTS (
                              SELECT 1 FROM pg_catalog.pg_auth_members AS membership
                              WHERE membership.member = owner.oid OR membership.roleid = owner.oid
                          )
                          AND procedure.proconfig @> ARRAY['search_path=pg_catalog']
                          AND has_function_privilege(current_user,procedure.oid,'EXECUTE')
                          AND NOT EXISTS (
                              SELECT 1 FROM aclexplode(
                                  COALESCE(procedure.proacl,acldefault('f',procedure.proowner))
                              ) AS privilege
                              WHERE privilege.grantee=0
                                AND privilege.privilege_type='EXECUTE'
                          )
                      )
                   FROM routines
                   LEFT JOIN pg_proc AS procedure ON procedure.oid=routines.routine_oid
                   LEFT JOIN pg_roles AS owner ON owner.oid=procedure.proowner"""
            )
            routines_ready = bool(cur.fetchone()[0])
        return direct_boundary_ready and routines_ready

    def register(self, email: str, organization_name: str) -> CustomerLink:
        normalized = normalize_email(email)
        organization = normalize_organization_name(organization_name)
        account_id, tenant_id, token_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        token = self._new_token()
        expires = datetime.now(timezone.utc) + self._verification_ttl
        import psycopg
        try:
            with psycopg.connect(self._dsn) as conn, conn.cursor() as cur:
                cur.execute("SELECT * FROM public.customer_register(%s,%s,%s,%s,%s,%s,%s,%s)", (email.strip(), normalized, organization, account_id, tenant_id, token_id, self._digest(token), expires))
                row = cur.fetchone()
            if row is None:
                raise CustomerIdentityError("Customer registration could not be completed")
            return CustomerLink(row[0], normalized, "verify_email", token, row[5])
        except Exception as exc:
            if isinstance(exc, CustomerIdentityError):
                raise
            if isinstance(exc, psycopg.errors.UniqueViolation):
                raise CustomerIdentityConflict("Customer registration conflicts with an existing account") from None
            raise CustomerIdentityError("Customer registration could not be completed") from exc

    def issue_verification_link(self, email: str) -> CustomerLink | None:
        return self._issue_link(email, "verify_email", self._verification_ttl)

    def issue_login_link(self, email: str) -> CustomerLink | None:
        return self._issue_link(email, "login", self._login_ttl)

    def _issue_link(self, email: str, purpose: str, ttl: timedelta) -> CustomerLink | None:
        normalized = normalize_email(email)
        token_id, token = uuid.uuid4(), self._new_token()
        expires = datetime.now(timezone.utc) + ttl
        import psycopg
        try:
            with psycopg.connect(self._dsn) as conn, conn.cursor() as cur:
                cur.execute("SELECT * FROM public.customer_issue_link(%s,%s,%s,%s,%s)", (normalized, purpose, token_id, self._digest(token), expires))
                row = cur.fetchone()
            return CustomerLink(row[0], row[1], purpose, token, row[4]) if row else None
        except CustomerIdentityError:
            raise
        except Exception as exc:
            raise CustomerIdentityError("Customer sign-in link could not be issued") from exc

    def verify_email(self, token: str) -> CustomerAccount:
        return self._consume_link(token, "verify_email", create_session=False)

    def consume_login_link(self, token: str) -> CustomerSession:
        return self._consume_link(token, "login", create_session=True)

    def _consume_link(self, token: str, purpose: str, *, create_session: bool):
        if not isinstance(token, str) or not 32 <= len(token) <= 128:
            raise CustomerIdentityError("Invalid or expired customer link")
        session_token = self._new_token() if create_session else None
        session_id = uuid.uuid4() if create_session else None
        session_expiry = datetime.now(timezone.utc) + self._session_ttl if create_session else None
        import psycopg
        try:
            with psycopg.connect(self._dsn) as conn, conn.cursor() as cur:
                cur.execute("SELECT * FROM public.customer_consume_link(%s,%s,%s,%s,%s)", (self._digest(token), purpose, session_id, self._digest(session_token) if session_token else None, session_expiry))
                row = cur.fetchone()
            if row is None:
                raise CustomerIdentityError("Invalid or expired customer link")
            account = CustomerAccount(row[0], row[1], row[2], row[3], row[4])
            return CustomerSession(account, session_token, row[5]) if create_session else account
        except CustomerIdentityError:
            raise
        except Exception as exc:
            raise CustomerIdentityError("Customer link could not be processed") from exc

    def authenticate_session(self, token: str) -> CustomerAccount | None:
        if not isinstance(token, str) or not 32 <= len(token) <= 128:
            return None
        import psycopg
        with psycopg.connect(self._dsn) as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM public.customer_authenticate_session(%s)", (self._digest(token),))
            row = cur.fetchone()
        return CustomerAccount(*row) if row else None

    def revoke_session(self, token: str) -> bool:
        if not isinstance(token, str) or not 32 <= len(token) <= 128:
            return False
        import psycopg
        with psycopg.connect(self._dsn) as conn, conn.cursor() as cur:
            cur.execute("SELECT public.customer_revoke_session(%s)", (self._digest(token),))
            row = cur.fetchone()
        return bool(row and row[0])

    def usage_summary(self, session_token: str, since: datetime) -> dict:
        """Read usage through a database routine bound to the live customer session."""
        if not isinstance(session_token, str) or not 32 <= len(session_token) <= 128:
            raise CustomerIdentityError("Invalid or expired customer session")
        if not isinstance(since, datetime) or since.tzinfo is None:
            raise CustomerIdentityError("Usage start time must be timezone-aware")
        import psycopg
        try:
            with psycopg.connect(self._dsn) as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM public.customer_usage_summary(%s,%s)",
                    (self._digest(session_token), since.astimezone(timezone.utc)),
                )
                row = cur.fetchone()
            if row is None:
                raise CustomerIdentityError("Customer usage session is invalid or expired")
            return {
                "tenant_id": str(row[0]),
                "since": since.astimezone(timezone.utc).isoformat(),
                "units": int(row[1]),
                "events": int(row[2]),
                "by_operation": row[3] or [],
                "current_month_units": int(row[4]),
                "billing_status": "not_connected",
                "note": "Measured technical usage only; no monetary balance or paid entitlement is inferred.",
            }
        except CustomerIdentityError:
            raise
        except Exception as exc:
            raise CustomerIdentityError("Unable to read customer usage summary") from exc

    def usage_events(
        self, session_token: str, *, limit: int = 50,
        before: datetime | None = None, before_event_id: str | None = None,
    ) -> dict:
        """Read one keyset page; the database derives tenant from the live session."""
        if not isinstance(session_token, str) or not 32 <= len(session_token) <= 128:
            raise CustomerIdentityError("Invalid or expired customer session")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise CustomerIdentityError("Usage history limit must be between 1 and 100")
        if (before is None) != (before_event_id is None):
            raise CustomerIdentityError("Both usage history cursor fields are required together")
        cursor_id = None
        if before is not None:
            if not isinstance(before, datetime) or before.tzinfo is None:
                raise CustomerIdentityError("Usage history cursor timestamp must be timezone-aware")
            try:
                cursor_id = uuid.UUID(before_event_id)
            except (TypeError, ValueError):
                raise CustomerIdentityError("Usage history cursor event ID is invalid") from None
            before = before.astimezone(timezone.utc)
        import psycopg
        try:
            with psycopg.connect(self._dsn) as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM public.customer_usage_events(%s,%s,%s,%s)",
                    (self._digest(session_token), limit, before, cursor_id),
                )
                rows = cur.fetchall()
            has_more = len(rows) > limit
            page = rows[:limit]
            items = [
                {
                    "event_id": str(row[0]),
                    "request_id": row[1],
                    "operation": row[2],
                    "units": int(row[3]),
                    "occurred_at": row[4].isoformat(),
                }
                for row in page
            ]
            next_cursor = None
            if has_more and page:
                last = page[-1]
                next_cursor = {
                    "before": last[4].isoformat(),
                    "before_event_id": str(last[0]),
                }
            return {"items": items, "next_cursor": next_cursor}
        except CustomerIdentityError:
            raise
        except Exception as exc:
            raise CustomerIdentityError("Unable to read customer usage history") from exc
