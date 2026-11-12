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
                          AND NOT owner.rolbypassrls
                          AND NOT EXISTS (
                              SELECT 1 FROM pg_auth_members AS membership
                              WHERE membership.member = owner.oid
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

    def register(self, email: str, organization_name: str) -> CustomerLink:
        normalized, organization = normalize_email(email), normalize_organization_name(organization_name)
        account_id, tenant_id, token_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        token, now = self._new_token(), datetime.now(timezone.utc)
        expires = now + self._verification_ttl
        tenant_label = f"{organization[:109]} [{tenant_id.hex[:8]}]"
        import psycopg
        try:
            with psycopg.connect(self._dsn) as conn, conn.cursor() as cur:
                cur.execute("INSERT INTO jas_si_tenants (tenant_id, tenant_name) VALUES (%s, %s)", (tenant_id, tenant_label))
                cur.execute("INSERT INTO jas_si_customer_accounts (account_id, tenant_id, email, email_normalized, organization_name) VALUES (%s, %s, %s, %s, %s)", (account_id, tenant_id, email.strip(), normalized, organization))
                cur.execute("INSERT INTO jas_si_customer_auth_tokens (token_id, account_id, token_digest, purpose, expires_at) VALUES (%s, %s, %s, 'verify_email', %s)", (token_id, account_id, self._digest(token), expires))
        except Exception as exc:
            try:
                import psycopg
                if isinstance(exc, psycopg.errors.UniqueViolation):
                    raise CustomerIdentityConflict("Customer registration conflicts with an existing account") from None
            except ImportError:
                pass
            if isinstance(exc, CustomerIdentityError):
                raise
            raise CustomerIdentityError("Customer registration could not be completed") from exc
        return CustomerLink(account_id, normalized, "verify_email", token, expires)

    def issue_verification_link(self, email: str) -> CustomerLink | None:
        normalized = normalize_email(email)
        token_id, token = uuid.uuid4(), self._new_token()
        expires = datetime.now(timezone.utc) + self._verification_ttl
        import psycopg
        try:
            with psycopg.connect(self._dsn) as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT account_id FROM jas_si_customer_accounts WHERE email_normalized=%s AND status='pending' FOR UPDATE",
                    (normalized,),
                )
                row = cur.fetchone()
                if row is None:
                    return None
                cur.execute(
                    "INSERT INTO jas_si_customer_auth_tokens (token_id, account_id, token_digest, purpose, expires_at) VALUES (%s, %s, %s, 'verify_email', %s)",
                    (token_id, row[0], self._digest(token), expires),
                )
            return CustomerLink(row[0], normalized, "verify_email", token, expires)
        except CustomerIdentityError:
            raise
        except Exception as exc:
            raise CustomerIdentityError("Customer verification link could not be issued") from exc

    def issue_login_link(self, email: str) -> CustomerLink | None:
        normalized = normalize_email(email)
        token_id, token = uuid.uuid4(), self._new_token()
        expires = datetime.now(timezone.utc) + self._login_ttl
        import psycopg
        try:
            with psycopg.connect(self._dsn) as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT account_id FROM jas_si_customer_accounts WHERE email_normalized=%s AND status='active' FOR UPDATE",
                    (normalized,),
                )
                row = cur.fetchone()
                if row is None:
                    return None
                cur.execute(
                    "INSERT INTO jas_si_customer_auth_tokens (token_id, account_id, token_digest, purpose, expires_at) VALUES (%s, %s, %s, 'login', %s)",
                    (token_id, row[0], self._digest(token), expires),
                )
            return CustomerLink(row[0], normalized, "login", token, expires)
        except CustomerIdentityError:
            raise
        except Exception as exc:
            raise CustomerIdentityError("Customer sign-in link could not be issued") from exc

    def verify_email(self, token: str) -> CustomerAccount:
        result = self._consume_link(token, "verify_email", create_session=False)
        return result

    def consume_login_link(self, token: str) -> CustomerSession:
        return self._consume_link(token, "login", create_session=True)

    def _consume_link(self, token: str, purpose: str, *, create_session: bool):
        if not isinstance(token, str) or not 32 <= len(token) <= 128:
            raise CustomerIdentityError("Invalid or expired customer link")
        import psycopg
        now = datetime.now(timezone.utc)
        session_token = self._new_token() if create_session else None
        session_id = uuid.uuid4() if create_session else None
        session_expiry = now + self._session_ttl if create_session else None
        try:
            with psycopg.connect(self._dsn) as conn, conn.cursor() as cur:
                cur.execute("""SELECT t.token_id, t.account_id, t.expires_at, t.consumed_at, a.tenant_id, a.email, a.organization_name, a.status, a.email_verified_at FROM jas_si_customer_auth_tokens t JOIN jas_si_customer_accounts a ON a.account_id=t.account_id WHERE t.token_digest=%s AND t.purpose=%s FOR UPDATE OF t, a""", (self._digest(token), purpose))
                row = cur.fetchone()
                if row is None or row[3] is not None or row[2] <= now or row[7] == "suspended":
                    raise CustomerIdentityError("Invalid or expired customer link")
                if purpose == "verify_email":
                    if row[7] != "pending" or row[8] is not None:
                        raise CustomerIdentityError("Customer email is already verified or unavailable")
                    cur.execute("UPDATE jas_si_customer_accounts SET status='active', email_verified_at=%s, updated_at=%s WHERE account_id=%s", (now, now, row[1]))
                elif row[7] != "active" or row[8] is None:
                    raise CustomerIdentityError("Customer account is not active")
                cur.execute("UPDATE jas_si_customer_auth_tokens SET consumed_at=%s WHERE token_id=%s", (now, row[0]))
                if create_session:
                    cur.execute("INSERT INTO jas_si_customer_sessions (session_id, account_id, token_digest, expires_at) VALUES (%s, %s, %s, %s)", (session_id, row[1], self._digest(session_token), session_expiry))
            account = CustomerAccount(row[1], row[4], row[5], row[6], "active" if purpose == "verify_email" else row[7])
            if create_session:
                return CustomerSession(account, session_token, session_expiry)
            return account
        except CustomerIdentityError:
            raise
        except Exception as exc:
            raise CustomerIdentityError("Customer link could not be processed") from exc

    def authenticate_session(self, token: str) -> CustomerAccount | None:
        if not isinstance(token, str) or not 32 <= len(token) <= 128:
            return None
        import psycopg
        with psycopg.connect(self._dsn) as conn, conn.cursor() as cur:
            cur.execute("""SELECT a.account_id, a.tenant_id, a.email, a.organization_name, a.status FROM jas_si_customer_sessions s JOIN jas_si_customer_accounts a ON a.account_id=s.account_id WHERE s.token_digest=%s AND s.revoked_at IS NULL AND s.expires_at>%s AND a.status='active'""", (self._digest(token), datetime.now(timezone.utc)))
            row = cur.fetchone()
        return CustomerAccount(*row) if row else None

    def revoke_session(self, token: str) -> bool:
        if not isinstance(token, str) or not 32 <= len(token) <= 128:
            return False
        import psycopg
        with psycopg.connect(self._dsn) as conn, conn.cursor() as cur:
            cur.execute("UPDATE jas_si_customer_sessions SET revoked_at=NOW() WHERE token_digest=%s AND revoked_at IS NULL", (self._digest(token),))
            return cur.rowcount == 1
