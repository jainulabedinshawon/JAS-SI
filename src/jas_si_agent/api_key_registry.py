"""PostgreSQL-backed, tenant-scoped API key lifecycle.

Raw API tokens are returned once at issuance and are never persisted.
The pepper must be loaded from a secret manager, not PostgreSQL or source control.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

KEY_PREFIX = "jassi_live_"
KEY_SECRET_BYTES = 32
PEPPER_VERSION = 1
ALLOWED_SCOPES = frozenset({
    "authorization:check",
    "outcomes:submit",
    "github:evidence:verify",
    "usage:read",
})


class ApiKeyError(ValueError):
    """Raised when API-key input or lifecycle operations are invalid."""


@dataclass(frozen=True)
class IssuedApiKey:
    key_id: uuid.UUID
    token: str
    prefix: str
    expires_at: datetime | None


@dataclass(frozen=True)
class AuthenticatedApiKey:
    key_id: uuid.UUID
    tenant_id: uuid.UUID
    tenant_name: str
    scopes: frozenset[str]


def _validate_pepper(pepper: bytes) -> None:
    if not isinstance(pepper, bytes) or len(pepper) < 32:
        raise ApiKeyError("API key pepper must contain at least 32 bytes")


def _digest(secret: bytes, pepper: bytes) -> bytes:
    _validate_pepper(pepper)
    return hmac.new(pepper, secret, hashlib.sha256).digest()


def _encode_secret(secret: bytes) -> str:
    return base64.urlsafe_b64encode(secret).decode("ascii").rstrip("=")


def _decode_secret(value: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise ApiKeyError("Malformed API key")
    try:
        return base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError):
        raise ApiKeyError("Malformed API key") from None


def parse_token(token: str) -> tuple[uuid.UUID, bytes]:
    if not isinstance(token, str) or not token.startswith(KEY_PREFIX):
        raise ApiKeyError("Malformed API key")
    parts = token[len(KEY_PREFIX):].split("_", 1)
    if len(parts) != 2 or len(parts[0]) != 32:
        raise ApiKeyError("Malformed API key")
    try:
        key_id = uuid.UUID(hex=parts[0])
        secret = _decode_secret(parts[1])
    except (ValueError, ApiKeyError):
        raise ApiKeyError("Malformed API key") from None
    if len(secret) != KEY_SECRET_BYTES:
        raise ApiKeyError("Malformed API key")
    return key_id, secret


class PostgresApiKeyRegistry:
    """Tenant/key metadata operations against the JAS-SI PostgreSQL database."""

    def __init__(self, dsn: str, pepper: bytes) -> None:
        if not isinstance(dsn, str) or not dsn.strip():
            raise ApiKeyError("Database DSN is required")
        _validate_pepper(pepper)
        self._dsn = dsn.strip()
        self._pepper = pepper

    def verify_schema(self) -> bool:
        """Fail closed unless both tenant registry tables exist."""
        import psycopg

        with psycopg.connect(self._dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """SELECT
                         to_regclass('public.jas_si_tenants'),
                         to_regclass('public.jas_si_api_keys')"""
                )
                row = cursor.fetchone()
                return bool(row and row[0] and row[1])

    def verify_provisioning_schema(self) -> bool:
        """Fail closed unless all tables required for atomic issuance exist."""
        import psycopg

        with psycopg.connect(self._dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        to_regclass('public.jas_si_tenants'),
                        to_regclass('public.jas_si_api_keys'),
                        to_regclass('public.jas_si_api_key_provisioning_runs'),
                        to_regclass('public.jas_si_audit_events'),
                        to_regclass('public.jas_si_audit_chain_state')
                    """
                )
                row = cursor.fetchone()
                return bool(row and all(row))

    def verify_customer_runtime_role(self) -> bool:
        """Require the dedicated non-superuser, non-BYPASSRLS customer role."""
        import psycopg

        with psycopg.connect(self._dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT r.rolname, r.rolsuper, r.rolbypassrls,
                           r.rolcanlogin,
                           EXISTS (
                               SELECT 1
                               FROM pg_auth_members AS membership
                               WHERE membership.member = r.oid
                           ) AS has_inherited_role
                    FROM pg_roles AS r
                    WHERE r.rolname = current_user
                    """
                )
                row = cursor.fetchone()
        return bool(
            row
            and row[0] == "jas_si_customer_key_runtime"
            and row[1] is False
            and row[2] is False
            and row[3] is False
            and row[4] is False
        )

    def verify_customer_audit_isolation(self) -> bool:
        """Fail closed if the customer role can directly access global audit or identity tables.

        Customer key lifecycle operations must move behind database-owned routines
        before this guard can pass. Column-level grants are checked as well as
        table-level grants.
        """
        import psycopg

        protected = {
            "public.jas_si_audit_events": ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE"),
            "public.jas_si_audit_chain_state": ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE"),
            "public.jas_si_customer_sessions": ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE"),
            "public.jas_si_customer_auth_tokens": ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE"),
            "public.jas_si_customer_accounts": ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE"),
        }
        with psycopg.connect(self._dsn) as connection:
            with connection.cursor() as cursor:
                for table, privileges in protected.items():
                    cursor.execute("SELECT to_regclass(%s)", (table,))
                    exists = cursor.fetchone()
                    if not exists or exists[0] is None:
                        return False
                    for privilege in privileges:
                        cursor.execute(
                            """SELECT
                                has_table_privilege(current_user, %s, %s)
                                OR has_any_column_privilege(current_user, %s, %s)""",
                            (table, privilege, table, privilege),
                        )
                        row = cursor.fetchone()
                        if row is None or row[0]:
                            return False
        return True

    def create_tenant(self, tenant_name: str) -> uuid.UUID:
        name = tenant_name.strip() if isinstance(tenant_name, str) else ""
        if not name or len(name) > 120:
            raise ApiKeyError("Tenant name must contain 1 to 120 characters")
        import psycopg

        tenant_id = uuid.uuid4()
        with psycopg.connect(self._dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO jas_si_tenants (tenant_id, tenant_name)
                       VALUES (%s, %s)""",
                    (tenant_id, name),
                )
        return tenant_id

    def issue_key(
        self,
        tenant_id: uuid.UUID,
        key_name: str,
        scopes: Iterable[str],
        created_by: str,
        expires_at: datetime | None = None,
    ) -> IssuedApiKey:
        """Compatibility wrapper; all key issuance remains atomic and audited."""
        return self.issue_key_with_audit(
            tenant_id=tenant_id,
            key_name=key_name,
            scopes=scopes,
            created_by=created_by,
            provisioning_run_id=f"compat-api:{uuid.uuid4()}",
            expires_at=expires_at,
        )

    def issue_key_with_audit(
        self,
        tenant_id: uuid.UUID,
        key_name: str,
        scopes: Iterable[str],
        created_by: str,
        provisioning_run_id: str,
        expires_at: datetime | None = None,
        tenant_scope: uuid.UUID | None = None,
    ) -> IssuedApiKey:
        """Issue a key, append its audit event, and record idempotency atomically.

        When tenant_scope is supplied, PostgreSQL RLS constrains this transaction
        to that tenant. The caller must use the dedicated customer-key role.
        """
        import re
        import psycopg
        from jas_si_agent.postgres_security_event_store import (
            PostgresSecurityEventStore,
        )

        if not isinstance(tenant_id, uuid.UUID):
            raise ApiKeyError("A valid tenant UUID is required")
        name = key_name.strip() if isinstance(key_name, str) else ""
        creator = created_by.strip() if isinstance(created_by, str) else ""
        run_id = (
            provisioning_run_id.strip()
            if isinstance(provisioning_run_id, str)
            else ""
        )
        scope_set = frozenset(scopes)
        if not name or len(name) > 120:
            raise ApiKeyError("Key name must contain 1 to 120 characters")
        if not creator or len(creator) > 120:
            raise ApiKeyError("created_by must contain 1 to 120 characters")
        if not scope_set or not scope_set.issubset(ALLOWED_SCOPES):
            raise ApiKeyError("One or more API key scopes are invalid")
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", run_id):
            raise ApiKeyError("A valid provisioning run identifier is required")
        if expires_at is not None:
            if (
                expires_at.tzinfo is None
                or expires_at <= datetime.now(timezone.utc)
            ):
                raise ApiKeyError(
                    "Expiry must be a future timezone-aware timestamp"
                )

        if not self.verify_provisioning_schema():
            raise ApiKeyError(
                "Atomic provisioning schema is missing; apply migrations first"
            )
        key_id = uuid.uuid4()
        secret = secrets.token_bytes(KEY_SECRET_BYTES)
        token = f"{KEY_PREFIX}{key_id.hex}_{_encode_secret(secret)}"
        prefix = f"{KEY_PREFIX}{key_id.hex}"
        digest = _digest(secret, self._pepper)

        try:
            with psycopg.connect(self._dsn) as connection:
                with connection.cursor() as cursor:
                    if tenant_scope is not None:
                        if tenant_scope != tenant_id:
                            raise ApiKeyError("Customer tenant scope mismatch")
                        cursor.execute(
                            "SELECT set_config('jas_si.tenant_id', %s, true)",
                            (str(tenant_scope),),
                        )
                    # Serialize all audit writers, then verify the exact chain
                    # snapshot that this transaction will extend.
                    cursor.execute(
                        """
                        INSERT INTO jas_si_audit_chain_state (singleton, last_hash)
                        VALUES (TRUE, %s)
                        ON CONFLICT (singleton) DO NOTHING
                        """,
                        ("0" * 64,),
                    )
                    cursor.execute(
                        """
                        SELECT last_hash
                        FROM jas_si_audit_chain_state
                        WHERE singleton = TRUE
                        FOR UPDATE
                        """
                    )
                    if cursor.fetchone() is None:
                        raise ApiKeyError(
                            "Audit checkpoint unavailable; provisioning stopped"
                        )
                    integrity = (
                        PostgresSecurityEventStore.verify_integrity_in_transaction(
                            connection
                        )
                    )
                    if integrity.get("valid") is not True:
                        raise ApiKeyError(
                            "Audit chain integrity check failed; provisioning stopped"
                        )

                    cursor.execute(
                        """
                        SELECT status
                        FROM jas_si_tenants
                        WHERE tenant_id = %s
                        FOR UPDATE
                        """,
                        (tenant_id,),
                    )
                    tenant_row = cursor.fetchone()
                    if tenant_row is None or tenant_row[0] != "active":
                        raise ApiKeyError(
                            "Tenant does not exist or is not active"
                        )

                    cursor.execute(
                        """
                        INSERT INTO jas_si_api_keys
                            (key_id, tenant_id, key_name, key_prefix,
                             secret_digest, pepper_version, scopes,
                             created_by, expires_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            key_id, tenant_id, name, prefix, digest,
                            PEPPER_VERSION, sorted(scope_set), creator,
                            expires_at,
                        ),
                    )

                    cursor.execute(
                        """
                        INSERT INTO jas_si_api_key_provisioning_runs
                            (run_id, key_id, tenant_id)
                        VALUES (%s, %s, %s)
                        """,
                        (run_id, key_id, tenant_id),
                    )

                PostgresSecurityEventStore.append_in_transaction(
                    connection,
                    {
                        "event_type": "api_key_issued",
                        "tenant_id": str(tenant_id),
                        "key_id": str(key_id),
                        "key_name": name,
                        "scopes": sorted(scope_set),
                        "expires_at": (
                            expires_at.isoformat() if expires_at else None
                        ),
                        "operator_id": creator,
                        "provisioning_run_id": run_id,
                    },
                )
        except ApiKeyError:
            raise
        except Exception as exc:
            # Do not leak SQL details, connection strings, or secret material.
            raise ApiKeyError(
                "Atomic API key provisioning failed; no key was issued"
            ) from exc

        return IssuedApiKey(key_id, token, prefix, expires_at)

    def authenticate(self, token: str) -> AuthenticatedApiKey | None:
        try:
            key_id, secret = parse_token(token)
        except ApiKeyError:
            return None

        import psycopg

        with psycopg.connect(self._dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """SELECT k.tenant_id, k.secret_digest, k.pepper_version,
                              k.scopes, k.status, k.expires_at,
                              t.tenant_name, t.status
                       FROM jas_si_api_keys AS k
                       JOIN jas_si_tenants AS t ON t.tenant_id = k.tenant_id
                       WHERE k.key_id = %s""",
                    (key_id,),
                )
                row = cursor.fetchone()
                if row is None:
                    return None
                tenant_id, stored, pepper_version, scopes, key_status, expiry, tenant_name, tenant_status = row
                if pepper_version != PEPPER_VERSION:
                    return None
                if key_status != "active" or tenant_status != "active":
                    return None
                now = datetime.now(timezone.utc)
                if expiry is not None and expiry <= now:
                    return None
                if not hmac.compare_digest(bytes(stored), _digest(secret, self._pepper)):
                    return None
                cursor.execute(
                    """UPDATE jas_si_api_keys SET last_used_at = NOW()
                       WHERE key_id = %s""",
                    (key_id,),
                )
                return AuthenticatedApiKey(
                    key_id=key_id,
                    tenant_id=tenant_id,
                    tenant_name=tenant_name,
                    scopes=frozenset(scopes),
                )


    def list_tenant_keys(self, tenant_id: uuid.UUID) -> list[dict]:
        """List non-secret key metadata for one tenant under PostgreSQL RLS."""
        import psycopg

        if not isinstance(tenant_id, uuid.UUID):
            raise ApiKeyError("A valid tenant UUID is required")
        try:
            with psycopg.connect(self._dsn) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT set_config('jas_si.tenant_id', %s, true)",
                        (str(tenant_id),),
                    )
                    cursor.execute(
                        """
                        SELECT key_id, key_name, key_prefix, scopes, status,
                               created_at, expires_at, last_used_at, revoked_at
                        FROM jas_si_api_keys
                        WHERE tenant_id = %s
                        ORDER BY created_at DESC, key_id
                        """,
                        (tenant_id,),
                    )
                    rows = cursor.fetchall()
            return [
                {
                    "key_id": str(row[0]),
                    "key_name": row[1],
                    "key_prefix": row[2],
                    "scopes": list(row[3]),
                    "status": row[4],
                    "created_at": row[5].isoformat(),
                    "expires_at": row[6].isoformat() if row[6] else None,
                    "last_used_at": row[7].isoformat() if row[7] else None,
                    "revoked_at": row[8].isoformat() if row[8] else None,
                }
                for row in rows
            ]
        except ApiKeyError:
            raise
        except Exception as exc:
            raise ApiKeyError("Unable to list customer API keys") from exc

    def revoke_key(self, key_id: uuid.UUID) -> bool:
        """Compatibility wrapper; revocation and audit are one transaction."""
        return self.revoke_key_with_audit(
            key_id=key_id,
            revoked_by="compat-api",
            revocation_run_id=f"compat-revoke:{uuid.uuid4()}",
        )

    def revoke_key_with_audit(
        self,
        key_id: uuid.UUID,
        revoked_by: str,
        revocation_run_id: str,
        tenant_scope: uuid.UUID | None = None,
    ) -> bool:
        """Revoke a key and append its audit event atomically.

        When tenant_scope is supplied, PostgreSQL RLS and the explicit predicate
        restrict the operation to the authenticated customer's tenant.
        """
        import re
        import psycopg
        from jas_si_agent.postgres_security_event_store import (
            PostgresSecurityEventStore,
        )

        if not isinstance(key_id, uuid.UUID):
            raise ApiKeyError("A valid key UUID is required")
        operator = revoked_by.strip() if isinstance(revoked_by, str) else ""
        run_id = (
            revocation_run_id.strip()
            if isinstance(revocation_run_id, str)
            else ""
        )
        if not operator or len(operator) > 120:
            raise ApiKeyError("revoked_by must contain 1 to 120 characters")
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", run_id):
            raise ApiKeyError("A valid revocation run identifier is required")
        if not self.verify_provisioning_schema():
            raise ApiKeyError(
                "Atomic provisioning schema is missing; revocation stopped"
            )

        try:
            with psycopg.connect(self._dsn) as connection:
                with connection.cursor() as cursor:
                    if tenant_scope is not None:
                        cursor.execute(
                            "SELECT set_config('jas_si.tenant_id', %s, true)",
                            (str(tenant_scope),),
                        )
                    cursor.execute(
                        """
                        INSERT INTO jas_si_audit_chain_state (singleton, last_hash)
                        VALUES (TRUE, %s)
                        ON CONFLICT (singleton) DO NOTHING
                        """,
                        ("0" * 64,),
                    )
                    cursor.execute(
                        """
                        SELECT last_hash
                        FROM jas_si_audit_chain_state
                        WHERE singleton = TRUE
                        FOR UPDATE
                        """
                    )
                    if cursor.fetchone() is None:
                        raise ApiKeyError(
                            "Audit checkpoint unavailable; revocation stopped"
                        )
                    integrity = (
                        PostgresSecurityEventStore.verify_integrity_in_transaction(
                            connection
                        )
                    )
                    if integrity.get("valid") is not True:
                        raise ApiKeyError(
                            "Audit chain integrity check failed; revocation stopped"
                        )
                    cursor.execute(
                        """
                        UPDATE jas_si_api_keys
                        SET status = 'revoked', revoked_at = NOW()
                        WHERE key_id = %s AND status = 'active'
                          AND (%s::uuid IS NULL OR tenant_id = %s)
                        RETURNING tenant_id
                        """,
                        (key_id, tenant_scope, tenant_scope),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        return False
                    tenant_id = row[0]

                PostgresSecurityEventStore.append_in_transaction(
                    connection,
                    {
                        "event_type": "api_key_revoked",
                        "tenant_id": str(tenant_id),
                        "key_id": str(key_id),
                        "operator_id": operator,
                        "revocation_run_id": run_id,
                    },
                )
            return True
        except ApiKeyError:
            raise
        except Exception as exc:
            raise ApiKeyError(
                "Atomic API key revocation failed; state was not changed"
            ) from exc
