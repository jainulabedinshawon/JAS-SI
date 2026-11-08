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
        if not isinstance(tenant_id, uuid.UUID):
            raise ApiKeyError("A valid tenant UUID is required")
        name = key_name.strip() if isinstance(key_name, str) else ""
        creator = created_by.strip() if isinstance(created_by, str) else ""
        scope_set = frozenset(scopes)
        if not name or len(name) > 120:
            raise ApiKeyError("Key name must contain 1 to 120 characters")
        if not creator or len(creator) > 120:
            raise ApiKeyError("created_by must contain 1 to 120 characters")
        if not scope_set or not scope_set.issubset(ALLOWED_SCOPES):
            raise ApiKeyError("One or more API key scopes are invalid")
        if expires_at is not None:
            if expires_at.tzinfo is None or expires_at <= datetime.now(timezone.utc):
                raise ApiKeyError("Expiry must be a future timezone-aware timestamp")

        key_id = uuid.uuid4()
        secret = secrets.token_bytes(KEY_SECRET_BYTES)
        token = f"{KEY_PREFIX}{key_id.hex}_{_encode_secret(secret)}"
        prefix = f"{KEY_PREFIX}{key_id.hex}"
        digest = _digest(secret, self._pepper)

        import psycopg

        with psycopg.connect(self._dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """SELECT status FROM jas_si_tenants
                       WHERE tenant_id = %s FOR UPDATE""",
                    (tenant_id,),
                )
                row = cursor.fetchone()
                if row is None or row[0] != "active":
                    raise ApiKeyError("Tenant does not exist or is not active")
                cursor.execute(
                    """INSERT INTO jas_si_api_keys
                       (key_id, tenant_id, key_name, key_prefix, secret_digest,
                        pepper_version, scopes, created_by, expires_at)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (
                        key_id, tenant_id, name, prefix, digest,
                        PEPPER_VERSION, sorted(scope_set), creator, expires_at,
                    ),
                )
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

    def revoke_key(self, key_id: uuid.UUID) -> bool:
        if not isinstance(key_id, uuid.UUID):
            raise ApiKeyError("A valid key UUID is required")
        import psycopg

        with psycopg.connect(self._dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """UPDATE jas_si_api_keys
                       SET status = 'revoked', revoked_at = NOW()
                       WHERE key_id = %s AND status = 'active'""",
                    (key_id,),
                )
                return cursor.rowcount == 1
