
"""HMAC-based signing and verification for JAS-SI authorization grants.

HMAC authenticates grant integrity to parties that share the secret key.
It is not a public-key digital signature and does not independently prove
that the named human approved the grant.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any

from jas_si_agent.authorization import AuthorizationGrant

ALGORITHM = "HMAC-SHA256"
SIGNING_VERSION = 1
_MIN_KEY_BYTES = 32
_DOMAIN = b"JAS-SI:AUTHORIZATION-GRANT:v1:"


class GrantSigningError(ValueError):
    """Raised when a grant or signing key is invalid."""


def _validate_key(key: bytes) -> None:
    """Require a sufficiently long caller-managed secret."""
    if not isinstance(key, bytes):
        raise GrantSigningError("Signing key must be bytes")
    if len(key) < _MIN_KEY_BYTES:
        raise GrantSigningError(
            "Signing key must contain at least 32 bytes"
        )


def _canonical_expiry(value: datetime) -> str:
    """Serialize an aware expiry timestamp in UTC."""
    if not isinstance(value, datetime):
        raise GrantSigningError("Grant expiry must be a datetime")

    try:
        offset = value.utcoffset()
    except Exception as exc:
        raise GrantSigningError(
            "Grant expiry timezone is invalid"
        ) from exc

    if offset is None:
        raise GrantSigningError(
            "Grant expiry must be timezone-aware"
        )

    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def canonical_grant_payload(grant: AuthorizationGrant) -> bytes:
    """Return deterministic bytes covering all grant security fields."""
    if not isinstance(grant, AuthorizationGrant):
        raise GrantSigningError(
            "grant must be an AuthorizationGrant"
        )

    if not isinstance(grant.grant_id, str) or not grant.grant_id.strip():
        raise GrantSigningError("Invalid grant_id")

    if not isinstance(grant.approved_by, str) or not grant.approved_by.strip():
        raise GrantSigningError("Invalid approved_by")

    if not isinstance(grant.human_approved, bool):
        raise GrantSigningError("human_approved must be a boolean")

    if (
        not isinstance(grant.allowed_actions, tuple)
        or not grant.allowed_actions
        or any(
            not isinstance(item, str) or not item.strip()
            for item in grant.allowed_actions
        )
    ):
        raise GrantSigningError("Invalid allowed_actions")

    if (
        not isinstance(grant.allowed_resources, tuple)
        or not grant.allowed_resources
        or any(
            not isinstance(item, str) or not item.strip()
            for item in grant.allowed_resources
        )
    ):
        raise GrantSigningError("Invalid allowed_resources")

    payload: dict[str, Any] = {
        "version": SIGNING_VERSION,
        "algorithm": ALGORITHM,
        "grant_id": grant.grant_id,
        "approved_by": grant.approved_by,
        "human_approved": grant.human_approved,
        "allowed_actions": list(grant.allowed_actions),
        "allowed_resources": list(grant.allowed_resources),
        "expires_at": _canonical_expiry(grant.expires_at),
    }

    try:
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise GrantSigningError(
            "Unable to serialize grant safely"
        ) from exc

    return encoded


def sign_grant(grant: AuthorizationGrant, key: bytes) -> str:
    """Sign a grant and return its lowercase hexadecimal HMAC."""
    _validate_key(key)
    payload = canonical_grant_payload(grant)
    return hmac.new(
        key,
        _DOMAIN + payload,
        hashlib.sha256,
    ).hexdigest()


def verify_grant_signature(
    grant: AuthorizationGrant,
    signature: str,
    key: bytes,
) -> bool:
    """Return False for malformed inputs or an invalid signature."""
    try:
        _validate_key(key)

        if (
            not isinstance(signature, str)
            or len(signature) != 64
            or any(char not in "0123456789abcdef" for char in signature)
        ):
            return False

        expected = sign_grant(grant, key)
        return hmac.compare_digest(expected, signature)
    except (GrantSigningError, TypeError, ValueError, OverflowError):
        return False
