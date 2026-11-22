"""Environment-based configuration for the JAS-SI API.

Python 3.10 compatible. Secrets must be supplied through the environment.
"""

from __future__ import annotations

import base64
import json
import os
import re
from urllib.parse import urlsplit
from dataclasses import dataclass, field
from typing import Optional


_MIN_HMAC_SECRET_BYTES = 32
_MIN_API_KEY_PEPPER_BYTES = 32
_MIN_CUSTOMER_TOKEN_PEPPER_BYTES = 32
_GITHUB_OAUTH_KEY_VERSION_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
_MIN_API_RATE_LIMIT_PEPPER_BYTES = 32


def _read_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default

    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False

    raise ValueError(f"{name} must be a boolean value")


def _read_positive_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default

    try:
        value = int(raw.strip())
    except (TypeError, ValueError):
        raise ValueError(
            f"{name} must be a positive integer"
        ) from None

    if value < 1:
        raise ValueError(f"{name} must be a positive integer")

    return value


def _read_optional_api_key_pepper() -> Optional[bytes]:
    raw = os.getenv("JAS_SI_API_KEY_PEPPER")
    if raw is None or raw == "":
        return None
    pepper = raw.encode("utf-8")
    if len(pepper) < _MIN_API_KEY_PEPPER_BYTES:
        raise ValueError("JAS_SI_API_KEY_PEPPER must contain at least 32 UTF-8 bytes")
    return pepper


def _read_optional_customer_token_pepper() -> Optional[bytes]:
    raw = os.getenv("JAS_SI_CUSTOMER_TOKEN_PEPPER")
    if raw is None or raw == "":
        return None
    pepper = raw.encode("utf-8")
    if len(pepper) < _MIN_CUSTOMER_TOKEN_PEPPER_BYTES:
        raise ValueError("JAS_SI_CUSTOMER_TOKEN_PEPPER must contain at least 32 UTF-8 bytes")
    return pepper


def _read_optional_api_rate_limit_pepper() -> Optional[bytes]:
    raw = os.getenv("JAS_SI_API_RATE_LIMIT_PEPPER")
    if raw is None or raw == "":
        return None
    pepper = raw.encode("utf-8")
    if len(pepper) < _MIN_API_RATE_LIMIT_PEPPER_BYTES:
        raise ValueError("JAS_SI_API_RATE_LIMIT_PEPPER must contain at least 32 UTF-8 bytes")
    return pepper


def _read_optional_hmac_secret() -> Optional[bytes]:
    raw = os.getenv("JAS_SI_TRUSTED_ANCHOR_HMAC_SECRET")

    if raw is None or raw == "":
        return None

    secret = raw.encode("utf-8")

    if len(secret) < _MIN_HMAC_SECRET_BYTES:
        raise ValueError(
            "JAS_SI_TRUSTED_ANCHOR_HMAC_SECRET "
            "must contain at least 32 UTF-8 bytes"
        )

    return secret


def _read_optional_provider_id() -> Optional[str]:
    raw = os.getenv("JAS_SI_TRUSTED_ANCHOR_PROVIDER_ID")

    if raw is None or not raw.strip():
        return None

    value = raw.strip()

    if value != raw:
        raise ValueError(
            "JAS_SI_TRUSTED_ANCHOR_PROVIDER_ID "
            "must not contain surrounding whitespace"
        )

    return value


def _read_github_oauth_config() -> tuple[Optional[str], Optional[str], Optional[str], Optional[dict[str, bytes]], Optional[str], Optional[int]]:
    oauth_names = (
        "JAS_SI_GITHUB_OAUTH_CLIENT_ID",
        "JAS_SI_GITHUB_OAUTH_CLIENT_SECRET",
        "JAS_SI_GITHUB_OAUTH_REDIRECT_URI",
        "JAS_SI_GITHUB_OAUTH_ENCRYPTION_KEYRING",
        "JAS_SI_GITHUB_OAUTH_ACTIVE_KEY_VERSION",
    )
    values = {name: os.getenv(name) for name in oauth_names}
    raw_app_id = os.getenv("JAS_SI_GITHUB_APP_ID")
    app_id = None
    if raw_app_id:
        try:
            app_id = int(raw_app_id)
        except ValueError:
            raise ValueError("JAS_SI_GITHUB_APP_ID must be a positive integer") from None
        if app_id <= 0:
            raise ValueError("JAS_SI_GITHUB_APP_ID must be a positive integer")

    if not any(value for value in values.values()):
        return None, None, None, None, None, app_id
    if not all(values.values()) or app_id is None:
        raise ValueError("GitHub OAuth configuration and App ID must be supplied as a complete set")

    client_id = values[oauth_names[0]]
    client_secret = values[oauth_names[1]]
    redirect_uri = values[oauth_names[2]]
    active_version = values[oauth_names[4]]
    if not client_id or not re.fullmatch(r"^(?:Iv1\.)?[A-Za-z0-9_-]{8,128}$", client_id):
        raise ValueError("JAS_SI_GITHUB_OAUTH_CLIENT_ID is invalid")
    if not client_secret or not 20 <= len(client_secret) <= 512:
        raise ValueError("JAS_SI_GITHUB_OAUTH_CLIENT_SECRET is invalid")
    parsed = urlsplit(redirect_uri or "")
    if (
        parsed.scheme != "https" or not parsed.hostname
        or parsed.username is not None or parsed.password is not None
        or parsed.fragment or parsed.query
        or parsed.path != "/v1/github/oauth/callback"
        or parsed.port not in (None, 443)
    ):
        raise ValueError("JAS_SI_GITHUB_OAUTH_REDIRECT_URI must be the fixed HTTPS JAS-SI callback path")
    if not active_version or not _GITHUB_OAUTH_KEY_VERSION_RE.fullmatch(active_version):
        raise ValueError("JAS_SI_GITHUB_OAUTH_ACTIVE_KEY_VERSION is invalid")
    try:
        encoded_ring = json.loads(values[oauth_names[3]] or "")
        if not isinstance(encoded_ring, dict) or not encoded_ring:
            raise ValueError
        keyring = {
            version: base64.b64decode(encoded, validate=True)
            for version, encoded in encoded_ring.items()
            if isinstance(version, str) and _GITHUB_OAUTH_KEY_VERSION_RE.fullmatch(version)
            and isinstance(encoded, str)
        }
        if len(keyring) != len(encoded_ring) or any(len(key) != 32 for key in keyring.values()):
            raise ValueError
        if active_version not in keyring:
            raise ValueError
    except Exception:
        raise ValueError("JAS_SI_GITHUB_OAUTH_ENCRYPTION_KEYRING must be a valid base64 JSON keyring") from None
    return client_id, client_secret, redirect_uri, keyring, active_version, app_id


@dataclass(frozen=True)
class Settings:
    service_name: str = "JAS-SI API"
    environment: str = "development"
    api_enabled: bool = False
    api_key: Optional[str] = None
    api_key_pepper: Optional[bytes] = field(default=None, repr=False)
    rate_limit_requests: int = 60
    rate_limit_window_seconds: int = 60
    security_event_log_path: str = (
        "/var/lib/jas-si/audit/security-events.jsonl"
    )

    # Never include secret material in the Settings representation.
    trusted_anchor_hmac_secret: Optional[bytes] = field(
        default=None,
        repr=False,
    )
    trusted_anchor_provider_id: Optional[str] = None
    database_url: Optional[str] = field(
        default=None,
        repr=False,
    )
    customer_database_url: Optional[str] = field(default=None, repr=False)
    customer_api_key_database_url: Optional[str] = field(default=None, repr=False)
    customer_token_pepper: Optional[bytes] = field(default=None, repr=False)
    api_rate_limit_pepper: Optional[bytes] = field(default=None, repr=False)
    customer_smtp_host: Optional[str] = None
    customer_smtp_port: int = 587
    customer_smtp_username: Optional[str] = field(default=None, repr=False)
    customer_smtp_password: Optional[str] = field(default=None, repr=False)
    customer_smtp_sender: Optional[str] = None
    customer_public_base_url: str = "https://jas-si.vercel.app"
    github_webhook_secret: Optional[bytes] = field(default=None, repr=False)
    github_webhook_database_url: Optional[str] = field(default=None, repr=False)
    github_oauth_client_id: Optional[str] = None
    github_oauth_client_secret: Optional[str] = field(default=None, repr=False)
    github_oauth_redirect_uri: Optional[str] = None
    github_oauth_encryption_keyring: Optional[dict[str, bytes]] = field(default=None, repr=False)
    github_oauth_active_key_version: Optional[str] = None
    github_app_id: Optional[int] = None

    @classmethod
    def from_env(cls) -> "Settings":
        # Respect an explicit application override; otherwise use the
        # platform-provided Vercel environment. Without this fallback, a
        # production deployment could accidentally retain development cookie
        # and trusted-proxy behavior.
        raw_environment = os.getenv("JAS_SI_ENVIRONMENT")
        if raw_environment is None:
            raw_environment = os.getenv("VERCEL_ENV", "development")
        environment = raw_environment.strip().lower()

        if environment not in {
            "development",
            "test",
            "preview",
            "production",
        }:
            raise ValueError("Invalid JAS_SI_ENVIRONMENT")

        raw_api_key = os.getenv("JAS_SI_API_KEY")
        api_key = raw_api_key if raw_api_key else None

        api_key_pepper = _read_optional_api_key_pepper()
        customer_token_pepper = _read_optional_customer_token_pepper()
        api_rate_limit_pepper = _read_optional_api_rate_limit_pepper()
        hmac_secret = _read_optional_hmac_secret()
        provider_id = _read_optional_provider_id()
        github_oauth = _read_github_oauth_config()
        raw_webhook_secret = os.getenv("JAS_SI_GITHUB_WEBHOOK_SECRET")
        github_webhook_secret = raw_webhook_secret.encode("utf-8") if raw_webhook_secret else None
        if github_webhook_secret is not None and len(github_webhook_secret) < 32:
            raise ValueError("JAS_SI_GITHUB_WEBHOOK_SECRET must contain at least 32 UTF-8 bytes")
        if (hmac_secret is None) != (provider_id is None):
            raise ValueError(
                "Trusted Anchor HMAC secret and provider ID "
                "must be configured together"
            )

        return cls(
            service_name=os.getenv(
                "JAS_SI_SERVICE_NAME",
                "JAS-SI API",
            ).strip(),
            environment=environment,
            api_enabled=_read_bool(
                "JAS_SI_API_ENABLED",
                False,
            ),
            api_key=api_key,
            api_key_pepper=api_key_pepper,
            rate_limit_requests=_read_positive_int(
                "JAS_SI_RATE_LIMIT_REQUESTS",
                60,
            ),
            rate_limit_window_seconds=_read_positive_int(
                "JAS_SI_RATE_LIMIT_WINDOW_SECONDS",
                60,
            ),
            security_event_log_path=os.getenv(
                "JAS_SI_SECURITY_EVENT_LOG_PATH",
                "/var/lib/jas-si/audit/security-events.jsonl",
            ).strip(),
            trusted_anchor_hmac_secret=hmac_secret,
            trusted_anchor_provider_id=provider_id,
            database_url=(
                os.getenv("JAS_SI_DATABASE_URL") or None
            ),
            customer_database_url=(
                os.getenv("JAS_SI_CUSTOMER_DATABASE_URL") or None
            ),
            customer_api_key_database_url=(
                os.getenv("JAS_SI_CUSTOMER_API_KEY_DATABASE_URL") or None
            ),
            customer_token_pepper=customer_token_pepper,
            api_rate_limit_pepper=api_rate_limit_pepper,
            customer_smtp_host=os.getenv("JAS_SI_CUSTOMER_SMTP_HOST") or None,
            customer_smtp_port=_read_positive_int("JAS_SI_CUSTOMER_SMTP_PORT", 587),
            customer_smtp_username=os.getenv("JAS_SI_CUSTOMER_SMTP_USERNAME") or None,
            customer_smtp_password=os.getenv("JAS_SI_CUSTOMER_SMTP_PASSWORD") or None,
            customer_smtp_sender=os.getenv("JAS_SI_CUSTOMER_SMTP_SENDER") or None,
            customer_public_base_url=os.getenv(
                "JAS_SI_CUSTOMER_PUBLIC_URL", "https://jas-si.vercel.app"
            ).strip(),
            github_webhook_secret=github_webhook_secret,
            github_webhook_database_url=(os.getenv("JAS_SI_GITHUB_WEBHOOK_DATABASE_URL") or None),
            github_oauth_client_id=github_oauth[0],
            github_oauth_client_secret=github_oauth[1],
            github_oauth_redirect_uri=github_oauth[2],
            github_oauth_encryption_keyring=github_oauth[3],
            github_oauth_active_key_version=github_oauth[4],
            github_app_id=github_oauth[5],
        )
