"""Environment-based configuration for the JAS-SI API.

Python 3.10 compatible. Secrets must be supplied through the environment.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Optional

from jas_si_agent.github_capability_identity import (
    CertificateWorkloadIdentityRegistry,
    WorkloadIdentity,
)


_MIN_HMAC_SECRET_BYTES = 32
_MIN_API_KEY_PEPPER_BYTES = 32
_MIN_CUSTOMER_TOKEN_PEPPER_BYTES = 32
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


def _read_github_capability_workload_identities() -> Optional[CertificateWorkloadIdentityRegistry]:
    raw = os.getenv("JAS_SI_GITHUB_CAPABILITY_WORKLOAD_IDENTITIES")
    if raw is None or not raw.strip():
        return None
    try:
        decoded = json.loads(raw)
    except (TypeError, ValueError):
        raise ValueError(
            "JAS_SI_GITHUB_CAPABILITY_WORKLOAD_IDENTITIES must be valid JSON"
        ) from None
    if not isinstance(decoded, dict) or not decoded:
        raise ValueError(
            "JAS_SI_GITHUB_CAPABILITY_WORKLOAD_IDENTITIES must be a non-empty object"
        )
    identities = {}
    for fingerprint, item in decoded.items():
        if not isinstance(item, dict) or set(item) != {"principal_id", "role"}:
            raise ValueError(
                "JAS_SI_GITHUB_CAPABILITY_WORKLOAD_IDENTITIES entries must contain principal_id and role"
            )
        try:
            identities[fingerprint] = WorkloadIdentity(
                principal_id=item["principal_id"],
                role=item["role"],
            )
        except (TypeError, ValueError):
            raise ValueError(
                "JAS_SI_GITHUB_CAPABILITY_WORKLOAD_IDENTITIES contains an invalid identity"
            ) from None
    try:
        return CertificateWorkloadIdentityRegistry(identities)
    except (TypeError, ValueError):
        raise ValueError(
            "JAS_SI_GITHUB_CAPABILITY_WORKLOAD_IDENTITIES contains an invalid certificate map"
        ) from None


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
    github_capability_workload_identities: Optional[CertificateWorkloadIdentityRegistry] = field(default=None, repr=False)
    github_capability_broker_database_url: Optional[str] = field(default=None, repr=False)
    github_capability_broker_enabled: bool = False
    github_capability_app_id: Optional[int] = None
    github_capability_app_private_key_path: Optional[str] = field(default=None, repr=False)
    github_capability_app_private_key_pem: Optional[bytes] = field(default=None, repr=False)

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
        github_capability_workload_identities = _read_github_capability_workload_identities()

        github_capability_broker_database_url = os.getenv("JAS_SI_GITHUB_CAPABILITY_BROKER_DATABASE_URL") or None
        github_capability_broker_enabled = _read_bool("JAS_SI_GITHUB_CAPABILITY_BROKER_ENABLED", False)
        raw_capability_app_id = os.getenv("JAS_SI_GITHUB_CAPABILITY_APP_ID") or os.getenv("JAS_SI_GITHUB_APP_ID")
        try:
            github_capability_app_id = int(raw_capability_app_id) if raw_capability_app_id else None
        except (TypeError, ValueError):
            raise ValueError("GitHub Capability App ID must be a positive integer") from None
        if github_capability_app_id is not None and github_capability_app_id <= 0:
            raise ValueError("GitHub Capability App ID must be a positive integer")
        github_capability_app_private_key_path = os.getenv("JAS_SI_GITHUB_CAPABILITY_APP_PRIVATE_KEY_PATH") or None
        raw_capability_key_b64 = os.getenv("JAS_SI_GITHUB_CAPABILITY_APP_PRIVATE_KEY_B64") or os.getenv("JAS_SI_GITHUB_APP_PRIVATE_KEY_B64")
        github_capability_app_private_key_pem = None
        if raw_capability_key_b64:
            from jas_si_agent.github_app_tokens import decode_github_app_private_key_b64
            github_capability_app_private_key_pem = decode_github_app_private_key_b64(raw_capability_key_b64)
        if github_capability_app_private_key_path and github_capability_app_private_key_pem:
            raise ValueError("Configure exactly one GitHub Capability App private-key source")
        if github_capability_broker_enabled:
            if environment != "preview":
                raise ValueError("GitHub Capability Broker may be enabled only in preview")
            if not github_capability_broker_database_url:
                raise ValueError("GitHub Capability Broker database URL is required")
            try:
                from psycopg.conninfo import conninfo_to_dict
                broker_dsn_options = conninfo_to_dict(github_capability_broker_database_url)
            except Exception:
                raise ValueError("GitHub Capability Broker database URL is invalid") from None
            if broker_dsn_options.get("sslmode") != "verify-full":
                raise ValueError("GitHub Capability Broker database URL must require sslmode=verify-full")
            if github_capability_workload_identities is None:
                raise ValueError("Pinned GitHub Capability workload identities are required")
            if not github_capability_app_id or not (github_capability_app_private_key_path or github_capability_app_private_key_pem):
                raise ValueError("Dedicated GitHub Capability App credentials are required")

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
            github_capability_workload_identities=github_capability_workload_identities,
            github_capability_broker_database_url=github_capability_broker_database_url,
            github_capability_broker_enabled=github_capability_broker_enabled,
            github_capability_app_id=github_capability_app_id,
            github_capability_app_private_key_path=github_capability_app_private_key_path,
            github_capability_app_private_key_pem=github_capability_app_private_key_pem,
        )
