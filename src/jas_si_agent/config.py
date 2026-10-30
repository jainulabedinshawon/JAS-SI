
"""Environment-based configuration for the JAS-SI API.

Python 3.10 compatible. Secrets must be supplied through the environment.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional


_MIN_HMAC_SECRET_BYTES = 32


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


@dataclass(frozen=True)
class Settings:
    service_name: str = "JAS-SI API"
    environment: str = "development"
    api_enabled: bool = False
    api_key: Optional[str] = None
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

    @classmethod
    def from_env(cls) -> "Settings":
        environment = os.getenv(
            "JAS_SI_ENVIRONMENT",
            "development",
        ).strip().lower()

        if environment not in {
            "development",
            "test",
            "production",
        }:
            raise ValueError("Invalid JAS_SI_ENVIRONMENT")

        raw_api_key = os.getenv("JAS_SI_API_KEY")
        api_key = raw_api_key if raw_api_key else None

        hmac_secret = _read_optional_hmac_secret()
        provider_id = _read_optional_provider_id()

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
        )
