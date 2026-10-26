
"""Environment-based configuration for the JAS-SI API.

Python 3.10 compatible. Secrets must be supplied through the environment.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional


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


@dataclass(frozen=True)
class Settings:
    service_name: str = "JAS-SI API"
    environment: str = "development"
    api_enabled: bool = False
    api_key: Optional[str] = None

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
        )
