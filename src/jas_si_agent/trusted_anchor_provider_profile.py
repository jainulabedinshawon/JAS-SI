
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit


_PROVIDER_ID_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")


class TrustedAnchorProviderProfileError(ValueError):
    """Raised when provider endpoint configuration is unsafe."""


@dataclass(frozen=True)
class TrustedAnchorProviderProfile:
    provider_id: str
    base_url: str
    connect_timeout_seconds: float = 3.0
    read_timeout_seconds: float = 5.0
    max_response_bytes: int = 65536

    def __post_init__(self) -> None:
        if (
            not isinstance(self.provider_id, str)
            or not _PROVIDER_ID_PATTERN.fullmatch(self.provider_id)
        ):
            raise TrustedAnchorProviderProfileError(
                "Invalid provider ID"
            )

        if not isinstance(self.base_url, str):
            raise TrustedAnchorProviderProfileError(
                "Provider base URL must be a string"
            )

        try:
            parsed = urlsplit(self.base_url)
            hostname = parsed.hostname
            port = parsed.port
        except ValueError as exc:
            raise TrustedAnchorProviderProfileError(
                "Invalid provider base URL"
            ) from exc

        if parsed.scheme.lower() != "https":
            raise TrustedAnchorProviderProfileError(
                "Provider endpoint must use HTTPS"
            )

        if not hostname:
            raise TrustedAnchorProviderProfileError(
                "Provider endpoint must include a hostname"
            )

        if parsed.username is not None or parsed.password is not None:
            raise TrustedAnchorProviderProfileError(
                "Credentials must not appear in the provider URL"
            )

        if parsed.query or parsed.fragment:
            raise TrustedAnchorProviderProfileError(
                "Provider base URL must not contain query or fragment"
            )

        if port is not None and not 1 <= port <= 65535:
            raise TrustedAnchorProviderProfileError(
                "Invalid provider endpoint port"
            )

        if any(char.isspace() for char in self.base_url):
            raise TrustedAnchorProviderProfileError(
                "Provider URL must not contain whitespace"
            )

        if (
            not isinstance(self.connect_timeout_seconds, (int, float))
            or isinstance(self.connect_timeout_seconds, bool)
            or not 0.1 <= self.connect_timeout_seconds <= 30
        ):
            raise TrustedAnchorProviderProfileError(
                "Connect timeout must be between 0.1 and 30 seconds"
            )

        if (
            not isinstance(self.read_timeout_seconds, (int, float))
            or isinstance(self.read_timeout_seconds, bool)
            or not 0.1 <= self.read_timeout_seconds <= 60
        ):
            raise TrustedAnchorProviderProfileError(
                "Read timeout must be between 0.1 and 60 seconds"
            )

        if (
            not isinstance(self.max_response_bytes, int)
            or isinstance(self.max_response_bytes, bool)
            or not 1024 <= self.max_response_bytes <= 1048576
        ):
            raise TrustedAnchorProviderProfileError(
                "Maximum response size must be between 1024 and 1048576 bytes"
            )
