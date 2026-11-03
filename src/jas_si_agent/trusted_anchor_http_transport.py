from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

import httpx

from jas_si_agent.trusted_anchor_provider_profile import (
    TrustedAnchorProviderProfile,
)


class TrustedAnchorHttpTransportError(RuntimeError):
    """Raised when a bounded HTTPS request fails."""


@dataclass(frozen=True)
class TrustedAnchorHttpResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes


class TrustedAnchorHttpTransport:
    """Bounded HTTPS transport for Trusted Anchor provider requests.

    Redirects are disabled. TLS verification remains enabled by default.
    Response bodies are read incrementally and size-limited.
    """

    def __init__(
        self,
        profile: TrustedAnchorProviderProfile,
        *,
        client: httpx.Client | None = None,
    ) -> None:
        if not isinstance(profile, TrustedAnchorProviderProfile):
            raise TrustedAnchorHttpTransportError(
                "A valid provider profile is required"
            )

        self._profile = profile
        self._owns_client = client is None

        timeout = httpx.Timeout(
            connect=profile.connect_timeout_seconds,
            read=profile.read_timeout_seconds,
            write=profile.read_timeout_seconds,
            pool=profile.connect_timeout_seconds,
        )

        self._client = client or httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            verify=True,
            trust_env=False,
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str] | None = None,
        content: bytes | None = None,
    ) -> TrustedAnchorHttpResponse:
        if not isinstance(method, str) or not method:
            raise TrustedAnchorHttpTransportError(
                "HTTP method must be a non-empty string"
            )

        if not isinstance(path, str) or not path:
            raise TrustedAnchorHttpTransportError(
                "Request path must be a non-empty string"
            )

        if (
            path.startswith("/")
            or "://" in path
            or "\\" in path
            or "?" in path
            or "#" in path
            or any(part in {".", ".."} for part in path.split("/"))
        ):
            raise TrustedAnchorHttpTransportError(
                "Only safe relative request paths are allowed"
            )

        if content is not None and not isinstance(content, bytes):
            raise TrustedAnchorHttpTransportError(
                "Request content must be bytes"
            )

        if headers is not None and not isinstance(headers, Mapping):
            raise TrustedAnchorHttpTransportError(
                "Request headers must be a mapping"
            )

        url = f"{self._profile.base_url.rstrip('/')}/{path}"

        try:
            with self._client.stream(
                method.upper(),
                url,
                headers=dict(headers or {}),
                content=content,
                follow_redirects=False,
            ) as response:
                body = bytearray()

                for chunk in response.iter_bytes():
                    body.extend(chunk)

                    if len(body) > self._profile.max_response_bytes:
                        raise TrustedAnchorHttpTransportError(
                            "Provider response exceeded the configured limit"
                        )

                return TrustedAnchorHttpResponse(
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body=bytes(body),
                )

        except TrustedAnchorHttpTransportError:
            raise
        except httpx.HTTPError as exc:
            raise TrustedAnchorHttpTransportError(
                "Trusted Anchor HTTPS request failed"
            ) from exc

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "TrustedAnchorHttpTransport":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()
