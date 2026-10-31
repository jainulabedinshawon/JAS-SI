from __future__ import annotations

import json
import re
from typing import Any

from jas_si_agent.security_checkpoint_anchor import (
    SecurityCheckpointAnchor,
)
from jas_si_agent.trusted_anchor_http_transport import (
    TrustedAnchorHttpTransport,
    TrustedAnchorHttpTransportError,
)
from jas_si_agent.trusted_anchor_provider import (
    TrustedAnchorProviderError,
    TrustedAnchorReceipt,
)
from jas_si_agent.trusted_anchor_provider_profile import (
    TrustedAnchorProviderProfile,
)


class TrustedAnchorApiClientError(RuntimeError):
    """Raised when provider authentication or response validation fails."""


_TOKEN_PATTERN = re.compile(r"^[\x21-\x7e]{16,4096}$")

_RECEIPT_FIELDS = {
    "provider_id",
    "anchor_digest",
    "external_reference",
    "observed_at",
    "proof",
}


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value

    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON constant: {value}")


class TrustedAnchorApiClient:
    """Authenticated API client for publishing checkpoint anchors.

    This client validates provider responses but does not independently
    establish provider trust or implement receipt verification.
    """

    def __init__(
        self,
        profile: TrustedAnchorProviderProfile,
        transport: TrustedAnchorHttpTransport,
        *,
        bearer_token: str,
    ) -> None:
        if not isinstance(profile, TrustedAnchorProviderProfile):
            raise TrustedAnchorApiClientError(
                "A valid provider profile is required"
            )

        if not isinstance(transport, TrustedAnchorHttpTransport):
            raise TrustedAnchorApiClientError(
                "A valid HTTPS transport is required"
            )

        if (
            not isinstance(bearer_token, str)
            or not _TOKEN_PATTERN.fullmatch(bearer_token)
        ):
            raise TrustedAnchorApiClientError(
                "Bearer token must contain 16-4096 visible ASCII characters"
            )

        self._profile = profile
        self._transport = transport
        self._bearer_token = bearer_token

    def publish(
        self,
        anchor: SecurityCheckpointAnchor,
        *,
        path: str = "v1/anchors",
    ) -> TrustedAnchorReceipt:
        if not isinstance(anchor, SecurityCheckpointAnchor):
            raise TrustedAnchorApiClientError(
                "A valid checkpoint anchor is required"
            )

        try:
            response = self._transport.request(
                "POST",
                path,
                headers={
                    "Authorization": f"Bearer {self._bearer_token}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                content=anchor.to_json().encode("utf-8"),
            )
        except TrustedAnchorHttpTransportError as exc:
            raise TrustedAnchorApiClientError(
                "Trusted Anchor provider request failed"
            ) from exc

        if response.status_code not in {200, 201}:
            raise TrustedAnchorApiClientError(
                f"Provider returned unexpected HTTP status: "
                f"{response.status_code}"
            )

        content_type = next(
            (
                value
                for key, value in response.headers.items()
                if key.lower() == "content-type"
            ),
            "",
        )

        if content_type.split(";", 1)[0].strip().lower() != "application/json":
            raise TrustedAnchorApiClientError(
                "Provider response must use application/json"
            )

        try:
            data = json.loads(
                response.body.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_json_constant,
            )
        except (UnicodeDecodeError, ValueError, TypeError, RecursionError) as exc:
            raise TrustedAnchorApiClientError(
                "Provider returned invalid JSON"
            ) from exc

        if not isinstance(data, dict) or set(data) != _RECEIPT_FIELDS:
            raise TrustedAnchorApiClientError(
                "Provider receipt has unexpected or missing fields"
            )

        try:
            receipt = TrustedAnchorReceipt(**data)
        except (TypeError, TrustedAnchorProviderError) as exc:
            raise TrustedAnchorApiClientError(
                "Provider receipt failed schema validation"
            ) from exc

        if receipt.provider_id != self._profile.provider_id:
            raise TrustedAnchorApiClientError(
                "Receipt provider ID does not match configured provider"
            )

        if receipt.anchor_digest != anchor.digest:
            raise TrustedAnchorApiClientError(
                "Receipt digest does not match the submitted anchor"
            )

        return receipt
