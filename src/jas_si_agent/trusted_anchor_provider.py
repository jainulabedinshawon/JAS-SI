
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from jas_si_agent.security_checkpoint_anchor import (
    SecurityCheckpointAnchor,
)

_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class TrustedAnchorProviderError(RuntimeError):
    """Raised when external anchor publication or verification fails."""


@dataclass(frozen=True)
class TrustedAnchorReceipt:
    """Receipt returned by an external anchor provider.

    The receipt is provider-supplied metadata, not proof of trust by itself.
    Its authenticity must be checked by the configured provider.
    """

    provider_id: str
    anchor_digest: str
    external_reference: str
    observed_at: str
    proof: str

    def __post_init__(self) -> None:
        for field_name in (
            "provider_id",
            "external_reference",
            "observed_at",
            "proof",
        ):
            value = getattr(self, field_name)

            if (
                not isinstance(value, str)
                or not value.strip()
                or value != value.strip()
            ):
                raise TrustedAnchorProviderError(
                    f"{field_name} must be a non-empty trimmed string"
                )

        if (
            not isinstance(self.anchor_digest, str)
            or not _DIGEST_PATTERN.fullmatch(self.anchor_digest)
        ):
            raise TrustedAnchorProviderError(
                "anchor_digest must be a lowercase SHA-256 digest"
            )


@runtime_checkable
class TrustedAnchorProvider(Protocol):
    """Contract for a separately operated trusted-anchor service."""

    def publish(
        self,
        anchor: SecurityCheckpointAnchor,
    ) -> TrustedAnchorReceipt:
        """Publish an anchor and return the provider's receipt."""
        ...

    def verify(
        self,
        anchor: SecurityCheckpointAnchor,
        receipt: TrustedAnchorReceipt,
    ) -> bool:
        """Independently verify the receipt against the anchor."""
        ...


def publish_and_verify_anchor(
    provider: TrustedAnchorProvider,
    anchor: SecurityCheckpointAnchor,
) -> TrustedAnchorReceipt:
    """Publish an anchor and fail closed unless its receipt verifies."""

    if not isinstance(anchor, SecurityCheckpointAnchor):
        raise TrustedAnchorProviderError(
            "Expected a SecurityCheckpointAnchor"
        )

    if not isinstance(provider, TrustedAnchorProvider):
        raise TrustedAnchorProviderError(
            "Provider does not implement the trusted-anchor contract"
        )

    try:
        receipt = provider.publish(anchor)
    except Exception as exc:
        raise TrustedAnchorProviderError(
            "External anchor publication failed"
        ) from exc

    if not isinstance(receipt, TrustedAnchorReceipt):
        raise TrustedAnchorProviderError(
            "Provider returned an invalid receipt"
        )

    if receipt.anchor_digest != anchor.digest:
        raise TrustedAnchorProviderError(
            "Receipt digest does not match the published anchor"
        )

    try:
        verified = provider.verify(anchor, receipt)
    except Exception as exc:
        raise TrustedAnchorProviderError(
            "External receipt verification failed"
        ) from exc

    if verified is not True:
        raise TrustedAnchorProviderError(
            "External receipt was not verified"
        )

    return receipt
