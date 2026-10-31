
from __future__ import annotations

from jas_si_agent.security_checkpoint_anchor import (
    SecurityCheckpointAnchor,
)
from jas_si_agent.trusted_anchor_provider import (
    TrustedAnchorReceipt,
)
from jas_si_agent.trusted_anchor_recovery import (
    RecoverableIdempotentTrustedAnchorProvider,
    TrustedAnchorRecoveryError,
    recover_or_publish_anchor,
)


class TrustedAnchorIntegrationError(RuntimeError):
    """Raised when the configured provider boundary cannot be trusted."""


def publish_or_recover_trusted_anchor(
    provider: RecoverableIdempotentTrustedAnchorProvider,
    anchor: SecurityCheckpointAnchor,
    *,
    expected_provider_id: str,
) -> TrustedAnchorReceipt:
    """Publish or recover an anchor and enforce the configured provider ID.

    This boundary validates the provider identity on the returned receipt.
    It does not establish that the provider is independently trustworthy;
    that requires a concrete provider and its own verification evidence.
    """

    if not isinstance(anchor, SecurityCheckpointAnchor):
        raise TrustedAnchorIntegrationError(
            "A valid SecurityCheckpointAnchor is required"
        )

    if not isinstance(
        provider,
        RecoverableIdempotentTrustedAnchorProvider,
    ):
        raise TrustedAnchorIntegrationError(
            "Provider does not implement the recovery contract"
        )

    if (
        not isinstance(expected_provider_id, str)
        or not expected_provider_id.strip()
        or expected_provider_id != expected_provider_id.strip()
    ):
        raise TrustedAnchorIntegrationError(
            "expected_provider_id must be a non-empty trimmed string"
        )

    try:
        receipt = recover_or_publish_anchor(provider, anchor)
    except TrustedAnchorRecoveryError as exc:
        raise TrustedAnchorIntegrationError(
            "Trusted Anchor publication or recovery failed"
        ) from exc

    if not isinstance(receipt, TrustedAnchorReceipt):
        raise TrustedAnchorIntegrationError(
            "Provider returned an invalid receipt"
        )

    if receipt.provider_id != expected_provider_id:
        raise TrustedAnchorIntegrationError(
            "Receipt provider ID does not match configured provider"
        )

    if receipt.anchor_digest != anchor.digest:
        raise TrustedAnchorIntegrationError(
            "Receipt digest does not match the requested anchor"
        )

    return receipt
