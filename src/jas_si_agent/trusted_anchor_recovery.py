from __future__ import annotations

from typing import Protocol, runtime_checkable

from jas_si_agent.security_checkpoint_anchor import (
    SecurityCheckpointAnchor,
)
from jas_si_agent.trusted_anchor_provider import (
    TrustedAnchorReceipt,
)
from jas_si_agent.trusted_anchor_idempotency import (
    IdempotentTrustedAnchorProvider,
)


class TrustedAnchorRecoveryError(RuntimeError):
    """Raised when trusted-anchor recovery cannot complete."""


@runtime_checkable
class RecoverableIdempotentTrustedAnchorProvider(
    IdempotentTrustedAnchorProvider,
    Protocol,
):
    """Provider contract that supports lookup after an interrupted run."""

    def lookup_by_idempotency_key(
        self,
        idempotency_key: str,
    ) -> TrustedAnchorReceipt | None:
        """Return the existing receipt, or None when no record exists."""
        ...


def _verify_receipt(
    provider: RecoverableIdempotentTrustedAnchorProvider,
    anchor: SecurityCheckpointAnchor,
    receipt: TrustedAnchorReceipt,
) -> TrustedAnchorReceipt:
    if not isinstance(receipt, TrustedAnchorReceipt):
        raise TrustedAnchorRecoveryError(
            "Provider returned an invalid recovery receipt"
        )

    if receipt.anchor_digest != anchor.digest:
        raise TrustedAnchorRecoveryError(
            "Recovery receipt digest does not match the anchor"
        )

    try:
        verified = provider.verify(anchor, receipt)
    except Exception as exc:
        raise TrustedAnchorRecoveryError(
            "Recovered receipt verification failed"
        ) from exc

    if verified is not True:
        raise TrustedAnchorRecoveryError(
            "Recovered receipt was not verified"
        )

    return receipt


def recover_or_publish_anchor(
    provider: RecoverableIdempotentTrustedAnchorProvider,
    anchor: SecurityCheckpointAnchor,
) -> TrustedAnchorReceipt:
    """Recover an existing publication or safely publish a missing one.

    The provider must enforce atomic idempotency for concurrent requests.
    This function does not itself guarantee distributed exactly-once
    execution.
    """

    if not isinstance(anchor, SecurityCheckpointAnchor):
        raise TrustedAnchorRecoveryError(
            "A valid SecurityCheckpointAnchor is required"
        )

    if not isinstance(
        provider,
        RecoverableIdempotentTrustedAnchorProvider,
    ):
        raise TrustedAnchorRecoveryError(
            "Provider does not implement the recovery contract"
        )

    idempotency_key = anchor.digest

    try:
        existing_receipt = provider.lookup_by_idempotency_key(
            idempotency_key
        )
    except Exception as exc:
        raise TrustedAnchorRecoveryError(
            "Unable to look up existing anchor publication"
        ) from exc

    if existing_receipt is not None:
        return _verify_receipt(
            provider,
            anchor,
            existing_receipt,
        )

    try:
        receipt = provider.publish_idempotent(
            anchor,
            idempotency_key,
        )
    except Exception as exc:
        raise TrustedAnchorRecoveryError(
            "Idempotent recovery publication failed"
        ) from exc

    return _verify_receipt(
        provider,
        anchor,
        receipt,
    )
