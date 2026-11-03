from __future__ import annotations

from typing import Protocol, runtime_checkable

from jas_si_agent.security_checkpoint_anchor import (
    SecurityCheckpointAnchor,
)
from jas_si_agent.trusted_anchor_provider import (
    TrustedAnchorReceipt,
)


class TrustedAnchorIdempotencyError(RuntimeError):
    """Raised when idempotent anchor publication fails."""


@runtime_checkable
class IdempotentTrustedAnchorProvider(Protocol):
    """Provider contract for retry-safe anchor publication.

    Implementations must guarantee:
    - The same idempotency key and same anchor return the same
      logical publication.
    - Reusing a key with a different anchor is rejected.
    - Concurrent requests using the same key do not create
      multiple logical publications.
    """

    def publish_idempotent(
        self,
        anchor: SecurityCheckpointAnchor,
        idempotency_key: str,
    ) -> TrustedAnchorReceipt:
        ...

    def verify(
        self,
        anchor: SecurityCheckpointAnchor,
        receipt: TrustedAnchorReceipt,
    ) -> bool:
        ...


def publish_and_verify_anchor_idempotently(
    provider: IdempotentTrustedAnchorProvider,
    anchor: SecurityCheckpointAnchor,
) -> TrustedAnchorReceipt:
    """Publish using the anchor digest as a stable idempotency key."""

    if not isinstance(anchor, SecurityCheckpointAnchor):
        raise TrustedAnchorIdempotencyError(
            "A valid SecurityCheckpointAnchor is required"
        )

    if not isinstance(provider, IdempotentTrustedAnchorProvider):
        raise TrustedAnchorIdempotencyError(
            "Provider does not implement the idempotent anchor contract"
        )

    idempotency_key = anchor.digest

    try:
        receipt = provider.publish_idempotent(
            anchor,
            idempotency_key,
        )
    except Exception as exc:
        raise TrustedAnchorIdempotencyError(
            "Idempotent anchor publication failed"
        ) from exc

    if not isinstance(receipt, TrustedAnchorReceipt):
        raise TrustedAnchorIdempotencyError(
            "Provider returned an invalid receipt"
        )

    if receipt.anchor_digest != anchor.digest:
        raise TrustedAnchorIdempotencyError(
            "Receipt digest does not match the anchor"
        )

    try:
        verified = provider.verify(anchor, receipt)
    except Exception as exc:
        raise TrustedAnchorIdempotencyError(
            "Anchor receipt verification failed"
        ) from exc

    if verified is not True:
        raise TrustedAnchorIdempotencyError(
            "Anchor receipt was not verified"
        )

    return receipt
