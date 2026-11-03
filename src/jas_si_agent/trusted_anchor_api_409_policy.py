from __future__ import annotations

from jas_si_agent.security_checkpoint_anchor import (
    SecurityCheckpointAnchor,
)
from jas_si_agent.trusted_anchor_provider import (
    TrustedAnchorReceipt,
)
from jas_si_agent.trusted_anchor_api_recovery import (
    TrustedAnchorApiRequestInProgressError,
    TrustedAnchorApiRecoveryError,
)
from jas_si_agent.trusted_anchor_recovery import (
    RecoverableIdempotentTrustedAnchorProvider,
    recover_or_publish_anchor,
)


def recover_anchor_with_409_policy(
    provider: RecoverableIdempotentTrustedAnchorProvider,
    anchor: SecurityCheckpointAnchor,
    *,
    max_lookup_attempts: int = 3,
) -> TrustedAnchorReceipt:
    """Recover a publication after HTTP 409 without republishing.

    The initial recovery performs one lookup and one idempotent publish.
    If publication reports HTTP 409, this function performs only bounded
    lookups using the same anchor digest. It never republishes.

    HTTP 422 and all other errors propagate without retry.
    """

    if (
        not isinstance(max_lookup_attempts, int)
        or isinstance(max_lookup_attempts, bool)
        or not 1 <= max_lookup_attempts <= 5
    ):
        raise TrustedAnchorApiRecoveryError(
            "max_lookup_attempts must be an integer between 1 and 5"
        )

    try:
        return recover_or_publish_anchor(provider, anchor)

    except TrustedAnchorApiRequestInProgressError as original_error:
        idempotency_key = anchor.digest

        for _ in range(max_lookup_attempts):
            try:
                receipt = provider.lookup_by_idempotency_key(
                    idempotency_key
                )
            except Exception as exc:
                raise TrustedAnchorApiRecoveryError(
                    "Lookup failed while recovering an in-progress request"
                ) from exc

            if receipt is None:
                continue

            if not isinstance(receipt, TrustedAnchorReceipt):
                raise TrustedAnchorApiRecoveryError(
                    "Provider returned an invalid recovery receipt"
                )

            if receipt.anchor_digest != anchor.digest:
                raise TrustedAnchorApiRecoveryError(
                    "Recovery receipt digest does not match the anchor"
                )

            try:
                verified = provider.verify(anchor, receipt)
            except Exception as exc:
                raise TrustedAnchorApiRecoveryError(
                    "Recovered receipt verification failed"
                ) from exc

            if verified is not True:
                raise TrustedAnchorApiRecoveryError(
                    "Recovered receipt was not verified"
                )

            return receipt

        # Still processing: preserve the original HTTP 409 classification.
        raise original_error
