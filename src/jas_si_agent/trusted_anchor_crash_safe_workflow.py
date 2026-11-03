
from __future__ import annotations

from typing import Protocol, runtime_checkable

from jas_si_agent.security_checkpoint_anchor import (
    SecurityCheckpointAnchor,
)
from jas_si_agent.trusted_anchor_outbox import (
    TrustedAnchorOutbox,
    TrustedAnchorOutboxError,
)
from jas_si_agent.trusted_anchor_provider import (
    TrustedAnchorReceipt,
)
from jas_si_agent.trusted_anchor_recovery import (
    RecoverableIdempotentTrustedAnchorProvider,
)


class TrustedAnchorCrashSafeWorkflowError(RuntimeError):
    """Raised when crash-safe anchor publication cannot complete."""


@runtime_checkable
class CrashSafeTrustedAnchorOutbox(Protocol):
    """Minimal durable outbox contract required by this workflow."""

    def prepare(
        self,
        anchor: SecurityCheckpointAnchor,
    ):
        ...

    def get(
        self,
        anchor_digest: str,
    ):
        ...

    def mark_verified(
        self,
        anchor: SecurityCheckpointAnchor,
        receipt: TrustedAnchorReceipt,
    ):
        ...


def _verify_receipt(
    provider: RecoverableIdempotentTrustedAnchorProvider,
    anchor: SecurityCheckpointAnchor,
    receipt: TrustedAnchorReceipt,
) -> TrustedAnchorReceipt:
    if not isinstance(receipt, TrustedAnchorReceipt):
        raise TrustedAnchorCrashSafeWorkflowError(
            "Provider returned an invalid receipt"
        )

    if receipt.anchor_digest != anchor.digest:
        raise TrustedAnchorCrashSafeWorkflowError(
            "Receipt digest does not match the anchor"
        )

    try:
        verified = provider.verify(anchor, receipt)
    except Exception as exc:
        raise TrustedAnchorCrashSafeWorkflowError(
            "Independent receipt verification failed"
        ) from exc

    if verified is not True:
        raise TrustedAnchorCrashSafeWorkflowError(
            "Receipt was not independently verified"
        )

    return receipt


def publish_anchor_crash_safely(
    provider: RecoverableIdempotentTrustedAnchorProvider,
    outbox: TrustedAnchorOutbox,
    anchor: SecurityCheckpointAnchor,
) -> TrustedAnchorReceipt:
    """Publish, recover, verify, and durably record a trusted anchor.

    Sequence:
      1. Persist PENDING before external provider operations.
      2. Re-verify a previously stored VERIFIED receipt.
      3. For PENDING, look up the provider using anchor.digest.
      4. Publish idempotently only when lookup returns None.
      5. Independently verify the receipt.
      6. Persist VERIFIED before returning.

    The provider must enforce atomic idempotency for concurrent requests.
    The local outbox does not provide distributed exactly-once execution.
    """

    if not isinstance(anchor, SecurityCheckpointAnchor):
        raise TrustedAnchorCrashSafeWorkflowError(
            "A valid SecurityCheckpointAnchor is required"
        )

    if not isinstance(
        provider,
        RecoverableIdempotentTrustedAnchorProvider,
    ):
        raise TrustedAnchorCrashSafeWorkflowError(
            "Provider does not implement the recovery contract"
        )

    if not isinstance(outbox, CrashSafeTrustedAnchorOutbox):
        raise TrustedAnchorCrashSafeWorkflowError(
            "Outbox does not implement the required durable contract"
        )

    try:
        prepared = outbox.prepare(anchor)
    except Exception as exc:
        raise TrustedAnchorCrashSafeWorkflowError(
            "Unable to persist the pending anchor"
        ) from exc

    if getattr(prepared, "anchor", None) != anchor:
        raise TrustedAnchorCrashSafeWorkflowError(
            "Outbox returned a different anchor"
        )

    status = getattr(prepared, "status", None)

    if status == "VERIFIED":
        stored_receipt = getattr(prepared, "receipt", None)

        receipt = _verify_receipt(
            provider,
            anchor,
            stored_receipt,
        )

        return receipt

    if status != "PENDING":
        raise TrustedAnchorCrashSafeWorkflowError(
            "Outbox returned an unsupported state"
        )

    try:
        existing_receipt = provider.lookup_by_idempotency_key(
            anchor.digest
        )
    except Exception as exc:
        raise TrustedAnchorCrashSafeWorkflowError(
            "Provider lookup failed; publication was not attempted"
        ) from exc

    if existing_receipt is None:
        try:
            receipt = provider.publish_idempotent(
                anchor,
                anchor.digest,
            )
        except Exception as exc:
            raise TrustedAnchorCrashSafeWorkflowError(
                "Idempotent anchor publication failed"
            ) from exc
    else:
        receipt = existing_receipt

    verified_receipt = _verify_receipt(
        provider,
        anchor,
        receipt,
    )

    try:
        persisted = outbox.mark_verified(
            anchor,
            verified_receipt,
        )
    except Exception as exc:
        raise TrustedAnchorCrashSafeWorkflowError(
            "Receipt verified, but durable VERIFIED persistence failed"
        ) from exc

    if (
        getattr(persisted, "anchor", None) != anchor
        or getattr(persisted, "status", None) != "VERIFIED"
        or getattr(persisted, "receipt", None) != verified_receipt
    ):
        raise TrustedAnchorCrashSafeWorkflowError(
            "Outbox did not confirm the verified state"
        )

    return verified_receipt
