from __future__ import annotations

from typing import Protocol, runtime_checkable

from jas_si_agent.security_checkpoint_anchor import (
    SecurityCheckpointAnchor,
)
from jas_si_agent.trusted_anchor_hmac import verify_receipt_hmac
from jas_si_agent.trusted_anchor_provider import (
    TrustedAnchorProviderError,
    TrustedAnchorReceipt,
)


class TrustedAnchorApiProviderError(RuntimeError):
    """Raised when the API provider adapter fails."""


@runtime_checkable
class TrustedAnchorApiPublisher(Protocol):
    def publish(
        self,
        anchor: SecurityCheckpointAnchor,
    ) -> TrustedAnchorReceipt:
        ...


@runtime_checkable
class TrustedAnchorReceiptVerifier(Protocol):
    def verify(
        self,
        anchor: SecurityCheckpointAnchor,
        receipt: TrustedAnchorReceipt,
    ) -> bool:
        ...


class HmacReceiptVerifier:
    """Verify receipt HMAC using a separately configured shared secret.

    HMAC verification proves possession of the shared secret, not
    independent provider identity or external publication.
    """

    def __init__(self, secret: bytes) -> None:
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise TrustedAnchorApiProviderError(
                "HMAC secret must contain at least 32 bytes"
            )

        self._secret = secret

    def verify(
        self,
        anchor: SecurityCheckpointAnchor,
        receipt: TrustedAnchorReceipt,
    ) -> bool:
        if not isinstance(anchor, SecurityCheckpointAnchor):
            return False

        if not isinstance(receipt, TrustedAnchorReceipt):
            return False

        if receipt.anchor_digest != anchor.digest:
            return False

        try:
            return verify_receipt_hmac(
                receipt,
                self._secret,
            ) is True
        except (TrustedAnchorProviderError, TypeError, ValueError):
            return False


class ApiTrustedAnchorProvider:
    """Adapt the authenticated API client to TrustedAnchorProvider."""

    def __init__(
        self,
        publisher: TrustedAnchorApiPublisher,
        verifier: TrustedAnchorReceiptVerifier,
        *,
        expected_provider_id: str,
    ) -> None:
        if not isinstance(publisher, TrustedAnchorApiPublisher):
            raise TrustedAnchorApiProviderError(
                "Publisher does not implement the API publish contract"
            )

        if not isinstance(verifier, TrustedAnchorReceiptVerifier):
            raise TrustedAnchorApiProviderError(
                "Verifier does not implement the receipt verification contract"
            )

        if (
            not isinstance(expected_provider_id, str)
            or not expected_provider_id.strip()
            or expected_provider_id != expected_provider_id.strip()
        ):
            raise TrustedAnchorApiProviderError(
                "Expected provider ID must be a non-empty trimmed string"
            )

        self._publisher = publisher
        self._verifier = verifier
        self._expected_provider_id = expected_provider_id

    def publish(
        self,
        anchor: SecurityCheckpointAnchor,
    ) -> TrustedAnchorReceipt:
        if not isinstance(anchor, SecurityCheckpointAnchor):
            raise TrustedAnchorApiProviderError(
                "A valid checkpoint anchor is required"
            )

        try:
            receipt = self._publisher.publish(anchor)
        except Exception as exc:
            raise TrustedAnchorApiProviderError(
                "API provider publication failed"
            ) from exc

        if not isinstance(receipt, TrustedAnchorReceipt):
            raise TrustedAnchorApiProviderError(
                "API provider returned an invalid receipt"
            )

        if receipt.provider_id != self._expected_provider_id:
            raise TrustedAnchorApiProviderError(
                "Receipt provider ID does not match configuration"
            )

        if receipt.anchor_digest != anchor.digest:
            raise TrustedAnchorApiProviderError(
                "Receipt digest does not match the anchor"
            )

        return receipt

    def verify(
        self,
        anchor: SecurityCheckpointAnchor,
        receipt: TrustedAnchorReceipt,
    ) -> bool:
        if not isinstance(anchor, SecurityCheckpointAnchor):
            return False

        if not isinstance(receipt, TrustedAnchorReceipt):
            return False

        if receipt.provider_id != self._expected_provider_id:
            return False

        if receipt.anchor_digest != anchor.digest:
            return False

        try:
            return self._verifier.verify(anchor, receipt) is True
        except Exception:
            return False
