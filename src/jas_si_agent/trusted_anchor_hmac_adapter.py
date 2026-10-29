
from __future__ import annotations

from jas_si_agent.security_checkpoint_anchor import (
    SecurityCheckpointAnchor,
)
from jas_si_agent.trusted_anchor_hmac import verify_receipt_hmac
from jas_si_agent.trusted_anchor_provider import (
    TrustedAnchorProvider,
    TrustedAnchorProviderError,
    TrustedAnchorReceipt,
)


class HmacVerifyingTrustedAnchorProvider:
    """Wrap a provider and require both backend and HMAC verification."""

    def __init__(
        self,
        backend: TrustedAnchorProvider,
        *,
        provider_id: str,
        secret: bytes,
    ) -> None:
        if not isinstance(backend, TrustedAnchorProvider):
            raise TrustedAnchorProviderError(
                "Backend does not implement the trusted-anchor contract"
            )

        if (
            not isinstance(provider_id, str)
            or not provider_id.strip()
            or provider_id != provider_id.strip()
        ):
            raise TrustedAnchorProviderError(
                "provider_id must be a non-empty trimmed string"
            )

        if not isinstance(secret, bytes) or len(secret) < 32:
            raise TrustedAnchorProviderError(
                "HMAC secret must contain at least 32 bytes"
            )

        self._backend = backend
        self._provider_id = provider_id
        self._secret = secret

    def publish(
        self,
        anchor: SecurityCheckpointAnchor,
    ) -> TrustedAnchorReceipt:
        if not isinstance(anchor, SecurityCheckpointAnchor):
            raise TrustedAnchorProviderError(
                "Expected a SecurityCheckpointAnchor"
            )

        receipt = self._backend.publish(anchor)

        if not isinstance(receipt, TrustedAnchorReceipt):
            raise TrustedAnchorProviderError(
                "Backend returned an invalid receipt"
            )

        if receipt.provider_id != self._provider_id:
            raise TrustedAnchorProviderError(
                "Receipt provider ID does not match configuration"
            )

        if receipt.anchor_digest != anchor.digest:
            raise TrustedAnchorProviderError(
                "Receipt digest does not match the published anchor"
            )

        if not verify_receipt_hmac(receipt, self._secret):
            raise TrustedAnchorProviderError(
                "Receipt HMAC signature is invalid"
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

        if receipt.provider_id != self._provider_id:
            return False

        if receipt.anchor_digest != anchor.digest:
            return False

        if not verify_receipt_hmac(receipt, self._secret):
            return False

        try:
            return self._backend.verify(anchor, receipt) is True
        except Exception:
            return False
