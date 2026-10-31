from __future__ import annotations

from typing import Protocol, runtime_checkable

from jas_si_agent.security_checkpoint_anchor import (
    SecurityCheckpointAnchor,
)
from jas_si_agent.trusted_anchor_provider import (
    TrustedAnchorReceipt,
)
from jas_si_agent.trusted_anchor_recovery import (
    RecoverableIdempotentTrustedAnchorProvider,
)


class TrustedAnchorApiRecoveryError(RuntimeError):
    """Raised when API recovery operations fail."""


@runtime_checkable
class TrustedAnchorApiRecoveryBackend(Protocol):
    """Provider-specific backend contract.

    A real implementation must guarantee atomic idempotency
    and consistent lookup semantics on the provider side.
    """

    def publish_idempotent(
        self,
        anchor: SecurityCheckpointAnchor,
        idempotency_key: str,
    ) -> TrustedAnchorReceipt:
        ...

    def lookup_by_idempotency_key(
        self,
        idempotency_key: str,
    ) -> TrustedAnchorReceipt | None:
        ...


@runtime_checkable
class TrustedAnchorApiReceiptVerifier(Protocol):
    def verify(
        self,
        anchor: SecurityCheckpointAnchor,
        receipt: TrustedAnchorReceipt,
    ) -> bool:
        ...


class RecoverableApiTrustedAnchorProvider:
    """Recovery-capable adapter for an injected API backend."""

    def __init__(
        self,
        backend: TrustedAnchorApiRecoveryBackend,
        verifier: TrustedAnchorApiReceiptVerifier,
        *,
        expected_provider_id: str,
    ) -> None:
        if not isinstance(backend, TrustedAnchorApiRecoveryBackend):
            raise TrustedAnchorApiRecoveryError(
                "Backend does not implement the recovery contract"
            )

        if not isinstance(verifier, TrustedAnchorApiReceiptVerifier):
            raise TrustedAnchorApiRecoveryError(
                "Verifier does not implement the verification contract"
            )

        if (
            not isinstance(expected_provider_id, str)
            or not expected_provider_id.strip()
            or expected_provider_id != expected_provider_id.strip()
        ):
            raise TrustedAnchorApiRecoveryError(
                "Expected provider ID must be a non-empty trimmed string"
            )

        self._backend = backend
        self._verifier = verifier
        self._expected_provider_id = expected_provider_id

    def _validate_receipt(
        self,
        receipt: TrustedAnchorReceipt,
        *,
        expected_digest: str | None = None,
    ) -> TrustedAnchorReceipt:
        if not isinstance(receipt, TrustedAnchorReceipt):
            raise TrustedAnchorApiRecoveryError(
                "Backend returned an invalid receipt"
            )

        if receipt.provider_id != self._expected_provider_id:
            raise TrustedAnchorApiRecoveryError(
                "Receipt provider ID does not match configuration"
            )

        if (
            expected_digest is not None
            and receipt.anchor_digest != expected_digest
        ):
            raise TrustedAnchorApiRecoveryError(
                "Receipt digest does not match the requested anchor"
            )

        return receipt

    def publish_idempotent(
        self,
        anchor: SecurityCheckpointAnchor,
        idempotency_key: str,
    ) -> TrustedAnchorReceipt:
        if not isinstance(anchor, SecurityCheckpointAnchor):
            raise TrustedAnchorApiRecoveryError(
                "A valid checkpoint anchor is required"
            )

        if idempotency_key != anchor.digest:
            raise TrustedAnchorApiRecoveryError(
                "Idempotency key must equal the anchor digest"
            )

        try:
            receipt = self._backend.publish_idempotent(
                anchor,
                idempotency_key,
            )
        except Exception as exc:
            raise TrustedAnchorApiRecoveryError(
                "API idempotent publication failed"
            ) from exc

        return self._validate_receipt(
            receipt,
            expected_digest=anchor.digest,
        )

    def lookup_by_idempotency_key(
        self,
        idempotency_key: str,
    ) -> TrustedAnchorReceipt | None:
        if (
            not isinstance(idempotency_key, str)
            or len(idempotency_key) != 64
            or any(c not in "0123456789abcdef" for c in idempotency_key)
        ):
            raise TrustedAnchorApiRecoveryError(
                "A lowercase SHA-256 idempotency key is required"
            )

        try:
            receipt = self._backend.lookup_by_idempotency_key(
                idempotency_key
            )
        except Exception as exc:
            raise TrustedAnchorApiRecoveryError(
                "API publication lookup failed"
            ) from exc

        if receipt is None:
            return None

        return self._validate_receipt(
            receipt,
            expected_digest=idempotency_key,
        )

    def verify(
        self,
        anchor: SecurityCheckpointAnchor,
        receipt: TrustedAnchorReceipt,
    ) -> bool:
        if not isinstance(anchor, SecurityCheckpointAnchor):
            return False

        try:
            self._validate_receipt(
                receipt,
                expected_digest=anchor.digest,
            )

            return self._verifier.verify(anchor, receipt) is True

        except Exception:
            return False
