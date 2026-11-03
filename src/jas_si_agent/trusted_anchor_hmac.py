
from __future__ import annotations

import hashlib
import hmac

from jas_si_agent.trusted_anchor_provider import (
    TrustedAnchorReceipt,
    TrustedAnchorProviderError,
)


_MIN_SECRET_BYTES = 32


def _validate_secret(secret: bytes) -> None:
    if not isinstance(secret, bytes):
        raise TrustedAnchorProviderError(
            "HMAC secret must be bytes"
        )

    if len(secret) < _MIN_SECRET_BYTES:
        raise TrustedAnchorProviderError(
            "HMAC secret must contain at least 32 bytes"
        )


def canonical_receipt_payload(
    receipt: TrustedAnchorReceipt,
) -> bytes:
    """Build an unambiguous canonical payload for receipt signing."""

    if not isinstance(receipt, TrustedAnchorReceipt):
        raise TrustedAnchorProviderError(
            "Expected a TrustedAnchorReceipt"
        )

    fields = (
        receipt.provider_id,
        receipt.anchor_digest,
        receipt.external_reference,
        receipt.observed_at,
    )

    payload = bytearray(b"JAS-SI-TRUSTED-ANCHOR-RECEIPT-V1\x00")

    for field in fields:
        encoded = field.encode("utf-8")
        payload.extend(len(encoded).to_bytes(4, "big"))
        payload.extend(encoded)

    return bytes(payload)


def sign_receipt_hmac(
    receipt: TrustedAnchorReceipt,
    secret: bytes,
) -> str:
    """Return an HMAC-SHA256 signature for receipt metadata."""

    _validate_secret(secret)
    payload = canonical_receipt_payload(receipt)

    return hmac.new(
        secret,
        payload,
        hashlib.sha256,
    ).hexdigest()


def verify_receipt_hmac(
    receipt: TrustedAnchorReceipt,
    secret: bytes,
) -> bool:
    """Verify receipt.proof using constant-time comparison."""

    _validate_secret(secret)

    expected = sign_receipt_hmac(
        TrustedAnchorReceipt(
            provider_id=receipt.provider_id,
            anchor_digest=receipt.anchor_digest,
            external_reference=receipt.external_reference,
            observed_at=receipt.observed_at,
            proof="placeholder",
        ),
        secret,
    )

    return hmac.compare_digest(receipt.proof, expected)


def create_signed_receipt(
    *,
    provider_id: str,
    anchor_digest: str,
    external_reference: str,
    observed_at: str,
    secret: bytes,
) -> TrustedAnchorReceipt:
    """Create a receipt whose proof is an HMAC-SHA256 signature."""

    _validate_secret(secret)

    unsigned = TrustedAnchorReceipt(
        provider_id=provider_id,
        anchor_digest=anchor_digest,
        external_reference=external_reference,
        observed_at=observed_at,
        proof="placeholder",
    )

    signature = sign_receipt_hmac(unsigned, secret)

    return TrustedAnchorReceipt(
        provider_id=provider_id,
        anchor_digest=anchor_digest,
        external_reference=external_reference,
        observed_at=observed_at,
        proof=signature,
    )
