
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.trusted_anchor_hmac import (
    create_signed_receipt,
    sign_receipt_hmac,
    verify_receipt_hmac,
)
from jas_si_agent.trusted_anchor_provider import (
    TrustedAnchorProviderError,
    TrustedAnchorReceipt,
)


class TestTrustedAnchorHmac(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = b"test-secret-for-jas-si-at-least-32-bytes"

        self.receipt = create_signed_receipt(
            provider_id="test-provider",
            anchor_digest="a" * 64,
            external_reference="record-001",
            observed_at="2026-10-30T00:00:00Z",
            secret=self.secret,
        )

    def test_valid_signature_verifies(self) -> None:
        self.assertTrue(
            verify_receipt_hmac(self.receipt, self.secret)
        )

    def test_wrong_secret_is_rejected(self) -> None:
        self.assertFalse(
            verify_receipt_hmac(
                self.receipt,
                b"another-secret-that-is-at-least-32-bytes",
            )
        )

    def test_tampered_reference_is_rejected(self) -> None:
        tampered = TrustedAnchorReceipt(
            provider_id=self.receipt.provider_id,
            anchor_digest=self.receipt.anchor_digest,
            external_reference="record-tampered",
            observed_at=self.receipt.observed_at,
            proof=self.receipt.proof,
        )

        self.assertFalse(
            verify_receipt_hmac(tampered, self.secret)
        )

    def test_tampered_timestamp_is_rejected(self) -> None:
        tampered = TrustedAnchorReceipt(
            provider_id=self.receipt.provider_id,
            anchor_digest=self.receipt.anchor_digest,
            external_reference=self.receipt.external_reference,
            observed_at="2026-10-31T00:00:00Z",
            proof=self.receipt.proof,
        )

        self.assertFalse(
            verify_receipt_hmac(tampered, self.secret)
        )

    def test_tampered_signature_is_rejected(self) -> None:
        tampered = TrustedAnchorReceipt(
            provider_id=self.receipt.provider_id,
            anchor_digest=self.receipt.anchor_digest,
            external_reference=self.receipt.external_reference,
            observed_at=self.receipt.observed_at,
            proof="0" * 64,
        )

        self.assertFalse(
            verify_receipt_hmac(tampered, self.secret)
        )

    def test_short_secret_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            TrustedAnchorProviderError,
            "at least 32 bytes",
        ):
            sign_receipt_hmac(self.receipt, b"too-short")

    def test_signature_is_deterministic(self) -> None:
        first = sign_receipt_hmac(
            self.receipt,
            self.secret,
        )
        second = sign_receipt_hmac(
            self.receipt,
            self.secret,
        )

        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
