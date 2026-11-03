
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.security_checkpoint_anchor import (
    SecurityCheckpointAnchor,
)
from jas_si_agent.trusted_anchor_provider import (
    TrustedAnchorProviderError,
    TrustedAnchorReceipt,
    publish_and_verify_anchor,
)


class FakeTrustedAnchorProvider:
    """Test double only; it is not an external trust service."""

    def __init__(self, *, verification_result: bool = True) -> None:
        self.verification_result = verification_result
        self.published: list[SecurityCheckpointAnchor] = []
        self.receipt: TrustedAnchorReceipt | None = None

    def publish(
        self,
        anchor: SecurityCheckpointAnchor,
    ) -> TrustedAnchorReceipt:
        self.published.append(anchor)
        self.receipt = TrustedAnchorReceipt(
            provider_id="test-provider",
            anchor_digest=anchor.digest,
            external_reference="test-record-001",
            observed_at="2026-01-01T00:00:00Z",
            proof="test-proof-not-cryptographic",
        )
        return self.receipt

    def verify(
        self,
        anchor: SecurityCheckpointAnchor,
        receipt: TrustedAnchorReceipt,
    ) -> bool:
        return (
            self.verification_result
            and receipt.anchor_digest == anchor.digest
        )


class TestTrustedAnchorProvider(unittest.TestCase):
    def setUp(self) -> None:
        self.anchor = SecurityCheckpointAnchor(
            repository_id="JAS-SI",
            event_count=3,
            last_hash="a" * 64,
        )

    def test_publishes_and_verifies_receipt(self) -> None:
        provider = FakeTrustedAnchorProvider()

        receipt = publish_and_verify_anchor(
            provider,
            self.anchor,
        )

        self.assertEqual(receipt.anchor_digest, self.anchor.digest)
        self.assertEqual(provider.published, [self.anchor])

    def test_fails_closed_when_receipt_is_not_verified(self) -> None:
        provider = FakeTrustedAnchorProvider(
            verification_result=False,
        )

        with self.assertRaisesRegex(
            TrustedAnchorProviderError,
            "was not verified",
        ):
            publish_and_verify_anchor(provider, self.anchor)

    def test_rejects_receipt_for_different_anchor(self) -> None:
        class MismatchedProvider(FakeTrustedAnchorProvider):
            def publish(
                self,
                anchor: SecurityCheckpointAnchor,
            ) -> TrustedAnchorReceipt:
                return TrustedAnchorReceipt(
                    provider_id="test-provider",
                    anchor_digest="b" * 64,
                    external_reference="test-record-002",
                    observed_at="2026-01-01T00:00:00Z",
                    proof="test-proof",
                )

        with self.assertRaisesRegex(
            TrustedAnchorProviderError,
            "does not match",
        ):
            publish_and_verify_anchor(
                MismatchedProvider(),
                self.anchor,
            )

    def test_rejects_invalid_receipt_fields(self) -> None:
        with self.assertRaisesRegex(
            TrustedAnchorProviderError,
            "anchor_digest",
        ):
            TrustedAnchorReceipt(
                provider_id="test-provider",
                anchor_digest="invalid",
                external_reference="test-record-003",
                observed_at="2026-01-01T00:00:00Z",
                proof="test-proof",
            )

    def test_fails_closed_when_provider_raises(self) -> None:
        class UnavailableProvider(FakeTrustedAnchorProvider):
            def publish(
                self,
                anchor: SecurityCheckpointAnchor,
            ) -> TrustedAnchorReceipt:
                raise OSError("simulated provider outage")

        with self.assertRaisesRegex(
            TrustedAnchorProviderError,
            "publication failed",
        ):
            publish_and_verify_anchor(
                UnavailableProvider(),
                self.anchor,
            )


if __name__ == "__main__":
    unittest.main()
