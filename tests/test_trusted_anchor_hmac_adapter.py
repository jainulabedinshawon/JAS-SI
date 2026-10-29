
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
from jas_si_agent.trusted_anchor_hmac import create_signed_receipt
from jas_si_agent.trusted_anchor_hmac_adapter import (
    HmacVerifyingTrustedAnchorProvider,
)
from jas_si_agent.trusted_anchor_provider import (
    TrustedAnchorProviderError,
    TrustedAnchorReceipt,
    publish_and_verify_anchor,
)


SECRET = b"jas-si-test-secret-with-at-least-32-bytes"


class FakeBackend:
    def __init__(self, *, verification_result: bool = True) -> None:
        self.verification_result = verification_result

    def publish(
        self,
        anchor: SecurityCheckpointAnchor,
    ) -> TrustedAnchorReceipt:
        return create_signed_receipt(
            provider_id="test-provider",
            anchor_digest=anchor.digest,
            external_reference="record-001",
            observed_at="2026-10-30T00:00:00Z",
            secret=SECRET,
        )

    def verify(
        self,
        anchor: SecurityCheckpointAnchor,
        receipt: TrustedAnchorReceipt,
    ) -> bool:
        return (
            self.verification_result
            and receipt.anchor_digest == anchor.digest
        )


class TestHmacVerifyingTrustedAnchorProvider(unittest.TestCase):
    def setUp(self) -> None:
        self.anchor = SecurityCheckpointAnchor(
            repository_id="JAS-SI",
            event_count=3,
            last_hash="a" * 64,
        )

    def test_valid_receipt_passes_both_checks(self) -> None:
        provider = HmacVerifyingTrustedAnchorProvider(
            FakeBackend(),
            provider_id="test-provider",
            secret=SECRET,
        )

        receipt = publish_and_verify_anchor(
            provider,
            self.anchor,
        )

        self.assertEqual(receipt.anchor_digest, self.anchor.digest)

    def test_backend_verification_failure_fails_closed(self) -> None:
        provider = HmacVerifyingTrustedAnchorProvider(
            FakeBackend(verification_result=False),
            provider_id="test-provider",
            secret=SECRET,
        )

        with self.assertRaisesRegex(
            TrustedAnchorProviderError,
            "was not verified",
        ):
            publish_and_verify_anchor(provider, self.anchor)

    def test_wrong_provider_id_is_rejected(self) -> None:
        provider = HmacVerifyingTrustedAnchorProvider(
            FakeBackend(),
            provider_id="unexpected-provider",
            secret=SECRET,
        )

        with self.assertRaisesRegex(
            TrustedAnchorProviderError,
            "provider ID",
        ):
            publish_and_verify_anchor(provider, self.anchor)

    def test_wrong_secret_fails_closed(self) -> None:
        provider = HmacVerifyingTrustedAnchorProvider(
            FakeBackend(),
            provider_id="test-provider",
            secret=b"different-secret-with-at-least-32-bytes",
        )

        with self.assertRaisesRegex(
            TrustedAnchorProviderError,
            "HMAC signature is invalid",
        ):
            publish_and_verify_anchor(provider, self.anchor)

    def test_backend_exception_fails_closed(self) -> None:
        class RaisingBackend(FakeBackend):
            def verify(
                self,
                anchor: SecurityCheckpointAnchor,
                receipt: TrustedAnchorReceipt,
            ) -> bool:
                raise OSError("simulated verification outage")

        provider = HmacVerifyingTrustedAnchorProvider(
            RaisingBackend(),
            provider_id="test-provider",
            secret=SECRET,
        )

        with self.assertRaisesRegex(
            TrustedAnchorProviderError,
            "was not verified",
        ):
            publish_and_verify_anchor(provider, self.anchor)


if __name__ == "__main__":
    unittest.main()
