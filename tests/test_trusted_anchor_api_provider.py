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
from jas_si_agent.trusted_anchor_api_provider import (
    ApiTrustedAnchorProvider,
    HmacReceiptVerifier,
    TrustedAnchorApiProviderError,
)
from jas_si_agent.trusted_anchor_hmac import (
    create_signed_receipt,
)
from jas_si_agent.trusted_anchor_provider import (
    TrustedAnchorReceipt,
    publish_and_verify_anchor,
)


class FakePublisher:

    def __init__(self, receipt):
        self.receipt = receipt
        self.calls = 0

    def publish(self, anchor):
        self.calls += 1
        return self.receipt


class FakeVerifier:

    def __init__(self, result=True):
        self.result = result
        self.calls = 0

    def verify(self, anchor, receipt):
        self.calls += 1
        return self.result


class TestTrustedAnchorApiProvider(unittest.TestCase):

    SECRET = b"test-secret-for-api-provider-32-bytes"

    def setUp(self):
        self.anchor = SecurityCheckpointAnchor(
            repository_id="jas-si",
            event_count=1,
            last_hash="a" * 64,
        )

        self.receipt = create_signed_receipt(
            provider_id="example-provider",
            anchor_digest=self.anchor.digest,
            external_reference="external-123",
            observed_at="2026-10-31T12:00:00Z",
            secret=self.SECRET,
        )

    def make_provider(self, publisher=None, verifier=None):
        return ApiTrustedAnchorProvider(
            publisher or FakePublisher(self.receipt),
            verifier or HmacReceiptVerifier(self.SECRET),
            expected_provider_id="example-provider",
        )

    def test_successful_publish_and_verify(self):
        provider = self.make_provider()

        receipt = publish_and_verify_anchor(
            provider,
            self.anchor,
        )

        self.assertEqual(receipt, self.receipt)

    def test_rejects_wrong_provider_id(self):
        wrong_receipt = create_signed_receipt(
            provider_id="attacker-provider",
            anchor_digest=self.anchor.digest,
            external_reference="external-123",
            observed_at="2026-10-31T12:00:00Z",
            secret=self.SECRET,
        )

        provider = self.make_provider(
            publisher=FakePublisher(wrong_receipt)
        )

        with self.assertRaises(TrustedAnchorApiProviderError):
            provider.publish(self.anchor)

    def test_rejects_wrong_anchor_digest(self):
        wrong_receipt = create_signed_receipt(
            provider_id="example-provider",
            anchor_digest="b" * 64,
            external_reference="external-123",
            observed_at="2026-10-31T12:00:00Z",
            secret=self.SECRET,
        )

        provider = self.make_provider(
            publisher=FakePublisher(wrong_receipt)
        )

        with self.assertRaises(TrustedAnchorApiProviderError):
            provider.publish(self.anchor)

    def test_rejects_invalid_hmac(self):
        invalid_receipt = TrustedAnchorReceipt(
            provider_id="example-provider",
            anchor_digest=self.anchor.digest,
            external_reference="external-123",
            observed_at="2026-10-31T12:00:00Z",
            proof="0" * 64,
        )

        provider = self.make_provider(
            publisher=FakePublisher(invalid_receipt)
        )

        receipt = provider.publish(self.anchor)

        self.assertFalse(
            provider.verify(self.anchor, receipt)
        )

    def test_rejects_wrong_secret(self):
        verifier = HmacReceiptVerifier(
            b"different-secret-for-api-provider-32"
        )

        provider = self.make_provider(verifier=verifier)

        self.assertFalse(
            provider.verify(self.anchor, self.receipt)
        )

    def test_rejects_verifier_false(self):
        verifier = FakeVerifier(result=False)
        provider = self.make_provider(verifier=verifier)

        self.assertFalse(
            provider.verify(self.anchor, self.receipt)
        )

        self.assertEqual(verifier.calls, 1)

    def test_publish_calls_publisher_once(self):
        publisher = FakePublisher(self.receipt)
        provider = self.make_provider(publisher=publisher)

        provider.publish(self.anchor)

        self.assertEqual(publisher.calls, 1)

    def test_rejects_blank_provider_id(self):
        publisher = FakePublisher(self.receipt)
        verifier = HmacReceiptVerifier(self.SECRET)

        with self.assertRaises(TrustedAnchorApiProviderError):
            ApiTrustedAnchorProvider(
                publisher,
                verifier,
                expected_provider_id=" ",
            )


if __name__ == "__main__":
    unittest.main()
