
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
    TrustedAnchorReceipt,
)
from jas_si_agent.trusted_anchor_integration import (
    TrustedAnchorIntegrationError,
    publish_or_recover_trusted_anchor,
)


class FakeRecoverableProvider:
    """In-memory test fixture only; not a production provider."""

    def __init__(self, provider_id="test-provider"):
        self.provider_id = provider_id
        self.records = {}
        self.publish_calls = 0

    def lookup_by_idempotency_key(self, idempotency_key):
        return self.records.get(idempotency_key)

    def publish_idempotent(self, anchor, idempotency_key):
        if idempotency_key != anchor.digest:
            raise ValueError("Invalid idempotency key")

        existing = self.records.get(idempotency_key)
        if existing is not None:
            return existing

        self.publish_calls += 1
        receipt = TrustedAnchorReceipt(
            provider_id=self.provider_id,
            anchor_digest=anchor.digest,
            external_reference=f"test-{anchor.digest[:16]}",
            observed_at="2026-10-31T00:00:00Z",
            proof=f"test-proof-{anchor.digest}",
        )
        self.records[idempotency_key] = receipt
        return receipt

    def verify(self, anchor, receipt):
        return (
            self.records.get(anchor.digest) == receipt
            and receipt.anchor_digest == anchor.digest
        )


class TestTrustedAnchorIntegration(unittest.TestCase):
    def setUp(self):
        self.provider = FakeRecoverableProvider()
        self.anchor = SecurityCheckpointAnchor(
            repository_id="jainulabedinshawon/JAS-SI",
            event_count=1,
            last_hash="a" * 64,
        )

    def test_accepts_matching_provider_identity(self):
        receipt = publish_or_recover_trusted_anchor(
            self.provider,
            self.anchor,
            expected_provider_id="test-provider",
        )

        self.assertEqual(receipt.provider_id, "test-provider")
        self.assertEqual(receipt.anchor_digest, self.anchor.digest)

    def test_rejects_unexpected_provider_identity(self):
        with self.assertRaises(TrustedAnchorIntegrationError):
            publish_or_recover_trusted_anchor(
                self.provider,
                self.anchor,
                expected_provider_id="unexpected-provider",
            )

    def test_rejects_blank_expected_provider_id(self):
        with self.assertRaises(TrustedAnchorIntegrationError):
            publish_or_recover_trusted_anchor(
                self.provider,
                self.anchor,
                expected_provider_id=" ",
            )

    def test_repeated_call_reuses_existing_publication(self):
        first = publish_or_recover_trusted_anchor(
            self.provider,
            self.anchor,
            expected_provider_id="test-provider",
        )
        second = publish_or_recover_trusted_anchor(
            self.provider,
            self.anchor,
            expected_provider_id="test-provider",
        )

        self.assertEqual(first, second)
        self.assertEqual(self.provider.publish_calls, 1)


if __name__ == "__main__":
    unittest.main()
