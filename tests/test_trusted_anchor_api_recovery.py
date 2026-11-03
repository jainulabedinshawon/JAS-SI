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
from jas_si_agent.trusted_anchor_api_recovery import (
    RecoverableApiTrustedAnchorProvider,
    TrustedAnchorApiRecoveryError,
)
from jas_si_agent.trusted_anchor_hmac import (
    create_signed_receipt,
)
from jas_si_agent.trusted_anchor_recovery import (
    recover_or_publish_anchor,
)


SECRET = b"test-api-recovery-secret-minimum-32-bytes"


class FakeBackend:

    def __init__(self):
        self.records = {}
        self.publish_calls = 0
        self.lookup_calls = 0

    def publish_idempotent(self, anchor, idempotency_key):
        self.publish_calls += 1

        if idempotency_key != anchor.digest:
            raise ValueError("Invalid idempotency key")

        existing = self.records.get(idempotency_key)

        if existing is not None:
            return existing

        receipt = create_signed_receipt(
            provider_id="example-provider",
            anchor_digest=anchor.digest,
            external_reference="external-" + anchor.digest[:12],
            observed_at="2026-10-31T12:00:00Z",
            secret=SECRET,
        )

        self.records[idempotency_key] = receipt
        return receipt

    def lookup_by_idempotency_key(self, idempotency_key):
        self.lookup_calls += 1
        return self.records.get(idempotency_key)


class FakeVerifier:

    def verify(self, anchor, receipt):
        from jas_si_agent.trusted_anchor_hmac import (
            verify_receipt_hmac,
        )

        return (
            receipt.anchor_digest == anchor.digest
            and verify_receipt_hmac(receipt, SECRET)
        )


class TestTrustedAnchorApiRecovery(unittest.TestCase):

    def setUp(self):
        self.anchor = SecurityCheckpointAnchor(
            repository_id="jas-si",
            event_count=5,
            last_hash="a" * 64,
        )

        self.backend = FakeBackend()

        self.provider = RecoverableApiTrustedAnchorProvider(
            self.backend,
            FakeVerifier(),
            expected_provider_id="example-provider",
        )

    def test_publish_when_no_existing_receipt(self):
        receipt = recover_or_publish_anchor(
            self.provider,
            self.anchor,
        )

        self.assertEqual(receipt.anchor_digest, self.anchor.digest)
        self.assertEqual(self.backend.lookup_calls, 1)
        self.assertEqual(self.backend.publish_calls, 1)

    def test_reuses_existing_receipt_without_duplicate_publish(self):
        first = recover_or_publish_anchor(
            self.provider,
            self.anchor,
        )

        second = recover_or_publish_anchor(
            self.provider,
            self.anchor,
        )

        self.assertEqual(first, second)
        self.assertEqual(self.backend.publish_calls, 1)
        self.assertEqual(self.backend.lookup_calls, 2)

    def test_rejects_wrong_idempotency_key(self):
        with self.assertRaises(TrustedAnchorApiRecoveryError):
            self.provider.publish_idempotent(
                self.anchor,
                "b" * 64,
            )

    def test_rejects_invalid_lookup_key(self):
        with self.assertRaises(TrustedAnchorApiRecoveryError):
            self.provider.lookup_by_idempotency_key("invalid")

    def test_rejects_wrong_provider_receipt(self):
        wrong_receipt = create_signed_receipt(
            provider_id="attacker-provider",
            anchor_digest=self.anchor.digest,
            external_reference="external-123",
            observed_at="2026-10-31T12:00:00Z",
            secret=SECRET,
        )

        self.backend.records[self.anchor.digest] = wrong_receipt

        with self.assertRaises(TrustedAnchorApiRecoveryError):
            self.provider.lookup_by_idempotency_key(
                self.anchor.digest
            )

    def test_rejects_wrong_digest_receipt(self):
        wrong_receipt = create_signed_receipt(
            provider_id="example-provider",
            anchor_digest="b" * 64,
            external_reference="external-123",
            observed_at="2026-10-31T12:00:00Z",
            secret=SECRET,
        )

        self.backend.records[self.anchor.digest] = wrong_receipt

        with self.assertRaises(TrustedAnchorApiRecoveryError):
            self.provider.lookup_by_idempotency_key(
                self.anchor.digest
            )

    def test_verification_fails_for_wrong_anchor(self):
        receipt = self.provider.publish_idempotent(
            self.anchor,
            self.anchor.digest,
        )

        another_anchor = SecurityCheckpointAnchor(
            repository_id="jas-si",
            event_count=6,
            last_hash="c" * 64,
        )

        self.assertFalse(
            self.provider.verify(another_anchor, receipt)
        )

    def test_backend_lookup_failure_fails_closed(self):

        class BrokenBackend(FakeBackend):

            def lookup_by_idempotency_key(self, key):
                raise ConnectionError("Simulated outage")

        provider = RecoverableApiTrustedAnchorProvider(
            BrokenBackend(),
            FakeVerifier(),
            expected_provider_id="example-provider",
        )

        with self.assertRaises(Exception):
            recover_or_publish_anchor(
                provider,
                self.anchor,
            )


if __name__ == "__main__":
    unittest.main()
