
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.security_checkpoint_anchor import (
    SecurityCheckpointAnchor,
)
from jas_si_agent.trusted_anchor_crash_safe_workflow import (
    TrustedAnchorCrashSafeWorkflowError,
    publish_anchor_crash_safely,
)
from jas_si_agent.trusted_anchor_hmac import create_signed_receipt
from jas_si_agent.trusted_anchor_outbox import TrustedAnchorOutbox
from jas_si_agent.trusted_anchor_provider import TrustedAnchorReceipt


SECRET = b"jas-si-crash-safe-test-secret-at-least-32-bytes"


class FakeRecoverableProvider:
    def __init__(self):
        self.records = {}
        self.lookup_calls = 0
        self.publish_calls = 0
        self.verify_calls = 0
        self.lookup_error = False
        self.publish_error = False
        self.verify_result = True

    def lookup_by_idempotency_key(self, idempotency_key):
        self.lookup_calls += 1

        if self.lookup_error:
            raise RuntimeError("simulated lookup failure")

        return self.records.get(idempotency_key)

    def publish_idempotent(self, anchor, idempotency_key):
        self.publish_calls += 1

        if self.publish_error:
            raise RuntimeError("simulated publication failure")

        if idempotency_key != anchor.digest:
            raise AssertionError("unexpected idempotency key")

        existing = self.records.get(idempotency_key)

        if existing is not None:
            return existing

        receipt = create_signed_receipt(
            provider_id="crash-safe-test-provider",
            anchor_digest=anchor.digest,
            external_reference="crash-safe-record-001",
            observed_at="2026-10-30T00:00:00Z",
            secret=SECRET,
        )

        self.records[idempotency_key] = receipt
        return receipt

    def verify(self, anchor, receipt):
        self.verify_calls += 1

        if receipt.anchor_digest != anchor.digest:
            return False

        return self.verify_result


class TrustedAnchorCrashSafeWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.outbox = TrustedAnchorOutbox(
            Path(self.temp_dir.name) / "trusted-anchor-outbox.jsonl"
        )

        self.anchor = SecurityCheckpointAnchor(
            repository_id="jainulabedinshawon/JAS-SI",
            event_count=25,
            last_hash="a" * 64,
        )

        self.provider = FakeRecoverableProvider()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_new_anchor_is_published_verified_and_persisted(self):
        receipt = publish_anchor_crash_safely(
            self.provider,
            self.outbox,
            self.anchor,
        )

        entry = self.outbox.get(self.anchor.digest)

        self.assertEqual(receipt.anchor_digest, self.anchor.digest)
        self.assertEqual(entry.status, "VERIFIED")
        self.assertEqual(entry.receipt, receipt)
        self.assertEqual(self.provider.lookup_calls, 1)
        self.assertEqual(self.provider.publish_calls, 1)
        self.assertEqual(self.provider.verify_calls, 1)

    def test_existing_provider_record_is_recovered_without_publish(self):
        receipt = self.provider.publish_idempotent(
            self.anchor,
            self.anchor.digest,
        )
        self.provider.publish_calls = 0

        result = publish_anchor_crash_safely(
            self.provider,
            self.outbox,
            self.anchor,
        )

        self.assertEqual(result, receipt)
        self.assertEqual(self.provider.lookup_calls, 1)
        self.assertEqual(self.provider.publish_calls, 0)
        self.assertEqual(
            self.outbox.get(self.anchor.digest).status,
            "VERIFIED",
        )

    def test_pending_outbox_is_recovered_after_restart(self):
        self.outbox.prepare(self.anchor)

        receipt = self.provider.publish_idempotent(
            self.anchor,
            self.anchor.digest,
        )
        self.provider.publish_calls = 0

        restarted_outbox = TrustedAnchorOutbox(
            self.outbox.path
        )

        result = publish_anchor_crash_safely(
            self.provider,
            restarted_outbox,
            self.anchor,
        )

        self.assertEqual(result, receipt)
        self.assertEqual(self.provider.publish_calls, 0)
        self.assertEqual(
            restarted_outbox.get(self.anchor.digest).status,
            "VERIFIED",
        )

    def test_already_verified_receipt_is_verified_again(self):
        receipt = self.provider.publish_idempotent(
            self.anchor,
            self.anchor.digest,
        )

        self.outbox.prepare(self.anchor)
        self.outbox.mark_verified(self.anchor, receipt)

        self.provider.verify_calls = 0
        self.provider.lookup_calls = 0
        self.provider.publish_calls = 0

        result = publish_anchor_crash_safely(
            self.provider,
            self.outbox,
            self.anchor,
        )

        self.assertEqual(result, receipt)
        self.assertEqual(self.provider.verify_calls, 1)
        self.assertEqual(self.provider.lookup_calls, 0)
        self.assertEqual(self.provider.publish_calls, 0)

    def test_lookup_failure_fails_closed_without_publication(self):
        self.provider.lookup_error = True

        with self.assertRaises(TrustedAnchorCrashSafeWorkflowError):
            publish_anchor_crash_safely(
                self.provider,
                self.outbox,
                self.anchor,
            )

        self.assertEqual(self.provider.publish_calls, 0)
        self.assertEqual(
            self.outbox.get(self.anchor.digest).status,
            "PENDING",
        )

    def test_failed_verification_leaves_pending_state(self):
        self.provider.verify_result = False

        with self.assertRaises(TrustedAnchorCrashSafeWorkflowError):
            publish_anchor_crash_safely(
                self.provider,
                self.outbox,
                self.anchor,
            )

        self.assertEqual(
            self.outbox.get(self.anchor.digest).status,
            "PENDING",
        )

    def test_publish_failure_leaves_pending_state(self):
        self.provider.publish_error = True

        with self.assertRaises(TrustedAnchorCrashSafeWorkflowError):
            publish_anchor_crash_safely(
                self.provider,
                self.outbox,
                self.anchor,
            )

        self.assertEqual(
            self.outbox.get(self.anchor.digest).status,
            "PENDING",
        )

    def test_wrong_receipt_digest_fails_closed(self):
        wrong_receipt = create_signed_receipt(
            provider_id="crash-safe-test-provider",
            anchor_digest="b" * 64,
            external_reference="wrong-record",
            observed_at="2026-10-30T00:00:00Z",
            secret=SECRET,
        )

        self.provider.records[self.anchor.digest] = wrong_receipt

        with self.assertRaises(TrustedAnchorCrashSafeWorkflowError):
            publish_anchor_crash_safely(
                self.provider,
                self.outbox,
                self.anchor,
            )

        self.assertEqual(self.provider.publish_calls, 0)
        self.assertEqual(
            self.outbox.get(self.anchor.digest).status,
            "PENDING",
        )

    def test_invalid_anchor_is_rejected(self):
        with self.assertRaises(TrustedAnchorCrashSafeWorkflowError):
            publish_anchor_crash_safely(
                self.provider,
                self.outbox,
                object(),
            )

    def test_non_recoverable_provider_is_rejected(self):
        class IncompleteProvider:
            pass

        with self.assertRaises(TrustedAnchorCrashSafeWorkflowError):
            publish_anchor_crash_safely(
                IncompleteProvider(),
                self.outbox,
                self.anchor,
            )

    def test_outbox_persistence_failure_prevents_provider_calls(self):
        class BrokenOutbox:
            def prepare(self, anchor):
                raise RuntimeError("simulated disk failure")

            def get(self, anchor_digest):
                return None

            def mark_verified(self, anchor, receipt):
                raise AssertionError("must not be called")

        with self.assertRaises(TrustedAnchorCrashSafeWorkflowError):
            publish_anchor_crash_safely(
                self.provider,
                BrokenOutbox(),
                self.anchor,
            )

        self.assertEqual(self.provider.lookup_calls, 0)
        self.assertEqual(self.provider.publish_calls, 0)


if __name__ == "__main__":
    unittest.main()
