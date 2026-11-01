
from __future__ import annotations

import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.security_checkpoint_anchor import (
    SecurityCheckpointAnchor,
)
from jas_si_agent.trusted_anchor_hmac import (
    create_signed_receipt,
)
from jas_si_agent.trusted_anchor_provider import (
    TrustedAnchorReceipt,
)

from tests.contracts.trusted_anchor_api_conformance import (
    TrustedAnchorProviderConformance,
)


SECRET = b"jas-si-conformance-secret-minimum-32-bytes"


class FakeConformanceBackend:

    def __init__(self):
        self.records = {}
        self.publish_calls = 0
        self._lock = threading.Lock()

    def publish_idempotent(
        self,
        anchor,
        idempotency_key,
    ) -> TrustedAnchorReceipt:
        if idempotency_key != anchor.digest:
            raise ValueError("Idempotency key mismatch")

        with self._lock:
            self.publish_calls += 1

            existing = self.records.get(idempotency_key)

            if existing is not None:
                return existing

            receipt = create_signed_receipt(
                provider_id="conformance-test-provider",
                anchor_digest=anchor.digest,
                external_reference=(
                    "conformance-" + anchor.digest[:12]
                ),
                observed_at="2026-11-01T12:00:00Z",
                secret=SECRET,
            )

            self.records[idempotency_key] = receipt
            return receipt

    def lookup_by_idempotency_key(
        self,
        idempotency_key,
    ):
        with self._lock:
            return self.records.get(idempotency_key)


class TestTrustedAnchorApiConformance(unittest.TestCase):

    def setUp(self):
        self.anchor = SecurityCheckpointAnchor(
            repository_id="jas-si",
            event_count=40,
            last_hash="f" * 64,
        )

        self.conflicting_anchor = SecurityCheckpointAnchor(
            repository_id="jas-si",
            event_count=41,
            last_hash="e" * 64,
        )

        self.backend = FakeConformanceBackend()

        self.suite = TrustedAnchorProviderConformance(
            self.backend,
        )

    def test_all_conformance_checks_pass(self):
        results = self.suite.run(
            self.anchor,
            missing_key="a" * 64,
            conflicting_anchor=self.conflicting_anchor,
        )

        self.assertEqual(len(results), 5)

        for result in results:
            with self.subTest(check=result.name):
                self.assertTrue(
                    result.passed,
                    result.detail,
                )

    def test_replay_does_not_create_duplicate_record(self):
        result = self.suite.check_idempotent_replay(
            self.anchor,
        )

        self.assertTrue(result.passed)
        self.assertEqual(len(self.backend.records), 1)
        self.assertEqual(self.backend.publish_calls, 2)

    def test_concurrent_replay_returns_same_receipt(self):
        workers = 8

        result = self.suite.check_concurrent_replay(
            self.anchor,
            workers=workers,
        )

        self.assertTrue(result.passed, result.detail)

        self.assertEqual(
            len(self.backend.records),
            1,
        )

        self.assertEqual(
            self.backend.publish_calls,
            workers,
        )

        receipt = self.backend.lookup_by_idempotency_key(
            self.anchor.digest,
        )

        self.assertIsNotNone(receipt)
        self.assertEqual(
            receipt.anchor_digest,
            self.anchor.digest,
        )

    def test_concurrent_replay_rejects_invalid_worker_count(self):
        result = self.suite.check_concurrent_replay(
            self.anchor,
            workers=1,
        )

        self.assertFalse(result.passed)
        self.assertEqual(result.detail, "ValueError")

    def test_idempotency_key_conflict_is_rejected(self):
        result = self.suite.check_idempotency_key_conflict(
            self.anchor,
            self.conflicting_anchor,
        )

        self.assertTrue(result.passed, result.detail)

        self.assertEqual(
            len(self.backend.records),
            1,
        )

        original = self.backend.lookup_by_idempotency_key(
            self.anchor.digest,
        )

        self.assertIsNotNone(original)
        self.assertEqual(
            original.anchor_digest,
            self.anchor.digest,
        )

        self.assertIsNone(
            self.backend.lookup_by_idempotency_key(
                self.conflicting_anchor.digest,
            )
        )

    def test_missing_lookup_returns_none(self):
        result = self.suite.check_missing_lookup(
            "b" * 64,
        )

        self.assertTrue(result.passed)
        self.assertEqual(len(self.backend.records), 0)


if __name__ == "__main__":
    unittest.main()
