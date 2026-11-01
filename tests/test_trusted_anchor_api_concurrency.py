
from __future__ import annotations

import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.security_checkpoint_anchor import (
    SecurityCheckpointAnchor,
)
from jas_si_agent.trusted_anchor_api_provider import (
    HmacReceiptVerifier,
)
from jas_si_agent.trusted_anchor_api_recovery import (
    RecoverableApiTrustedAnchorProvider,
)
from jas_si_agent.trusted_anchor_hmac import (
    create_signed_receipt,
)
from jas_si_agent.trusted_anchor_provider import (
    TrustedAnchorReceipt,
)
from jas_si_agent.trusted_anchor_recovery import (
    recover_or_publish_anchor,
)


SECRET = b"jas-si-concurrency-test-secret-minimum-32-bytes"
WORKER_COUNT = 12


class AtomicConcurrentBackend:
    """Thread-safe test backend modeling provider-side atomic idempotency.

    This is a test double, not evidence of a real provider's behavior.
    """

    def __init__(self, lookup_barrier: threading.Barrier):
        self.lookup_barrier = lookup_barrier
        self.lock = threading.Lock()

        self.records: dict[str, TrustedAnchorReceipt] = {}
        self.publish_calls = 0
        self.lookup_calls = 0

    def lookup_by_idempotency_key(
        self,
        idempotency_key: str,
    ) -> TrustedAnchorReceipt | None:
        with self.lock:
            self.lookup_calls += 1
            existing = self.records.get(idempotency_key)

        # Force all workers to complete their initial lookup
        # before any worker proceeds to publication.
        self.lookup_barrier.wait(timeout=10)

        return existing

    def publish_idempotent(
        self,
        anchor: SecurityCheckpointAnchor,
        idempotency_key: str,
    ) -> TrustedAnchorReceipt:
        if idempotency_key != anchor.digest:
            raise ValueError("Idempotency key does not match anchor")

        with self.lock:
            self.publish_calls += 1

            existing = self.records.get(idempotency_key)

            if existing is not None:
                if existing.anchor_digest != anchor.digest:
                    raise ValueError(
                        "Idempotency key reused for a different anchor"
                    )

                return existing

            receipt = create_signed_receipt(
                provider_id="concurrent-test-provider",
                anchor_digest=anchor.digest,
                external_reference=(
                    "external-" + anchor.digest[:16]
                ),
                observed_at="2026-11-01T12:00:00Z",
                secret=SECRET,
            )

            # Atomic first-write-wins operation.
            self.records[idempotency_key] = receipt

            return receipt


class TestTrustedAnchorApiConcurrency(unittest.TestCase):

    def setUp(self):
        self.anchor = SecurityCheckpointAnchor(
            repository_id="jas-si",
            event_count=25,
            last_hash="d" * 64,
        )

        self.barrier = threading.Barrier(WORKER_COUNT)

        self.backend = AtomicConcurrentBackend(
            self.barrier
        )

        self.provider = RecoverableApiTrustedAnchorProvider(
            self.backend,
            HmacReceiptVerifier(SECRET),
            expected_provider_id="concurrent-test-provider",
        )

    def test_concurrent_recovery_creates_one_logical_publication(self):
        with ThreadPoolExecutor(
            max_workers=WORKER_COUNT
        ) as executor:

            futures = [
                executor.submit(
                    recover_or_publish_anchor,
                    self.provider,
                    self.anchor,
                )
                for _ in range(WORKER_COUNT)
            ]

            receipts = [
                future.result(timeout=20)
                for future in futures
            ]

        self.assertEqual(len(receipts), WORKER_COUNT)

        first_receipt = receipts[0]

        for receipt in receipts:
            self.assertEqual(receipt, first_receipt)
            self.assertEqual(
                receipt.anchor_digest,
                self.anchor.digest,
            )
            self.assertTrue(
                self.provider.verify(self.anchor, receipt)
            )

        self.assertEqual(
            self.backend.lookup_calls,
            WORKER_COUNT,
        )

        # Every worker attempted publication after the synchronized
        # initial lookup returned no record.
        self.assertEqual(
            self.backend.publish_calls,
            WORKER_COUNT,
        )

        # But atomic provider-side idempotency retained one record.
        self.assertEqual(
            len(self.backend.records),
            1,
        )

        self.assertIn(
            self.anchor.digest,
            self.backend.records,
        )

    def test_concurrent_retries_return_same_receipt(self):
        first = recover_or_publish_anchor(
            self.provider,
            self.anchor,
        )

        # A fresh barrier is not needed because the initial record
        # already exists. Use a separate executor for concurrent lookups.
        with ThreadPoolExecutor(
            max_workers=WORKER_COUNT
        ) as executor:

            futures = [
                executor.submit(
                    self.provider.lookup_by_idempotency_key,
                    self.anchor.digest,
                )
                for _ in range(WORKER_COUNT)
            ]

            receipts = [
                future.result(timeout=20)
                for future in futures
            ]

        for receipt in receipts:
            self.assertEqual(receipt, first)

        self.assertEqual(len(self.backend.records), 1)
        self.assertEqual(self.backend.publish_calls, 1)


if __name__ == "__main__":
    unittest.main()
