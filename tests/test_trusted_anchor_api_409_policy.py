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
from jas_si_agent.trusted_anchor_api_recovery import (
    TrustedAnchorApiRequestInProgressError,
    TrustedAnchorApiIdempotencyConflictError,
    TrustedAnchorApiRecoveryError,
)
from jas_si_agent.trusted_anchor_api_409_policy import (
    recover_anchor_with_409_policy,
)


class FakeProvider:

    def __init__(self, lookup_results=None, publish_error=None):
        self.lookup_results = list(lookup_results or [])
        self.publish_error = publish_error
        self.lookup_calls = 0
        self.publish_calls = 0

        self.anchor = SecurityCheckpointAnchor(
            repository_id="jas-si",
            event_count=5,
            last_hash="a" * 64,
        )

    def lookup_by_idempotency_key(self, key):
        self.lookup_calls += 1

        if self.lookup_results:
            return self.lookup_results.pop(0)

        return None

    def publish_idempotent(self, anchor, idempotency_key):
        self.publish_calls += 1

        if self.publish_error is not None:
            raise self.publish_error

        raise AssertionError("Unexpected publication")

    def verify(self, anchor, receipt):
        return receipt.anchor_digest == anchor.digest


class TestTrustedAnchorApi409Policy(unittest.TestCase):

    def setUp(self):
        self.anchor = SecurityCheckpointAnchor(
            repository_id="jas-si",
            event_count=5,
            last_hash="a" * 64,
        )

    def make_receipt(self):
        return TrustedAnchorReceipt(
            provider_id="test-provider",
            anchor_digest=self.anchor.digest,
            external_reference="external-123",
            observed_at="2026-11-02T00:00:00Z",
            proof="test-proof",
        )

    def test_409_recovers_receipt_without_republishing(self):
        receipt = self.make_receipt()

        provider = FakeProvider(
            lookup_results=[None, receipt],
            publish_error=TrustedAnchorApiRequestInProgressError(
                "Request is still processing"
            ),
        )

        recovered = recover_anchor_with_409_policy(
            provider,
            self.anchor,
            max_lookup_attempts=3,
        )

        self.assertEqual(recovered, receipt)
        self.assertEqual(provider.publish_calls, 1)
        self.assertEqual(provider.lookup_calls, 2)  # সংশোধিত মান: ৩ এর পরিবর্তে ২

    def test_409_still_processing_stops_after_bound(self):
        provider = FakeProvider(
            lookup_results=[None, None, None],
            publish_error=TrustedAnchorApiRequestInProgressError(
                "Request is still processing"
            ),
        )

        with self.assertRaises(
            TrustedAnchorApiRequestInProgressError
        ):
            recover_anchor_with_409_policy(
                provider,
                self.anchor,
                max_lookup_attempts=3,
            )

        self.assertEqual(provider.publish_calls, 1)
        self.assertEqual(provider.lookup_calls, 4)

    def test_422_is_not_retried(self):
        provider = FakeProvider(
            publish_error=TrustedAnchorApiIdempotencyConflictError(
                "Idempotency conflict"
            )
        )

        with self.assertRaises(
            TrustedAnchorApiIdempotencyConflictError
        ):
            recover_anchor_with_409_policy(
                provider,
                self.anchor,
            )

        self.assertEqual(provider.publish_calls, 1)
        self.assertEqual(provider.lookup_calls, 1)

    def test_invalid_retry_bound_is_rejected(self):
        provider = FakeProvider()

        for invalid in (0, 6, -1, True, 1.5):
            with self.subTest(invalid=invalid):
                with self.assertRaises(TrustedAnchorApiRecoveryError):
                    recover_anchor_with_409_policy(
                        provider,
                        self.anchor,
                        max_lookup_attempts=invalid,
                    )

        self.assertEqual(provider.lookup_calls, 0)
        self.assertEqual(provider.publish_calls, 0)


if __name__ == "__main__":
    unittest.main()
