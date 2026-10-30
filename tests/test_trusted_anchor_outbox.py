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
from jas_si_agent.trusted_anchor_hmac import create_signed_receipt
from jas_si_agent.trusted_anchor_outbox import (
    TrustedAnchorOutbox,
    TrustedAnchorOutboxError,
)
from jas_si_agent.trusted_anchor_provider import TrustedAnchorReceipt


SECRET = b"jas-si-outbox-test-secret-at-least-32-bytes"


class TestTrustedAnchorOutbox(unittest.TestCase):

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.path = Path(self.temp_dir.name) / "outbox.jsonl"
        self.outbox = TrustedAnchorOutbox(self.path)

        self.anchor = SecurityCheckpointAnchor(
            repository_id="JAS-SI",
            event_count=8,
            last_hash="e" * 64,
        )

        self.receipt = create_signed_receipt(
            provider_id="test-outbox-provider",
            anchor_digest=self.anchor.digest,
            external_reference="outbox-record-001",
            observed_at="2026-10-30T00:00:00Z",
            secret=SECRET,
        )

    def test_prepare_persists_pending_state(self) -> None:
        entry = self.outbox.prepare(self.anchor)

        self.assertEqual(entry.status, "PENDING")
        self.assertIsNone(entry.receipt)

        stored = self.outbox.get(self.anchor.digest)

        self.assertIsNotNone(stored)
        self.assertEqual(stored.status, "PENDING")

    def test_prepare_is_idempotent(self) -> None:
        first = self.outbox.prepare(self.anchor)
        second = self.outbox.prepare(self.anchor)

        self.assertEqual(first, second)

        data = self.path.read_text(encoding="utf-8")
        self.assertEqual(len(data.splitlines()), 1)

    def test_verified_transition_is_persisted(self) -> None:
        self.outbox.prepare(self.anchor)

        entry = self.outbox.mark_verified(
            self.anchor,
            self.receipt,
        )

        self.assertEqual(entry.status, "VERIFIED")
        self.assertEqual(entry.receipt, self.receipt)

        stored = self.outbox.get(self.anchor.digest)

        self.assertEqual(stored.status, "VERIFIED")
        self.assertEqual(stored.receipt, self.receipt)

    def test_verified_state_survives_new_instance(self) -> None:
        self.outbox.prepare(self.anchor)
        self.outbox.mark_verified(
            self.anchor,
            self.receipt,
        )

        reopened = TrustedAnchorOutbox(self.path)
        stored = reopened.get(self.anchor.digest)

        self.assertIsNotNone(stored)
        self.assertEqual(stored.status, "VERIFIED")
        self.assertEqual(stored.receipt, self.receipt)

    def test_mark_verified_requires_pending_record(self) -> None:
        with self.assertRaisesRegex(
            TrustedAnchorOutboxError,
            "must be prepared",
        ):
            self.outbox.mark_verified(
                self.anchor,
                self.receipt,
            )

    def test_wrong_receipt_digest_is_rejected(self) -> None:
        wrong_anchor = SecurityCheckpointAnchor(
            repository_id="JAS-SI",
            event_count=9,
            last_hash="f" * 64,
        )

        wrong_receipt = create_signed_receipt(
            provider_id="test-outbox-provider",
            anchor_digest=wrong_anchor.digest,
            external_reference="wrong-record",
            observed_at="2026-10-30T00:00:00Z",
            secret=SECRET,
        )

        self.outbox.prepare(self.anchor)

        with self.assertRaisesRegex(
            TrustedAnchorOutboxError,
            "does not match",
        ):
            self.outbox.mark_verified(
                self.anchor,
                wrong_receipt,
            )

    def test_verified_record_cannot_be_replaced(self) -> None:
        self.outbox.prepare(self.anchor)
        self.outbox.mark_verified(
            self.anchor,
            self.receipt,
        )

        different_receipt = create_signed_receipt(
            provider_id="test-outbox-provider",
            anchor_digest=self.anchor.digest,
            external_reference="different-record",
            observed_at="2026-10-30T00:00:01Z",
            secret=SECRET,
        )

        with self.assertRaisesRegex(
            TrustedAnchorOutboxError,
            "different verified receipt",
        ):
            self.outbox.mark_verified(
                self.anchor,
                different_receipt,
            )

    def test_invalid_digest_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            TrustedAnchorOutboxError,
            "Invalid anchor digest",
        ):
            self.outbox.get("../invalid")

    def test_incomplete_record_fails_closed(self) -> None:
        self.path.write_text(
            '{"incomplete": true}',
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            TrustedAnchorOutboxError,
            "incomplete record",
        ):
            self.outbox.get(self.anchor.digest)

    def test_invalid_anchor_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            TrustedAnchorOutboxError,
            "valid SecurityCheckpointAnchor",
        ):
            self.outbox.prepare(
                None,  # type: ignore[arg-type]
            )


if __name__ == "__main__":
    unittest.main()
