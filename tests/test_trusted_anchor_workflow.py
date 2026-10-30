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
from jas_si_agent.security_checkpoint_anchor_journal import (
    SecurityCheckpointAnchorJournal,
)
from jas_si_agent.trusted_anchor_hmac import create_signed_receipt
from jas_si_agent.trusted_anchor_provider import (
    TrustedAnchorReceipt,
)
from jas_si_agent.trusted_anchor_workflow import (
    TrustedAnchorWorkflowError,
    publish_verify_and_persist_anchor,
)


SECRET = b"jas-si-workflow-test-secret-at-least-32-bytes"


class FakeProvider:
    """Test double only; not a real external anchor service."""

    def __init__(self, verification_result: bool = True) -> None:
        self.verification_result = verification_result
        self.publish_calls = 0

    def publish(
        self,
        anchor: SecurityCheckpointAnchor,
    ) -> TrustedAnchorReceipt:
        self.publish_calls += 1

        return create_signed_receipt(
            provider_id="test-provider",
            anchor_digest=anchor.digest,
            external_reference="workflow-record-001",
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


class TestTrustedAnchorWorkflow(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.journal_path = (
            Path(self.temp_dir.name) / "anchors.jsonl"
        )
        self.journal = SecurityCheckpointAnchorJournal(
            self.journal_path
        )

        self.anchor = SecurityCheckpointAnchor(
            repository_id="JAS-SI",
            event_count=3,
            last_hash="a" * 64,
        )

    def test_verified_anchor_is_persisted(self) -> None:
        provider = FakeProvider()

        receipt = publish_verify_and_persist_anchor(
            provider,
            self.journal,
            self.anchor,
        )

        self.assertEqual(
            receipt.anchor_digest,
            self.anchor.digest,
        )
        self.assertEqual(
            self.journal.load(),
            (self.anchor,),
        )

    def test_failed_verification_does_not_persist_anchor(self) -> None:
        provider = FakeProvider(
            verification_result=False,
        )

        with self.assertRaisesRegex(
            TrustedAnchorWorkflowError,
            "publication or verification failed",
        ):
            publish_verify_and_persist_anchor(
                provider,
                self.journal,
                self.anchor,
            )

        self.assertEqual(self.journal.load(), ())

    def test_invalid_provider_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            TrustedAnchorWorkflowError,
            "valid Trusted Anchor provider",
        ):
            publish_verify_and_persist_anchor(
                object(),  # type: ignore[arg-type]
                self.journal,
                self.anchor,
            )

        self.assertEqual(self.journal.load(), ())

    def test_invalid_journal_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            TrustedAnchorWorkflowError,
            "valid SecurityCheckpointAnchorJournal",
        ):
            publish_verify_and_persist_anchor(
                FakeProvider(),
                object(),  # type: ignore[arg-type]
                self.anchor,
            )

    def test_invalid_anchor_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            TrustedAnchorWorkflowError,
            "valid SecurityCheckpointAnchor",
        ):
            publish_verify_and_persist_anchor(
                FakeProvider(),
                self.journal,
                None,  # type: ignore[arg-type]
            )

        self.assertEqual(self.journal.load(), ())

    def test_invalid_journal_is_rejected_before_provider_call(self) -> None:
        provider = FakeProvider()

        invalid_journal = SecurityCheckpointAnchorJournal(
            Path(self.temp_dir.name) / "missing" / "anchors.jsonl"
        )

        invalid_journal.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        invalid_journal.path.write_text(
            self.anchor.to_json(),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            TrustedAnchorWorkflowError,
            "Unable to inspect local anchor journal before publication",
        ):
            publish_verify_and_persist_anchor(
                provider,
                invalid_journal,
                self.anchor,
            )

        # Malformed local state must block external publication.
        self.assertEqual(provider.publish_calls, 0)

    def test_duplicate_anchor_is_blocked_before_provider_call(self) -> None:
        provider = FakeProvider()

        # First call publishes, verifies, and persists the anchor.
        publish_verify_and_persist_anchor(
            provider,
            self.journal,
            self.anchor,
        )

        self.assertEqual(provider.publish_calls, 1)

        # Second call must be rejected before contacting the provider.
        with self.assertRaisesRegex(
            TrustedAnchorWorkflowError,
            "already persisted",
        ):
            publish_verify_and_persist_anchor(
                provider,
                self.journal,
                self.anchor,
            )

        self.assertEqual(provider.publish_calls, 1)
        self.assertEqual(self.journal.load(), (self.anchor,))


if __name__ == "__main__":
    unittest.main()
