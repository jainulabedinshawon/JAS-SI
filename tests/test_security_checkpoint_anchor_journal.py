from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jas_si_agent.security_checkpoint_anchor import (
    SecurityCheckpointAnchor,
)
from jas_si_agent.security_checkpoint_anchor_journal import (
    SecurityCheckpointAnchorJournal,
    SecurityCheckpointAnchorJournalError,
)


class TestSecurityCheckpointAnchorJournal(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.path = Path(self.temp_dir.name) / "anchors.jsonl"
        self.journal = SecurityCheckpointAnchorJournal(self.path)

        self.first = SecurityCheckpointAnchor(
            repository_id="JAS-SI",
            event_count=3,
            last_hash="a" * 64,
        )

        self.second = SecurityCheckpointAnchor(
            repository_id="JAS-SI",
            event_count=5,
            last_hash="b" * 64,
            previous_anchor_digest=self.first.digest,
        )

    def test_append_and_reload_sequence(self) -> None:
        self.journal.append(self.first)
        self.journal.append(self.second)

        restored = self.journal.load()
        self.assertEqual(restored, (self.first, self.second))

    def test_rejects_wrong_predecessor(self) -> None:
        self.journal.append(self.first)

        invalid = SecurityCheckpointAnchor(
            repository_id="JAS-SI",
            event_count=5,
            last_hash="b" * 64,
            previous_anchor_digest="c" * 64,
        )

        with self.assertRaises(SecurityCheckpointAnchorJournalError):
            self.journal.append(invalid)

        self.assertEqual(self.journal.load(), (self.first,))

    def test_rejects_different_repository(self) -> None:
        self.journal.append(self.first)

        invalid = SecurityCheckpointAnchor(
            repository_id="OTHER-REPO",
            event_count=5,
            last_hash="b" * 64,
            previous_anchor_digest=self.first.digest,
        )

        with self.assertRaises(SecurityCheckpointAnchorJournalError):
            self.journal.append(invalid)

    def test_detects_modified_journal_record(self) -> None:
        self.journal.append(self.first)
        self.path.write_text(
            self.path.read_text(encoding="utf-8").replace(
                '"event_count":3',
                '"event_count":9',
            ),
            encoding="utf-8",
        )

        with self.assertRaises(SecurityCheckpointAnchorJournalError):
            self.journal.load()

    def test_rejects_incomplete_final_record(self) -> None:
        self.path.write_text(
            self.first.to_json(),
            encoding="utf-8",
        )

        with self.assertRaises(SecurityCheckpointAnchorJournalError):
            self.journal.load()

    def test_rejects_symlink_journal(self) -> None:
        target = Path(self.temp_dir.name) / "target.jsonl"
        target.write_text("", encoding="utf-8")

        link = Path(self.temp_dir.name) / "link.jsonl"
        link.symlink_to(target)

        linked_journal = SecurityCheckpointAnchorJournal(link)

        with self.assertRaises(SecurityCheckpointAnchorJournalError):
            linked_journal.load()

    def test_rejects_oversized_journal(self) -> None:
        self.path.write_bytes(b"x" * 33)

        with patch.object(
            SecurityCheckpointAnchorJournal,
            "MAX_JOURNAL_BYTES",
            32,
        ):
            with self.assertRaisesRegex(
                SecurityCheckpointAnchorJournalError,
                "maximum allowed size",
            ):
                self.journal.load()

    def test_accepts_journal_at_size_limit(self) -> None:
        self.journal.append(self.first)
        payload = self.path.read_bytes()

        self.journal.MAX_JOURNAL_BYTES = len(payload)

        self.assertEqual(self.journal.load(), (self.first,))


if __name__ == "__main__":
    unittest.main()
