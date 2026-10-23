
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.audit_log import AuditLog
from jas_si_agent.audit_store import JsonlAuditStore
from jas_si_agent.checkpoint_store import (
    CheckpointStoreError,
    JsonCheckpointStore,
)
from jas_si_agent.authorization import (
    ActionRequest,
    AuthorizationDecision,
)
from jas_si_agent.verification import (
    VerificationResult,
    VerificationStatus,
)


class TestJsonCheckpointStore(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        root = Path(self.temp_dir.name)
        self.audit_store = JsonlAuditStore(
            root / "audit" / "events.jsonl"
        )
        self.checkpoints = JsonCheckpointStore(
            root / "checkpoints" / "audit.json"
        )

        self.log = AuditLog()
        self.request = ActionRequest(
            action_id="action-001",
            action_type="read_repository",
            resource="README.md",
        )
        self.decision = AuthorizationDecision(
            allowed=True,
            reason="SAFE_ACTION_POLICY_ALLOWED",
            action_id="action-001",
        )
        self.verification = VerificationResult(
            status=VerificationStatus.VERIFIED_SUCCESS,
            reason="REPORT_MATCHES_SUCCESS_EVIDENCE",
            action_id="action-001",
        )

    def append_record(self):
        record = self.log.append(
            self.request,
            self.decision,
            self.verification,
            evidence_ref="evidence-001",
        )
        self.audit_store.append(record)
        return record

    def test_checkpoint_survives_reload(self) -> None:
        self.append_record()

        records = self.audit_store.load_records()
        saved = self.checkpoints.create_and_save(records)
        loaded = self.checkpoints.load()

        self.assertEqual(saved, loaded)
        self.assertTrue(
            self.checkpoints.verify_records(records)
        )

    def test_detects_rollback_against_saved_checkpoint(self) -> None:
        self.append_record()
        self.append_record()

        records = self.audit_store.load_records()
        self.checkpoints.create_and_save(records)

        first_line = self.audit_store.path.read_text(
            encoding="utf-8"
        ).splitlines()[0]
        self.audit_store.path.write_text(
            first_line + "\n",
            encoding="utf-8",
        )

        rolled_back = self.audit_store.load_records()

        self.assertFalse(
            self.checkpoints.verify_records(rolled_back)
        )

    def test_missing_checkpoint_fails_closed(self) -> None:
        self.append_record()
        records = self.audit_store.load_records()

        self.assertFalse(
            self.checkpoints.verify_records(records)
        )

    def test_invalid_chain_cannot_be_checkpointed(self) -> None:
        self.append_record()
        self.append_record()

        # Replace the second record's previous hash with an invalid value
        # by editing the serialized data; the audit store must reject it.
        text = self.audit_store.path.read_text(encoding="utf-8")
        self.audit_store.path.write_text(
            text.replace(
                '"previous_hash":"',
                '"previous_hash":"invalid',
                1,
            ),
            encoding="utf-8",
        )

        with self.assertRaises(ValueError):
            self.audit_store.load_records()

    def test_rejects_malformed_checkpoint_file(self) -> None:
        self.checkpoints.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        self.checkpoints.path.write_text(
            "{invalid-json}\n",
            encoding="utf-8",
        )

        with self.assertRaises(CheckpointStoreError):
            self.checkpoints.load()


if __name__ == "__main__":
    unittest.main()
