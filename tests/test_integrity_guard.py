
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
from jas_si_agent.authorization import (
    ActionRequest,
    AuthorizationDecision,
)
from jas_si_agent.checkpoint_store import JsonCheckpointStore
from jas_si_agent.integrity_guard import verify_startup_integrity
from jas_si_agent.verification import (
    VerificationResult,
    VerificationStatus,
)


class TestIntegrityGuard(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        root = Path(self.temp_dir.name)
        self.audit = JsonlAuditStore(
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
        self.audit.append(record)
        return record

    def test_valid_current_checkpoint_passes(self) -> None:
        self.append_record()
        records = self.audit.load_records()
        self.checkpoints.create_and_save(records)

        result = verify_startup_integrity(
            self.audit,
            self.checkpoints,
        )

        self.assertTrue(result.valid)
        self.assertEqual(
            result.reason,
            "AUDIT_LOG_AND_CHECKPOINT_VERIFIED",
        )
        self.assertEqual(result.record_count, 1)

    def test_missing_checkpoint_fails_closed(self) -> None:
        self.append_record()

        result = verify_startup_integrity(
            self.audit,
            self.checkpoints,
        )

        self.assertFalse(result.valid)
        self.assertEqual(
            result.reason,
            "CHECKPOINT_MISSING_OR_INVALID",
        )

    def test_stale_checkpoint_fails_closed(self) -> None:
        self.append_record()
        self.checkpoints.create_and_save(
            self.audit.load_records()
        )

        self.append_record()

        result = verify_startup_integrity(
            self.audit,
            self.checkpoints,
        )

        self.assertFalse(result.valid)
        self.assertEqual(
            result.reason,
            "CHECKPOINT_NOT_AT_CURRENT_LOG_HEAD",
        )

    def test_rollback_fails_closed(self) -> None:
        self.append_record()
        self.append_record()

        original_records = self.audit.load_records()
        self.checkpoints.create_and_save(original_records)

        first_line = self.audit.path.read_text(
            encoding="utf-8"
        ).splitlines()[0]
        self.audit.path.write_text(
            first_line + "\n",
            encoding="utf-8",
        )

        result = verify_startup_integrity(
            self.audit,
            self.checkpoints,
        )

        self.assertFalse(result.valid)

    def test_empty_log_requires_genesis_checkpoint(self) -> None:
        self.checkpoints.create_and_save(())

        result = verify_startup_integrity(
            self.audit,
            self.checkpoints,
        )

        self.assertTrue(result.valid)
        self.assertEqual(result.record_count, 0)


if __name__ == "__main__":
    unittest.main()
