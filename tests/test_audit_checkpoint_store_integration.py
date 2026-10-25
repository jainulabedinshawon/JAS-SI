
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.audit_checkpoint import (
    create_checkpoint,
    verify_checkpoint,
)
from jas_si_agent.audit_log import AuditLog
from jas_si_agent.audit_store import (
    AuditStoreError,
    JsonlAuditStore,
)
from jas_si_agent.authorization import (
    ActionRequest,
    AuthorizationDecision,
)
from jas_si_agent.verification import (
    VerificationResult,
    VerificationStatus,
)


class TestAuditCheckpointStoreIntegration(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.path = Path(self.temp_dir.name) / "audit" / "events.jsonl"
        self.store = JsonlAuditStore(self.path)
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
        self.store.append(record)
        return record

    def test_persisted_records_match_checkpoint(self) -> None:
        self.append_record()
        self.append_record()

        persisted = self.store.load_records()
        checkpoint = create_checkpoint(persisted)

        self.assertTrue(verify_checkpoint(persisted, checkpoint))

    def test_checkpoint_detects_valid_chain_rollback(self) -> None:
        self.append_record()
        self.append_record()
        checkpoint = create_checkpoint(self.store.load_records())

        lines = self.path.read_text(
            encoding="utf-8"
        ).splitlines()
        self.path.write_text(lines[0] + "\n", encoding="utf-8")

        rolled_back = self.store.load_records()
        self.assertEqual(len(rolled_back), 1)
        self.assertFalse(
            verify_checkpoint(rolled_back, checkpoint)
        )

    def test_checkpoint_remains_valid_after_new_append(self) -> None:
        self.append_record()
        checkpoint = create_checkpoint(self.store.load_records())

        self.append_record()
        persisted = self.store.load_records()

        self.assertEqual(len(persisted), 2)
        self.assertTrue(verify_checkpoint(persisted, checkpoint))

    def test_tampered_persistent_log_is_rejected(self) -> None:
        self.append_record()

        content = self.path.read_text(encoding="utf-8")
        self.path.write_text(
            content.replace(
                "SAFE_ACTION_POLICY_ALLOWED",
                "ALTERED",
            ),
            encoding="utf-8",
        )

        with self.assertRaises(AuditStoreError):
            self.store.load_records()


if __name__ == "__main__":
    unittest.main()
