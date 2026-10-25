
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.audit_log import (  # noqa: E402
    AuditCheckpoint,
    AuditLog,
    GENESIS_HASH,
)
from jas_si_agent.authorization import (  # noqa: E402
    ActionRequest,
    AuthorizationDecision,
)
from jas_si_agent.verification import (  # noqa: E402
    VerificationResult,
    VerificationStatus,
)


class TestAuditCheckpoint(unittest.TestCase):
    def setUp(self) -> None:
        self.log = AuditLog()

    def append_record(self, action_id: str) -> None:
        request = ActionRequest(
            action_id=action_id,
            action_type="read_repository",
            resource="README.md",
        )
        decision = AuthorizationDecision(
            allowed=True,
            reason="SAFE_ACTION_POLICY_ALLOWED",
            action_id=action_id,
        )
        verification = VerificationResult(
            status=VerificationStatus.VERIFIED_SUCCESS,
            reason="TEST_FIXTURE_ONLY",
            action_id=action_id,
        )
        self.log.append(request, decision, verification)

    def test_empty_log_checkpoint_uses_genesis(self) -> None:
        checkpoint = self.log.create_checkpoint()

        self.assertEqual(checkpoint.sequence, 0)
        self.assertEqual(checkpoint.record_hash, GENESIS_HASH)
        self.assertTrue(self.log.verify_integrity(checkpoint))

    def test_checkpoint_accepts_unchanged_history(self) -> None:
        self.append_record("action-1")
        checkpoint = self.log.create_checkpoint()

        self.append_record("action-2")

        self.assertTrue(self.log.verify_integrity(checkpoint))

    def test_checkpoint_detects_truncation_before_checkpoint(self) -> None:
        self.append_record("action-1")
        self.append_record("action-2")
        checkpoint = self.log.create_checkpoint()

        self.log._records.pop()

        self.assertFalse(self.log.verify_integrity(checkpoint))

    def test_checkpoint_detects_modified_checkpointed_record(self) -> None:
        from dataclasses import replace

        self.append_record("action-1")
        checkpoint = self.log.create_checkpoint()

        self.log._records[0] = replace(
            self.log._records[0],
            authorization_reason="ALTERED",
        )

        self.assertFalse(self.log.verify_integrity(checkpoint))

    def test_checkpoint_beyond_log_length_is_rejected(self) -> None:
        self.append_record("action-1")
        checkpoint = self.log.create_checkpoint()

        future_checkpoint = AuditCheckpoint(
            sequence=checkpoint.sequence + 1,
            record_hash=checkpoint.record_hash,
        )

        self.assertFalse(self.log.verify_integrity(future_checkpoint))

    def test_invalid_checkpoint_is_rejected(self) -> None:
        self.append_record("action-1")

        self.assertFalse(
            self.log.verify_integrity(
                AuditCheckpoint(sequence=-1, record_hash="invalid")
            )
        )

    def test_wrong_genesis_checkpoint_is_rejected(self) -> None:
        self.assertFalse(
            self.log.verify_integrity(
                AuditCheckpoint(sequence=0, record_hash="f" * 64)
            )
        )


if __name__ == "__main__":
    unittest.main()
