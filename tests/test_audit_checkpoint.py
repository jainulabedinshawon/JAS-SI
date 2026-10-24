
from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.audit_checkpoint import (  # noqa: E402
    AuditCheckpoint,
    CheckpointError,
    checkpoint_fingerprint,
    create_checkpoint,
    verify_checkpoint,
)
from jas_si_agent.audit_log import (  # noqa: E402
    AuditLog,
    GENESIS_HASH,
    _calculate_hash,
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
        return self.log.append(
            self.request,
            self.decision,
            self.verification,
            evidence_ref="evidence-001",
        )

    def test_empty_checkpoint_uses_genesis(self) -> None:
        checkpoint = create_checkpoint(self.log.records)

        self.assertEqual(checkpoint.sequence, 0)
        self.assertEqual(checkpoint.head_hash, GENESIS_HASH)
        self.assertTrue(
            verify_checkpoint(self.log.records, checkpoint)
        )

    def test_checkpoint_round_trip_json(self) -> None:
        self.append_record()
        checkpoint = create_checkpoint(self.log.records)

        restored = AuditCheckpoint.from_json(checkpoint.to_json())

        self.assertEqual(restored, checkpoint)
        self.assertTrue(
            verify_checkpoint(self.log.records, restored)
        )

    def test_appended_records_preserve_old_checkpoint(self) -> None:
        self.append_record()
        checkpoint = create_checkpoint(self.log.records)

        self.append_record()

        self.assertTrue(
            verify_checkpoint(self.log.records, checkpoint)
        )

    def test_truncation_before_checkpoint_is_detected(self) -> None:
        self.append_record()
        self.append_record()
        checkpoint = create_checkpoint(self.log.records)

        truncated = self.log.records[:1]

        self.assertFalse(
            verify_checkpoint(truncated, checkpoint)
        )

    def test_modified_anchored_record_is_detected(self) -> None:
        self.append_record()
        checkpoint = create_checkpoint(self.log.records)

        altered = (
            replace(
                self.log.records[0],
                authorization_reason="ALTERED",
            ),
        )

        self.assertFalse(
            verify_checkpoint(altered, checkpoint)
        )

    def test_invalid_chain_cannot_be_checkpointed(self) -> None:
        self.append_record()
        altered = (
            replace(
                self.log.records[0],
                record_hash="f" * 64,
            ),
        )

        with self.assertRaises(CheckpointError):
            create_checkpoint(altered)

    def test_rejects_extra_json_fields(self) -> None:
        with self.assertRaises(CheckpointError):
            AuditCheckpoint.from_json(
                '{"sequence":0,"head_hash":"'
                + GENESIS_HASH
                + '","extra":true}'
            )

    def test_fingerprint_is_stable(self) -> None:
        checkpoint = create_checkpoint(self.log.records)

        self.assertEqual(
            checkpoint_fingerprint(checkpoint),
            checkpoint_fingerprint(checkpoint),
        )

    def test_boolean_record_sequence_is_rejected(self) -> None:
        self.append_record()
        original = self.log.records[0]

        malformed = replace(
            original,
            sequence=True,
            record_hash="",
        )
        malformed = replace(
            malformed,
            record_hash=_calculate_hash(malformed),
        )

        with self.assertRaises(CheckpointError):
            create_checkpoint((malformed,))

    def test_malformed_record_hash_is_rejected(self) -> None:
        self.append_record()
        original = self.log.records[0]

        malformed = replace(
            original,
            record_hash="NOT_A_SHA256_HASH",
        )

        self.assertFalse(
            verify_checkpoint(
                (malformed,),
                AuditCheckpoint(
                    sequence=1,
                    head_hash=original.record_hash,
                ),
            )
        )

    def test_boolean_checkpoint_sequence_is_rejected(self) -> None:
        with self.assertRaises(CheckpointError):
            AuditCheckpoint(
                sequence=True,
                head_hash=GENESIS_HASH,
            )

    def test_negative_checkpoint_sequence_is_rejected(self) -> None:
        with self.assertRaises(CheckpointError):
            AuditCheckpoint(
                sequence=-1,
                head_hash=GENESIS_HASH,
            )

    def test_malformed_checkpoint_hash_is_rejected(self) -> None:
        with self.assertRaises(CheckpointError):
            AuditCheckpoint(
                sequence=1,
                head_hash="NOT_A_SHA256_HASH",
            )

    def test_checkpoint_with_unmatched_hash_is_rejected(self) -> None:
        self.append_record()

        checkpoint = AuditCheckpoint(
            sequence=1,
            head_hash="a" * 64,
        )

        self.assertFalse(
            verify_checkpoint(self.log.records, checkpoint)
        )

    def test_checkpoint_beyond_log_length_is_rejected(self) -> None:
        checkpoint = AuditCheckpoint(
            sequence=1,
            head_hash="a" * 64,
        )

        self.assertFalse(
            verify_checkpoint(self.log.records, checkpoint)
        )

if __name__ == "__main__":
    unittest.main()
