"""Tests for the JAS-SI audit log and tamper detection."""

from __future__ import annotations

import sys
import unittest
from dataclasses import replace
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


class TestAuditLog(unittest.TestCase):
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

    def append_one(self):
        return self.log.append(
            self.request,
            self.decision,
            self.verification,
            evidence_ref="evidence-001",
        )

    def test_first_record_uses_genesis_hash(self) -> None:
        record = self.append_one()

        self.assertEqual(record.sequence, 1)
        self.assertEqual(record.previous_hash, GENESIS_HASH)
        self.assertTrue(self.log.verify_integrity())

    def test_second_record_links_to_first(self) -> None:
        first = self.append_one()
        second = self.append_one()

        self.assertEqual(second.sequence, 2)
        self.assertEqual(second.previous_hash, first.record_hash)
        self.assertTrue(self.log.verify_integrity())

    def test_records_property_returns_tuple(self) -> None:
        self.append_one()

        self.assertIsInstance(self.log.records, tuple)
        self.assertEqual(len(self.log.records), 1)

    def test_modified_record_is_detected(self) -> None:
        original = self.append_one()

        self.log._records[0] = replace(
            original,
            authorization_reason="ALTERED",
        )

        self.assertFalse(self.log.verify_integrity())

    def test_broken_chain_link_is_detected(self) -> None:
        self.append_one()
        second = self.append_one()

        self.log._records[1] = replace(
            second,
            previous_hash=GENESIS_HASH,
        )

        self.assertFalse(self.log.verify_integrity())

    def test_mismatched_action_id_is_rejected(self) -> None:
        wrong_decision = AuthorizationDecision(
            allowed=True,
            reason="TEST",
            action_id="different-action",
        )

        with self.assertRaises(ValueError):
            self.log.append(
                self.request,
                wrong_decision,
                self.verification,
            )

        self.assertEqual(len(self.log.records), 0)

    def test_unauthorized_decision_can_be_audited(self) -> None:
        denied = AuthorizationDecision(
            allowed=False,
            reason="HUMAN_APPROVAL_REQUIRED",
            action_id="action-001",
        )

        inconclusive = VerificationResult(
            status=VerificationStatus.INCONCLUSIVE,
            reason="ACTION_NOT_AUTHORIZED",
            action_id="action-001",
        )

        record = self.log.append(
            self.request,
            denied,
            inconclusive,
        )

        self.assertFalse(record.authorized)
        self.assertEqual(
            record.verification_status,
            "INCONCLUSIVE",
        )
        self.assertTrue(self.log.verify_integrity())

    def test_boolean_record_sequence_is_rejected(self) -> None:
        original = self.append_one()

        # bool is a subclass of int in Python.
        self.log._records[0] = replace(
            original,
            sequence=True,
        )

        self.assertFalse(self.log.verify_integrity())

    def test_negative_record_sequence_is_rejected(self) -> None:
        original = self.append_one()

        self.log._records[0] = replace(
            original,
            sequence=-1,
        )

        self.assertFalse(self.log.verify_integrity())

    def test_string_record_sequence_is_rejected(self) -> None:
        original = self.append_one()

        self.log._records[0] = replace(
            original,
            sequence="1",
        )

        self.assertFalse(self.log.verify_integrity())

    def test_malformed_previous_hash_is_rejected(self) -> None:
        original = self.append_one()

        self.log._records[0] = replace(
            original,
            previous_hash="not-a-valid-sha256-hash",
        )

        self.assertFalse(self.log.verify_integrity())

    def test_non_string_previous_hash_is_rejected(self) -> None:
        original = self.append_one()

        self.log._records[0] = replace(
            original,
            previous_hash=None,
        )

        self.assertFalse(self.log.verify_integrity())

    def test_malformed_record_hash_is_rejected(self) -> None:
        original = self.append_one()

        self.log._records[0] = replace(
            original,
            record_hash="invalid-hash",
        )

        self.assertFalse(self.log.verify_integrity())

    def test_non_string_record_hash_is_rejected(self) -> None:
        original = self.append_one()

        self.log._records[0] = replace(
            original,
            record_hash=None,
        )

        self.assertFalse(self.log.verify_integrity())

    def test_uppercase_record_hash_is_rejected(self) -> None:
        original = self.append_one()

        self.log._records[0] = replace(
            original,
            record_hash=original.record_hash.upper(),
        )

        self.assertFalse(self.log.verify_integrity())

    def test_record_sequence_gap_is_detected(self) -> None:
        self.append_one()
        second = self.append_one()

        self.log._records[1] = replace(
            second,
            sequence=3,
        )

        self.assertFalse(self.log.verify_integrity())

    def test_empty_log_checkpoint_is_valid(self) -> None:
        checkpoint = self.log.create_checkpoint()

        self.assertEqual(checkpoint.sequence, 0)
        self.assertEqual(checkpoint.record_hash, GENESIS_HASH)
        self.assertTrue(self.log.verify_integrity(checkpoint))

    def test_checkpoint_remains_valid_after_appending_records(self) -> None:
        self.append_one()
        checkpoint = self.log.create_checkpoint()

        self.append_one()

        self.assertEqual(checkpoint.sequence, 1)
        self.assertTrue(self.log.verify_integrity(checkpoint))

    def test_checkpoint_detects_mismatched_hash(self) -> None:
        self.append_one()

        checkpoint = AuditCheckpoint(
            sequence=1,
            record_hash="a" * 64,
        )

        self.assertFalse(self.log.verify_integrity(checkpoint))

    def test_checkpoint_beyond_log_is_rejected(self) -> None:
        self.append_one()

        checkpoint = AuditCheckpoint(
            sequence=2,
            record_hash="b" * 64,
        )

        self.assertFalse(self.log.verify_integrity(checkpoint))

    def test_checkpoint_boolean_sequence_is_rejected(self) -> None:
        self.append_one()

        checkpoint = AuditCheckpoint(
            sequence=True,
            record_hash=self.log.records[0].record_hash,
        )

        self.assertFalse(self.log.verify_integrity(checkpoint))

    def test_checkpoint_with_invalid_hash_is_rejected(self) -> None:
        self.append_one()

        checkpoint = AuditCheckpoint(
            sequence=1,
            record_hash="invalid-hash",
        )

        self.assertFalse(self.log.verify_integrity(checkpoint))

    def test_empty_log_has_valid_integrity(self) -> None:
        self.assertEqual(self.log.records, ())
        self.assertTrue(self.log.verify_integrity())


if __name__ == "__main__":
    unittest.main()
