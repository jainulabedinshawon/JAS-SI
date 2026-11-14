from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.verification import (  # noqa: E402
    ActionReport,
    EvidenceConsistencyStatus,
    VerificationEvidence,
    VerificationStatus,
    compare_report_to_evidence,
    verify_report,
)


class TestIndependentVerification(unittest.TestCase):
    def report(self, claimed_success: bool = True) -> ActionReport:
        return ActionReport(action_id="action-001", claimed_success=claimed_success)

    def evidence(
        self,
        observed_state: str = "success",
        *,
        action_id: str = "action-001",
        evidence_ref: str = "test-evidence-001",
    ) -> VerificationEvidence:
        return VerificationEvidence(
            action_id=action_id,
            observed_state=observed_state,
            evidence_ref=evidence_ref,
        )

    def test_submitted_matching_success_is_not_verified(self) -> None:
        result = verify_report(self.report(), self.evidence("success"))
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "EVIDENCE_PROVENANCE_UNVERIFIED")
        self.assertEqual(
            result.evidence_consistency,
            EvidenceConsistencyStatus.MATCHED_SUCCESS,
        )

    def test_submitted_failure_detects_false_success_candidate(self) -> None:
        result = verify_report(self.report(True), self.evidence("failure"))
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "EVIDENCE_PROVENANCE_UNVERIFIED")
        self.assertEqual(
            result.evidence_consistency,
            EvidenceConsistencyStatus.FALSE_SUCCESS_CANDIDATE,
        )

    def test_submitted_success_contradicts_reported_failure(self) -> None:
        comparison = compare_report_to_evidence(
            self.report(False), self.evidence("success")
        )
        self.assertEqual(
            comparison.status,
            EvidenceConsistencyStatus.CONTRADICTED_REPORT,
        )

    def test_matching_failure_is_only_a_consistency_result(self) -> None:
        result = verify_report(self.report(False), self.evidence("failure"))
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(
            result.evidence_consistency,
            EvidenceConsistencyStatus.MATCHED_FAILURE,
        )

    def test_missing_evidence_is_inconclusive(self) -> None:
        result = verify_report(self.report(), None)
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "EVIDENCE_MISSING")

    def test_mismatched_action_id_is_inconclusive(self) -> None:
        result = verify_report(
            self.report(), self.evidence(action_id="different-action")
        )
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "EVIDENCE_ACTION_ID_MISMATCH")

    def test_missing_evidence_reference_is_inconclusive(self) -> None:
        result = verify_report(self.report(), self.evidence(evidence_ref=" "))
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "EVIDENCE_REFERENCE_MISSING")

    def test_unknown_observed_state_is_inconclusive(self) -> None:
        result = verify_report(self.report(), self.evidence("unknown"))
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "UNKNOWN_OBSERVED_STATE")

    def test_none_report_is_inconclusive(self) -> None:
        result = verify_report(None, None)  # type: ignore[arg-type]
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "INVALID_ACTION_REPORT")
        self.assertEqual(result.action_id, "")

    def test_wrong_report_type_is_inconclusive(self) -> None:
        result = verify_report({"action_id": "action-001"}, None)  # type: ignore[arg-type]
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "INVALID_ACTION_REPORT")


if __name__ == "__main__":
    unittest.main()
