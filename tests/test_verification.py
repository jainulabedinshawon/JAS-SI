
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
    VerificationEvidence,
    VerificationStatus,
    verify_report,
)


class TestIndependentVerification(unittest.TestCase):
    def report(self, claimed_success: bool = True) -> ActionReport:
        return ActionReport(
            action_id="action-001",
            claimed_success=claimed_success,
        )

    def evidence(
        self,
        observed_state: str = "success",
        *,
        action_id: str = "action-001",
        evidence_ref: str = "test-evidence-001",
        independent: bool = True,
    ) -> VerificationEvidence:
        return VerificationEvidence(
            action_id=action_id,
            observed_state=observed_state,
            evidence_ref=evidence_ref,
            collected_independently=independent,
        )

    def test_matching_success_is_verified(self) -> None:
        result = verify_report(
            self.report(True),
            self.evidence("success"),
        )
        self.assertEqual(
            result.status,
            VerificationStatus.VERIFIED_SUCCESS,
        )

    def test_claimed_success_with_failure_evidence_is_false_success(
        self,
    ) -> None:
        result = verify_report(
            self.report(True),
            self.evidence("failure"),
        )
        self.assertEqual(
            result.status,
            VerificationStatus.FALSE_SUCCESS,
        )

    def test_reported_failure_with_success_evidence_is_contradicted(
        self,
    ) -> None:
        result = verify_report(
            self.report(False),
            self.evidence("success"),
        )
        self.assertEqual(
            result.status,
            VerificationStatus.CONTRADICTED_REPORT,
        )

    def test_matching_failure_is_verified(self) -> None:
        result = verify_report(
            self.report(False),
            self.evidence("failure"),
        )
        self.assertEqual(
            result.status,
            VerificationStatus.VERIFIED_FAILURE,
        )

    def test_missing_evidence_is_inconclusive(self) -> None:
        result = verify_report(self.report(), None)
        self.assertEqual(
            result.status,
            VerificationStatus.INCONCLUSIVE,
        )
        self.assertEqual(result.reason, "EVIDENCE_MISSING")

    def test_mismatched_action_id_is_inconclusive(self) -> None:
        result = verify_report(
            self.report(),
            self.evidence(action_id="different-action"),
        )
        self.assertEqual(
            result.status,
            VerificationStatus.INCONCLUSIVE,
        )
        self.assertEqual(
            result.reason,
            "EVIDENCE_ACTION_ID_MISMATCH",
        )

    def test_non_independent_evidence_is_inconclusive(self) -> None:
        result = verify_report(
            self.report(),
            self.evidence(independent=False),
        )
        self.assertEqual(
            result.status,
            VerificationStatus.INCONCLUSIVE,
        )
        self.assertEqual(
            result.reason,
            "INDEPENDENCE_NOT_ESTABLISHED",
        )

    def test_missing_evidence_reference_is_inconclusive(self) -> None:
        result = verify_report(
            self.report(),
            self.evidence(evidence_ref=" "),
        )
        self.assertEqual(
            result.status,
            VerificationStatus.INCONCLUSIVE,
        )
        self.assertEqual(
            result.reason,
            "EVIDENCE_REFERENCE_MISSING",
        )

    def test_unknown_observed_state_is_inconclusive(self) -> None:
        result = verify_report(
            self.report(),
            self.evidence("unknown"),
        )
        self.assertEqual(
            result.status,
            VerificationStatus.INCONCLUSIVE,
        )
        self.assertEqual(
            result.reason,
            "UNKNOWN_OBSERVED_STATE",
        )


if __name__ == "__main__":
    unittest.main()
