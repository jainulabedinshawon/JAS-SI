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

    def test_caller_true_flag_cannot_establish_trusted_provenance(self):
        result = verify_report(self.report(), self.evidence(independent=True))
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(
            result.reason,
            "TRUSTED_EVIDENCE_PROVENANCE_UNAVAILABLE",
        )

    def test_caller_false_flag_is_also_inconclusive(self):
        result = verify_report(self.report(), self.evidence(independent=False))
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(
            result.reason,
            "TRUSTED_EVIDENCE_PROVENANCE_UNAVAILABLE",
        )

    def test_failure_claim_cannot_be_classified_from_untrusted_evidence(self):
        result = verify_report(
            self.report(True),
            self.evidence("failure", independent=True),
        )
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(
            result.reason,
            "TRUSTED_EVIDENCE_PROVENANCE_UNAVAILABLE",
        )

    def test_reported_failure_cannot_be_verified_from_untrusted_evidence(self):
        result = verify_report(
            self.report(False),
            self.evidence("failure", independent=True),
        )
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)

    def test_missing_evidence_is_inconclusive(self):
        result = verify_report(self.report(), None)
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "EVIDENCE_MISSING")

    def test_mismatched_action_id_is_inconclusive(self):
        result = verify_report(
            self.report(),
            self.evidence(action_id="different-action"),
        )
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "EVIDENCE_ACTION_ID_MISMATCH")

    def test_missing_evidence_reference_is_inconclusive(self):
        result = verify_report(self.report(), self.evidence(evidence_ref=" "))
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "EVIDENCE_REFERENCE_MISSING")

    def test_none_report_is_inconclusive(self):
        result = verify_report(None, None)  # type: ignore[arg-type]
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "INVALID_ACTION_REPORT")
        self.assertEqual(result.action_id, "")

    def test_wrong_report_type_is_inconclusive(self):
        result = verify_report(
            {"action_id": "action-001"},  # type: ignore[arg-type]
            None,
        )
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "INVALID_ACTION_REPORT")


if __name__ == "__main__":
    unittest.main()
