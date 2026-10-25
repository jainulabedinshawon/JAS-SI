from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.action_lifecycle import (  # noqa: E402
    ActionLifecycleCoordinator,
)
from jas_si_agent.authorization import (  # noqa: E402
    ActionRequest,
    AuthorizationDecision,
)
from jas_si_agent.verification import (  # noqa: E402
    ActionReport,
    VerificationEvidence,
    VerificationStatus,
)


class TestActionLifecycleCoordinator(unittest.TestCase):
    def setUp(self) -> None:
        self.coordinator = ActionLifecycleCoordinator()

    def request(self) -> ActionRequest:
        return ActionRequest(
            action_id="action-001",
            action_type="read_repository",
            resource="README.md",
        )

    def report(self, claimed_success: bool = True) -> ActionReport:
        return ActionReport(
            action_id="action-001",
            claimed_success=claimed_success,
        )

    def evidence(
        self,
        observed_state: str = "success",
    ) -> VerificationEvidence:
        return VerificationEvidence(
            action_id="action-001",
            observed_state=observed_state,
            evidence_ref="test-evidence-001",
            collected_independently=True,
        )

    def test_safe_request_is_authorized_by_policy(self) -> None:
        decision = self.coordinator.authorize(self.request())
        self.assertTrue(decision.allowed)
        self.assertEqual(
            decision.reason,
            "SAFE_ACTION_POLICY_ALLOWED",
        )

    def test_unauthorized_action_cannot_be_verified(self) -> None:
        decision = AuthorizationDecision(
            allowed=False,
            reason="HUMAN_APPROVAL_REQUIRED",
            action_id="action-001",
        )
        result = self.coordinator.verify_outcome(
            decision,
            self.report(),
            self.evidence(),
        )
        self.assertEqual(
            result.status,
            VerificationStatus.INCONCLUSIVE,
        )
        self.assertEqual(result.reason, "ACTION_NOT_AUTHORIZED")

    def test_authorized_matching_success_is_verified(self) -> None:
        decision = self.coordinator.authorize(self.request())
        result = self.coordinator.verify_outcome(
            decision,
            self.report(True),
            self.evidence("success"),
        )
        self.assertEqual(
            result.status,
            VerificationStatus.VERIFIED_SUCCESS,
        )

    def test_false_success_is_detected(self) -> None:
        decision = self.coordinator.authorize(self.request())
        result = self.coordinator.verify_outcome(
            decision,
            self.report(True),
            self.evidence("failure"),
        )
        self.assertEqual(
            result.status,
            VerificationStatus.FALSE_SUCCESS,
        )

    def test_action_id_mismatch_is_inconclusive(self) -> None:
        decision = self.coordinator.authorize(self.request())
        mismatched_report = ActionReport(
            action_id="different-action",
            claimed_success=True,
        )
        result = self.coordinator.verify_outcome(
            decision,
            mismatched_report,
            self.evidence(),
        )
        self.assertEqual(
            result.status,
            VerificationStatus.INCONCLUSIVE,
        )
        self.assertEqual(result.reason, "ACTION_ID_MISMATCH")

    def test_missing_evidence_is_inconclusive(self) -> None:
        decision = self.coordinator.authorize(self.request())
        result = self.coordinator.verify_outcome(
            decision,
            self.report(),
            None,
        )
        self.assertEqual(
            result.status,
            VerificationStatus.INCONCLUSIVE,
        )
        self.assertEqual(result.reason, "EVIDENCE_MISSING")

    def test_none_report_is_inconclusive(self) -> None:
        decision = self.coordinator.authorize(self.request())
        result = self.coordinator.verify_outcome(
            decision,
            None,  # type: ignore[arg-type]
            self.evidence(),
        )
        self.assertEqual(
            result.status,
            VerificationStatus.INCONCLUSIVE,
        )
        self.assertEqual(result.reason, "INVALID_ACTION_REPORT")
        self.assertEqual(result.action_id, "")

    def test_wrong_report_type_is_inconclusive(self) -> None:
        decision = self.coordinator.authorize(self.request())
        result = self.coordinator.verify_outcome(
            decision,
            "not-an-action-report",  # type: ignore[arg-type]
            self.evidence(),
        )
        self.assertEqual(
            result.status,
            VerificationStatus.INCONCLUSIVE,
        )
        self.assertEqual(result.reason, "INVALID_ACTION_REPORT")
        self.assertEqual(result.action_id, "")

    def test_invalid_authorization_decision_is_inconclusive(self) -> None:
        result = self.coordinator.verify_outcome(
            None,  # type: ignore[arg-type]
            self.report(),
            self.evidence(),
        )
        self.assertEqual(
            result.status,
            VerificationStatus.INCONCLUSIVE,
        )
        self.assertEqual(
            result.reason,
            "INVALID_AUTHORIZATION_DECISION",
        )

    def test_empty_action_id_is_inconclusive(self) -> None:
        decision = self.coordinator.authorize(self.request())
        invalid_report = ActionReport(
            action_id=" ",
            claimed_success=True,
        )
        result = self.coordinator.verify_outcome(
            decision,
            invalid_report,
            self.evidence(),
        )
        self.assertEqual(
            result.status,
            VerificationStatus.INCONCLUSIVE,
        )
        self.assertEqual(result.reason, "INVALID_ACTION_ID")


if __name__ == "__main__":
    unittest.main()
