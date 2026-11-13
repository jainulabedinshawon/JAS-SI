from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.action_lifecycle import ActionLifecycleCoordinator
from jas_si_agent.authorization import ActionRequest, AuthorizationDecision
from jas_si_agent.verification import ActionReport, VerificationEvidence, VerificationStatus


class TestActionLifecycleCoordinator(unittest.TestCase):
    def setUp(self):
        self.coordinator = ActionLifecycleCoordinator()

    def request(self):
        return ActionRequest("action-001", "read_repository", "README.md")

    def report(self, claimed_success=True):
        return ActionReport("action-001", claimed_success)

    def evidence(self, observed_state="success"):
        return VerificationEvidence(
            action_id="action-001",
            observed_state=observed_state,
            evidence_ref="caller-controlled-test-reference",
            collected_independently=True,
        )

    def test_forged_authorization_decision_is_rejected(self):
        forged = AuthorizationDecision(True, "FORGED", "action-001")
        result = self.coordinator.verify_outcome(forged, self.report(), self.evidence())
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "INVALID_AUTHORIZATION_DECISION")

    def test_non_boolean_true_decision_is_rejected(self):
        decision = self.coordinator.authorize(self.request())
        object.__setattr__(decision, "allowed", 1)
        result = self.coordinator.verify_outcome(decision, self.report(), self.evidence())
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "ACTION_NOT_AUTHORIZED")

    def test_authorization_decision_cannot_be_replayed(self):
        decision = self.coordinator.authorize(self.request())
        first = self.coordinator.verify_outcome(decision, self.report(), self.evidence())
        second = self.coordinator.verify_outcome(decision, self.report(), self.evidence())
        self.assertEqual(first.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(first.reason, "TRUSTED_EVIDENCE_COLLECTOR_NOT_CONFIGURED")
        self.assertEqual(second.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(second.reason, "INVALID_AUTHORIZATION_DECISION")

    def test_safe_request_is_authorized_by_policy(self):
        decision = self.coordinator.authorize(self.request())
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "SAFE_ACTION_POLICY_ALLOWED")

    def test_unauthorized_action_cannot_be_verified(self):
        request = ActionRequest("action-001", "execute_shell", "README.md")
        decision = self.coordinator.authorize(request)
        self.assertIs(decision.allowed, False)
        result = self.coordinator.verify_outcome(decision, self.report(), self.evidence())
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "ACTION_NOT_AUTHORIZED")

    def test_authorized_action_without_trusted_collector_is_inconclusive(self):
        decision = self.coordinator.authorize(self.request())
        result = self.coordinator.verify_outcome(decision, self.report(), self.evidence())
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "TRUSTED_EVIDENCE_COLLECTOR_NOT_CONFIGURED")

    def test_false_success_is_not_claimed_without_trusted_collector(self):
        decision = self.coordinator.authorize(self.request())
        result = self.coordinator.verify_outcome(
            decision, self.report(True), self.evidence("failure")
        )
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "TRUSTED_EVIDENCE_COLLECTOR_NOT_CONFIGURED")

    def test_action_id_mismatch_is_inconclusive(self):
        decision = self.coordinator.authorize(self.request())
        report = ActionReport("different-action", True)
        result = self.coordinator.verify_outcome(decision, report, self.evidence())
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "ACTION_ID_MISMATCH")

    def test_missing_evidence_is_inconclusive(self):
        decision = self.coordinator.authorize(self.request())
        result = self.coordinator.verify_outcome(decision, self.report(), None)
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "EVIDENCE_MISSING")

    def test_none_report_is_inconclusive(self):
        decision = self.coordinator.authorize(self.request())
        result = self.coordinator.verify_outcome(decision, None, self.evidence())
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "INVALID_ACTION_REPORT")
        self.assertEqual(result.action_id, "")

    def test_wrong_report_type_is_inconclusive(self):
        decision = self.coordinator.authorize(self.request())
        result = self.coordinator.verify_outcome(decision, "not-an-action-report", self.evidence())
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "INVALID_ACTION_REPORT")
        self.assertEqual(result.action_id, "")

    def test_invalid_authorization_decision_is_inconclusive(self):
        result = self.coordinator.verify_outcome(None, self.report(), self.evidence())
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "INVALID_AUTHORIZATION_DECISION")

    def test_empty_action_id_is_inconclusive(self):
        decision = self.coordinator.authorize(self.request())
        result = self.coordinator.verify_outcome(
            decision, ActionReport(" ", True), self.evidence()
        )
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "INVALID_ACTION_ID")


if __name__ == "__main__":
    unittest.main()
