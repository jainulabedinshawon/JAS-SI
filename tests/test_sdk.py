"""Unit tests for the JAS-SI public SDK."""

import unittest

from jas_si_agent import JASSI
from jas_si_agent.authorization import AuthorizationDecision, AuthorizationGrant
from jas_si_agent.verification import ActionReport, VerificationEvidence, VerificationStatus


class TestJASSI(unittest.TestCase):
    def setUp(self):
        self.jas = JASSI()

    def test_safe_action_is_allowed(self):
        result = self.jas.authorize("action-001", "read_repository", "repo/example")
        self.assertIsInstance(result, AuthorizationDecision)
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, "SAFE_ACTION_POLICY_ALLOWED")

    def test_grant_required_action_denied_without_grant(self):
        result = self.jas.authorize("action-002", "write_file", "src/example.py")
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "HUMAN_APPROVAL_REQUIRED")

    def test_never_allowed_action_is_denied(self):
        result = self.jas.authorize("action-003", "execute_shell", "repo/example")
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "ACTION_DISABLED_IN_MVP")

    def test_unknown_action_is_denied(self):
        result = self.jas.authorize("action-004", "unknown_action", "repo/example")
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "UNKNOWN_ACTION_TYPE")

    def test_missing_evidence_is_inconclusive(self):
        result = self.jas.verify(ActionReport("action-005", True), evidence=None)
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "EVIDENCE_MISSING")

    def test_sdk_caller_cannot_forge_independent_evidence(self):
        result = self.jas.verify(
            ActionReport("action-006", True),
            VerificationEvidence(
                action_id="action-006",
                observed_state="failure",
                evidence_ref="caller-controlled-reference",
                collected_independently=True,
            ),
        )
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(
            result.reason,
            "TRUSTED_EVIDENCE_COLLECTOR_NOT_CONFIGURED",
        )

    def test_non_independent_evidence_is_not_trusted(self):
        result = self.jas.verify(
            ActionReport("action-007", True),
            VerificationEvidence(
                action_id="action-007",
                observed_state="success",
                evidence_ref="agent-self-report",
                collected_independently=False,
            ),
        )
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(
            result.reason,
            "TRUSTED_EVIDENCE_COLLECTOR_NOT_CONFIGURED",
        )

    def test_invalid_gate_type_is_rejected(self):
        with self.assertRaises(TypeError):
            JASSI(authorization_gate=object())

    def test_sdk_does_not_modify_grant_scope(self):
        grant = AuthorizationGrant(
            grant_id="grant-001",
            approved_by="reviewer-001",
            human_approved=True,
            allowed_actions=("write_file",),
            allowed_resources=("src/example.py",),
            expires_at=__import__("datetime").datetime.fromisoformat(
                "2099-01-01T00:00:00+00:00"
            ),
        )
        original_actions = grant.allowed_actions
        original_resources = grant.allowed_resources
        self.jas.authorize(
            action_id="action-008",
            action="write_file",
            resource="src/other.py",
            grant=grant,
        )
        self.assertEqual(grant.allowed_actions, original_actions)
        self.assertEqual(grant.allowed_resources, original_resources)


if __name__ == "__main__":
    unittest.main()
