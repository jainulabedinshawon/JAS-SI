
"""Unit tests for the JAS-SI public SDK."""

import unittest

from jas_si_agent import JASSI
from jas_si_agent.authorization import (
    AuthorizationDecision,
    AuthorizationGrant,
)
from jas_si_agent.verification import (
    ActionReport,
    VerificationEvidence,
    VerificationStatus,
)


class TestJASSI(unittest.TestCase):
    def setUp(self):
        self.jas = JASSI()

    def test_safe_action_is_allowed(self):
        result = self.jas.authorize(
            action_id="action-001",
            action="read_repository",
            resource="repo/example",
        )

        self.assertIsInstance(result, AuthorizationDecision)
        self.assertTrue(result.allowed)
        self.assertEqual(
            result.reason,
            "SAFE_ACTION_POLICY_ALLOWED",
        )

    def test_grant_required_action_denied_without_grant(self):
        result = self.jas.authorize(
            action_id="action-002",
            action="write_file",
            resource="src/example.py",
        )

        self.assertFalse(result.allowed)
        self.assertEqual(
            result.reason,
            "HUMAN_APPROVAL_REQUIRED",
        )

    def test_never_allowed_action_is_denied(self):
        result = self.jas.authorize(
            action_id="action-003",
            action="execute_shell",
            resource="repo/example",
        )

        self.assertFalse(result.allowed)
        self.assertEqual(
            result.reason,
            "ACTION_DISABLED_IN_MVP",
        )

    def test_unknown_action_is_denied(self):
        result = self.jas.authorize(
            action_id="action-004",
            action="unknown_action",
            resource="repo/example",
        )

        self.assertFalse(result.allowed)
        self.assertEqual(
            result.reason,
            "UNKNOWN_ACTION_TYPE",
        )

    def test_missing_evidence_is_inconclusive(self):
        result = self.jas.verify(
            ActionReport(
                action_id="action-005",
                claimed_success=True,
            ),
            evidence=None,
        )

        self.assertEqual(
            result.status,
            VerificationStatus.INCONCLUSIVE,
        )
        self.assertEqual(result.reason, "EVIDENCE_MISSING")

    def test_independent_failure_evidence_detects_false_success(self):
        result = self.jas.verify(
            ActionReport(
                action_id="action-006",
                claimed_success=True,
            ),
            VerificationEvidence(
                action_id="action-006",
                observed_state="failure",
                evidence_ref="test-evidence-006",
                collected_independently=True,
            ),
        )

        self.assertEqual(
            result.status,
            VerificationStatus.FALSE_SUCCESS,
        )

    def test_non_independent_evidence_is_inconclusive(self):
        result = self.jas.verify(
            ActionReport(
                action_id="action-007",
                claimed_success=True,
            ),
            VerificationEvidence(
                action_id="action-007",
                observed_state="success",
                evidence_ref="agent-self-report",
                collected_independently=False,
            ),
        )

        self.assertEqual(
            result.status,
            VerificationStatus.INCONCLUSIVE,
        )
        self.assertEqual(
            result.reason,
            "INDEPENDENCE_NOT_ESTABLISHED",
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
