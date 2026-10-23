
from __future__ import annotations

import sys
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.authorization import (
    ActionRequest,
    AuthorizationDecision,
    AuthorizationGate,
    AuthorizationGrant,
)


class TestAuthorizationDecisionContract(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = AuthorizationGate()
        self.now = datetime(
            2026, 10, 24, 12, 0, 0,
            tzinfo=timezone.utc,
        )

    def request(
        self,
        action_type: str = "write_file",
        action_id: str = "contract-test-001",
        resource: str = "README.md",
    ) -> ActionRequest:
        return ActionRequest(
            action_id=action_id,
            action_type=action_type,
            resource=resource,
        )

    def grant(
        self,
        *,
        action_type: str = "write_file",
        resource: str = "README.md",
        expires_at: datetime | None = None,
    ) -> AuthorizationGrant:
        return AuthorizationGrant(
            grant_id="contract-grant-001",
            approved_by="human-reviewer",
            human_approved=True,
            allowed_actions=(action_type,),
            allowed_resources=(resource,),
            expires_at=(
                expires_at
                if expires_at is not None
                else self.now + timedelta(minutes=10)
            ),
        )

    def test_decision_model_is_immutable(self) -> None:
        decision = AuthorizationDecision(
            allowed=False,
            reason="HUMAN_APPROVAL_REQUIRED",
            action_id="contract-test-001",
        )

        with self.assertRaises(FrozenInstanceError):
            decision.allowed = True  # type: ignore[misc]

        with self.assertRaises(FrozenInstanceError):
            decision.reason = "SAFE_ACTION_POLICY_ALLOWED"  # type: ignore[misc]

    def test_safe_decision_preserves_action_id(self) -> None:
        request = self.request(
            action_type="read_repository",
            action_id="read-contract-123",
        )

        decision = self.gate.evaluate(request, now=self.now)

        self.assertTrue(decision.allowed)
        self.assertEqual(
            decision.reason,
            "SAFE_ACTION_POLICY_ALLOWED",
        )
        self.assertEqual(decision.action_id, request.action_id)
        self.assertIsNone(decision.grant_id)

    def test_missing_grant_decision_preserves_action_id(self) -> None:
        request = self.request(action_id="missing-grant-456")

        decision = self.gate.evaluate(request, now=self.now)

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "HUMAN_APPROVAL_REQUIRED",
        )
        self.assertEqual(decision.action_id, request.action_id)
        self.assertIsNone(decision.grant_id)

    def test_accepted_grant_is_identified_in_decision(self) -> None:
        request = self.request(action_id="approved-write-789")
        grant = self.grant()

        decision = self.gate.evaluate(
            request,
            grant=grant,
            now=self.now,
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(
            decision.reason,
            "EXPLICIT_HUMAN_GRANT_ACCEPTED",
        )
        self.assertEqual(decision.action_id, request.action_id)
        self.assertEqual(decision.grant_id, grant.grant_id)

    def test_expired_grant_decision_preserves_grant_id(self) -> None:
        grant = self.grant(expires_at=self.now)

        decision = self.gate.evaluate(
            self.request(action_id="expired-grant-001"),
            grant=grant,
            now=self.now,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "GRANT_EXPIRED")
        self.assertEqual(decision.action_id, "expired-grant-001")
        self.assertEqual(decision.grant_id, grant.grant_id)

    def test_disabled_action_cannot_be_overridden_by_grant(self) -> None:
        request = self.request(
            action_type="merge_pull_request",
            action_id="disabled-merge-001",
        )
        grant = self.grant(action_type="merge_pull_request")

        decision = self.gate.evaluate(
            request,
            grant=grant,
            now=self.now,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "ACTION_DISABLED_IN_MVP",
        )
        self.assertEqual(decision.action_id, request.action_id)

    def test_unknown_action_fails_closed_with_correct_id(self) -> None:
        request = self.request(
            action_type="unregistered_action",
            action_id="unknown-action-001",
        )

        decision = self.gate.evaluate(request, now=self.now)

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "UNKNOWN_ACTION_TYPE")
        self.assertEqual(decision.action_id, request.action_id)


if __name__ == "__main__":
    unittest.main()
