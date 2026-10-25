
from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.authorization import (
    SAFE_ACTIONS,
    GRANT_REQUIRED_ACTIONS,
    NEVER_ALLOWED_ACTIONS,
    SUPPORTED_ACTIONS,
    ActionRequest,
    AuthorizationGate,
    AuthorizationGrant,
)


class TestAuthorizationPolicyMatrix(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = AuthorizationGate()
        self.now = datetime.now(timezone.utc)

    def request(
        self,
        action_type: str,
        resource: str = "README.md",
    ) -> ActionRequest:
        return ActionRequest(
            action_id=f"matrix-{action_type}",
            action_type=action_type,
            resource=resource,
        )

    def grant_for(
        self,
        action_type: str,
        resource: str = "README.md",
    ) -> AuthorizationGrant:
        return AuthorizationGrant(
            grant_id=f"grant-{action_type}",
            approved_by="human-reviewer",
            human_approved=True,
            allowed_actions=(action_type,),
            allowed_resources=(resource,),
            expires_at=self.now + timedelta(minutes=10),
        )

    def test_policy_categories_are_disjoint(self) -> None:
        self.assertEqual(
            SAFE_ACTIONS & GRANT_REQUIRED_ACTIONS,
            frozenset(),
        )
        self.assertEqual(
            SAFE_ACTIONS & NEVER_ALLOWED_ACTIONS,
            frozenset(),
        )
        self.assertEqual(
            GRANT_REQUIRED_ACTIONS & NEVER_ALLOWED_ACTIONS,
            frozenset(),
        )

        self.assertEqual(
            SAFE_ACTIONS
            | GRANT_REQUIRED_ACTIONS
            | NEVER_ALLOWED_ACTIONS,
            SUPPORTED_ACTIONS,
        )

    def test_every_safe_action_is_policy_allowed(self) -> None:
        for action_type in sorted(SAFE_ACTIONS):
            with self.subTest(action_type=action_type):
                decision = self.gate.evaluate(
                    self.request(action_type),
                    now=self.now,
                )

                self.assertTrue(decision.allowed)
                self.assertEqual(
                    decision.reason,
                    "SAFE_ACTION_POLICY_ALLOWED",
                )

    def test_every_grant_required_action_is_denied_without_grant(
        self,
    ) -> None:
        for action_type in sorted(GRANT_REQUIRED_ACTIONS):
            with self.subTest(action_type=action_type):
                decision = self.gate.evaluate(
                    self.request(action_type),
                    now=self.now,
                )

                self.assertFalse(decision.allowed)
                self.assertEqual(
                    decision.reason,
                    "HUMAN_APPROVAL_REQUIRED",
                )

    def test_every_grant_required_action_accepts_exact_valid_grant(
        self,
    ) -> None:
        for action_type in sorted(GRANT_REQUIRED_ACTIONS):
            with self.subTest(action_type=action_type):
                grant = self.grant_for(action_type)

                decision = self.gate.evaluate(
                    self.request(action_type),
                    grant=grant,
                    now=self.now,
                )

                self.assertTrue(decision.allowed)
                self.assertEqual(
                    decision.reason,
                    "EXPLICIT_HUMAN_GRANT_ACCEPTED",
                )
                self.assertEqual(
                    decision.grant_id,
                    grant.grant_id,
                )

    def test_every_never_allowed_action_is_denied_even_with_grant(
        self,
    ) -> None:
        for action_type in sorted(NEVER_ALLOWED_ACTIONS):
            with self.subTest(action_type=action_type):
                grant = self.grant_for(action_type)

                decision = self.gate.evaluate(
                    self.request(action_type),
                    grant=grant,
                    now=self.now,
                )

                self.assertFalse(decision.allowed)
                self.assertEqual(
                    decision.reason,
                    "ACTION_DISABLED_IN_MVP",
                )

    def test_unknown_action_is_denied(self) -> None:
        decision = self.gate.evaluate(
            self.request("unregistered_action"),
            now=self.now,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "UNKNOWN_ACTION_TYPE",
        )

    def test_grant_cannot_authorize_another_resource(self) -> None:
        grant = self.grant_for(
            "write_file",
            resource="README.md",
        )

        decision = self.gate.evaluate(
            self.request(
                "write_file",
                resource="src/unauthorized.py",
            ),
            grant=grant,
            now=self.now,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "RESOURCE_OUTSIDE_GRANT_SCOPE",
        )


if __name__ == "__main__":
    unittest.main()
