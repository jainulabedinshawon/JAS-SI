
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
    ActionRequest,
    AuthorizationGate,
    AuthorizationGrant,
)


class TestAuthorizationGrantScopeNonExpansion(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = AuthorizationGate()
        self.now = datetime(
            2026, 10, 24, 12, 0, 0,
            tzinfo=timezone.utc,
        )

    def request(
        self,
        *,
        action_type: str = "write_file",
        resource: str = "README.md",
    ) -> ActionRequest:
        return ActionRequest(
            action_id="scope-non-expansion-001",
            action_type=action_type,
            resource=resource,
        )

    def grant(
        self,
        *,
        actions: tuple[str, ...] = ("write_file",),
        resources: tuple[str, ...] = ("README.md",),
    ) -> AuthorizationGrant:
        return AuthorizationGrant(
            grant_id="scope-non-expansion-grant",
            approved_by="human-reviewer",
            human_approved=True,
            allowed_actions=actions,
            allowed_resources=resources,
            expires_at=self.now + timedelta(minutes=10),
        )

    def assert_scope_denied(
        self,
        *,
        actions: tuple[str, ...],
        expected_reason: str = "ACTION_OUTSIDE_GRANT_SCOPE",
    ) -> None:
        decision = self.gate.evaluate(
            self.request(),
            grant=self.grant(actions=actions),
            now=self.now,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, expected_reason)
        self.assertEqual(
            decision.action_id,
            "scope-non-expansion-001",
        )
        self.assertEqual(
            decision.grant_id,
            "scope-non-expansion-grant",
        )

    def test_wildcard_action_does_not_authorize_write(self) -> None:
        self.assert_scope_denied(actions=("*",))

    def test_uppercase_grant_action_does_not_match(self) -> None:
        self.assert_scope_denied(actions=("WRITE_FILE",))

    def test_whitespace_padded_grant_action_does_not_match(
        self,
    ) -> None:
        self.assert_scope_denied(actions=(" write_file ",))

    def test_partial_action_name_does_not_authorize_write(
        self,
    ) -> None:
        self.assert_scope_denied(actions=("write_",))

    def test_exact_action_scope_remains_authorized(self) -> None:
        decision = self.gate.evaluate(
            self.request(),
            grant=self.grant(actions=("write_file",)),
            now=self.now,
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(
            decision.reason,
            "EXPLICIT_HUMAN_GRANT_ACCEPTED",
        )
        self.assertEqual(
            decision.grant_id,
            "scope-non-expansion-grant",
        )


if __name__ == "__main__":
    unittest.main()
