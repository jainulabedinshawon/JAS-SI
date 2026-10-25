
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


class TestAuthorizationGateStateIsolation(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = AuthorizationGate()
        self.now = datetime(
            2026, 10, 24, 12, 0, 0,
            tzinfo=timezone.utc,
        )

        self.request = ActionRequest(
            action_id="state-isolation-001",
            action_type="write_file",
            resource="README.md",
        )

        self.grant = AuthorizationGrant(
            grant_id="state-isolation-grant-001",
            approved_by="human-reviewer",
            human_approved=True,
            allowed_actions=("write_file",),
            allowed_resources=("README.md",),
            expires_at=self.now + timedelta(minutes=10),
        )

    def test_denial_does_not_cancel_later_valid_decision(self) -> None:
        first = self.gate.evaluate(
            self.request,
            grant=self.grant,
            now=self.now,
        )

        denied = self.gate.evaluate(
            self.request,
            grant=None,
            now=self.now,
        )

        final = self.gate.evaluate(
            self.request,
            grant=self.grant,
            now=self.now,
        )

        self.assertTrue(first.allowed)
        self.assertEqual(
            first.reason,
            "EXPLICIT_HUMAN_GRANT_ACCEPTED",
        )

        self.assertFalse(denied.allowed)
        self.assertEqual(
            denied.reason,
            "HUMAN_APPROVAL_REQUIRED",
        )

        self.assertEqual(final, first)

    def test_denied_resource_does_not_expand_grant_scope(self) -> None:
        outside_request = ActionRequest(
            action_id="state-isolation-002",
            action_type="write_file",
            resource="private.txt",
        )

        denied = self.gate.evaluate(
            outside_request,
            grant=self.grant,
            now=self.now,
        )

        original = self.gate.evaluate(
            self.request,
            grant=self.grant,
            now=self.now,
        )

        self.assertFalse(denied.allowed)
        self.assertEqual(
            denied.reason,
            "RESOURCE_OUTSIDE_GRANT_SCOPE",
        )

        self.assertTrue(original.allowed)
        self.assertEqual(
            original.reason,
            "EXPLICIT_HUMAN_GRANT_ACCEPTED",
        )
        self.assertEqual(
            original.grant_id,
            self.grant.grant_id,
        )

    def test_disabled_action_does_not_affect_later_evaluation(self) -> None:
        disabled_request = ActionRequest(
            action_id="state-isolation-003",
            action_type="merge_pull_request",
            resource="README.md",
        )

        disabled_grant = AuthorizationGrant(
            grant_id="disabled-action-grant",
            approved_by="human-reviewer",
            human_approved=True,
            allowed_actions=("merge_pull_request",),
            allowed_resources=("README.md",),
            expires_at=self.now + timedelta(minutes=10),
        )

        denied = self.gate.evaluate(
            disabled_request,
            grant=disabled_grant,
            now=self.now,
        )

        allowed = self.gate.evaluate(
            self.request,
            grant=self.grant,
            now=self.now,
        )

        self.assertFalse(denied.allowed)
        self.assertEqual(
            denied.reason,
            "ACTION_DISABLED_IN_MVP",
        )

        self.assertTrue(allowed.allowed)
        self.assertEqual(
            allowed.reason,
            "EXPLICIT_HUMAN_GRANT_ACCEPTED",
        )


if __name__ == "__main__":
    unittest.main()
