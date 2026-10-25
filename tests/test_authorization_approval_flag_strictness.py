
from __future__ import annotations

import sys
import unittest
from dataclasses import replace
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


class TestAuthorizationApprovalFlagStrictness(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = AuthorizationGate()
        self.now = datetime(
            2026, 10, 24, 12, 0, 0,
            tzinfo=timezone.utc,
        )

        self.request = ActionRequest(
            action_id="approval-strictness-001",
            action_type="write_file",
            resource="README.md",
        )

        self.grant = AuthorizationGrant(
            grant_id="approval-strictness-grant-001",
            approved_by="human-reviewer",
            human_approved=True,
            allowed_actions=("write_file",),
            allowed_resources=("README.md",),
            expires_at=self.now + timedelta(minutes=10),
        )

    def test_only_boolean_true_is_accepted_as_approval(self) -> None:
        invalid_values = (
            False,
            1,
            0,
            "true",
            "yes",
            [],
            None,
            object(),
        )

        for value in invalid_values:
            with self.subTest(value_type=type(value).__name__):
                grant = replace(
                    self.grant,
                    human_approved=value,
                )

                decision = self.gate.evaluate(
                    self.request,
                    grant=grant,
                    now=self.now,
                )

                self.assertFalse(decision.allowed)
                self.assertEqual(
                    decision.reason,
                    "HUMAN_APPROVAL_NOT_CONFIRMED",
                )

    def test_actual_boolean_true_is_accepted(self) -> None:
        decision = self.gate.evaluate(
            self.request,
            grant=self.grant,
            now=self.now,
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(
            decision.reason,
            "EXPLICIT_HUMAN_GRANT_ACCEPTED",
        )
        self.assertEqual(
            decision.grant_id,
            self.grant.grant_id,
        )


if __name__ == "__main__":
    unittest.main()
