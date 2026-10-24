
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


class TestAuthorizationGrantNonInterference(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = AuthorizationGate()
        self.now = datetime(
            2026, 10, 25, 12, 0,
            tzinfo=timezone.utc,
        )

    def test_unrelated_grant_does_not_change_safe_action_decision(
        self,
    ) -> None:
        request = ActionRequest(
            action_id="non-interference-001",
            action_type="read_repository",
            resource="README.md",
        )

        grant = AuthorizationGrant(
            grant_id="unrelated-grant-001",
            approved_by="human-reviewer",
            human_approved=True,
            allowed_actions=("write_file",),
            allowed_resources=("private.txt",),
            expires_at=self.now + timedelta(minutes=10),
        )

        without_grant = self.gate.evaluate(
            request,
            now=self.now,
        )

        with_unrelated_grant = self.gate.evaluate(
            request,
            grant=grant,
            now=self.now,
        )

        self.assertTrue(without_grant.allowed)
        self.assertTrue(with_unrelated_grant.allowed)

        self.assertEqual(
            without_grant.reason,
            "SAFE_ACTION_POLICY_ALLOWED",
        )
        self.assertEqual(
            with_unrelated_grant.reason,
            "SAFE_ACTION_POLICY_ALLOWED",
        )

        self.assertEqual(
            without_grant.action_id,
            with_unrelated_grant.action_id,
        )
        self.assertIsNone(without_grant.grant_id)
        self.assertIsNone(with_unrelated_grant.grant_id)

    def test_safe_action_does_not_claim_grant_authorization(
        self,
    ) -> None:
        request = ActionRequest(
            action_id="non-interference-002",
            action_type="run_tests",
            resource="tests/",
        )

        grant = AuthorizationGrant(
            grant_id="write-only-grant",
            approved_by="human-reviewer",
            human_approved=True,
            allowed_actions=("write_file",),
            allowed_resources=("README.md",),
            expires_at=self.now + timedelta(minutes=10),
        )

        decision = self.gate.evaluate(
            request,
            grant=grant,
            now=self.now,
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(
            decision.reason,
            "SAFE_ACTION_POLICY_ALLOWED",
        )
        self.assertIsNone(decision.grant_id)

    def test_grant_required_action_still_requires_grant(
        self,
    ) -> None:
        request = ActionRequest(
            action_id="non-interference-003",
            action_type="write_file",
            resource="README.md",
        )

        decision = self.gate.evaluate(
            request,
            now=self.now,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "HUMAN_APPROVAL_REQUIRED",
        )
        self.assertIsNone(decision.grant_id)


if __name__ == "__main__":
    unittest.main()
