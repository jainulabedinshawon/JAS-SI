
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


class TestAuthorizationEvaluationDeterminism(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = AuthorizationGate()
        self.now = datetime(
            2026, 10, 24, 12, 0, 0,
            tzinfo=timezone.utc,
        )

        self.request = ActionRequest(
            action_id="determinism-request-001",
            action_type="write_file",
            resource="README.md",
        )

        self.grant = AuthorizationGrant(
            grant_id="determinism-grant-001",
            approved_by="human-reviewer",
            human_approved=True,
            allowed_actions=("write_file",),
            allowed_resources=("README.md",),
            expires_at=self.now + timedelta(minutes=10),
        )

    def test_repeated_approved_evaluation_is_identical(self) -> None:
        first = self.gate.evaluate(
            self.request,
            grant=self.grant,
            now=self.now,
        )
        second = self.gate.evaluate(
            self.request,
            grant=self.grant,
            now=self.now,
        )

        self.assertEqual(first, second)
        self.assertTrue(first.allowed)
        self.assertEqual(
            first.reason,
            "EXPLICIT_HUMAN_GRANT_ACCEPTED",
        )
        self.assertEqual(
            first.action_id,
            self.request.action_id,
        )
        self.assertEqual(
            first.grant_id,
            self.grant.grant_id,
        )

    def test_repeated_denial_evaluation_is_identical(self) -> None:
        first = self.gate.evaluate(
            self.request,
            grant=None,
            now=self.now,
        )
        second = self.gate.evaluate(
            self.request,
            grant=None,
            now=self.now,
        )

        self.assertEqual(first, second)
        self.assertFalse(first.allowed)
        self.assertEqual(
            first.reason,
            "HUMAN_APPROVAL_REQUIRED",
        )
        self.assertEqual(
            first.action_id,
            self.request.action_id,
        )
        self.assertIsNone(first.grant_id)

    def test_evaluation_does_not_mutate_request_or_grant(self) -> None:
        original_request = (
            self.request.action_id,
            self.request.action_type,
            self.request.resource,
        )
        original_grant = (
            self.grant.grant_id,
            self.grant.approved_by,
            self.grant.human_approved,
            self.grant.allowed_actions,
            self.grant.allowed_resources,
            self.grant.expires_at,
        )

        self.gate.evaluate(
            self.request,
            grant=self.grant,
            now=self.now,
        )

        self.assertEqual(
            (
                self.request.action_id,
                self.request.action_type,
                self.request.resource,
            ),
            original_request,
        )
        self.assertEqual(
            (
                self.grant.grant_id,
                self.grant.approved_by,
                self.grant.human_approved,
                self.grant.allowed_actions,
                self.grant.allowed_resources,
                self.grant.expires_at,
            ),
            original_grant,
        )


if __name__ == "__main__":
    unittest.main()
