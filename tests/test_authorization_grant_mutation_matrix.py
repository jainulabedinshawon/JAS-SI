
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


class TestAuthorizationGrantMutationMatrix(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = AuthorizationGate()
        self.now = datetime(
            2026, 10, 25, 12, 0,
            tzinfo=timezone.utc,
        )

        self.request = ActionRequest(
            action_id="grant-mutation-001",
            action_type="write_file",
            resource="README.md",
        )

        self.valid_grant = AuthorizationGrant(
            grant_id="mutation-grant-001",
            approved_by="human-reviewer",
            human_approved=True,
            allowed_actions=("write_file",),
            allowed_resources=("README.md",),
            expires_at=self.now + timedelta(minutes=10),
        )

    def test_mutated_grants_are_denied(self) -> None:
        cases = (
            (
                "approval revoked",
                replace(
                    self.valid_grant,
                    human_approved=False,
                ),
                "HUMAN_APPROVAL_NOT_CONFIRMED",
            ),
            (
                "blank grant identifier",
                replace(
                    self.valid_grant,
                    grant_id=" ",
                ),
                "INVALID_GRANT_ID",
            ),
            (
                "blank approver",
                replace(
                    self.valid_grant,
                    approved_by=" ",
                ),
                "MISSING_APPROVER",
            ),
            (
                "empty action scope",
                replace(
                    self.valid_grant,
                    allowed_actions=(),
                ),
                "INVALID_GRANT_ACTIONS",
            ),
            (
                "blank action scope entry",
                replace(
                    self.valid_grant,
                    allowed_actions=("",),
                ),
                "INVALID_GRANT_ACTIONS",
            ),
            (
                "empty resource scope",
                replace(
                    self.valid_grant,
                    allowed_resources=(),
                ),
                "INVALID_GRANT_RESOURCES",
            ),
            (
                "blank resource scope entry",
                replace(
                    self.valid_grant,
                    allowed_resources=(" ",),
                ),
                "INVALID_GRANT_RESOURCES",
            ),
            (
                "wrong action scope",
                replace(
                    self.valid_grant,
                    allowed_actions=("create_pull_request",),
                ),
                "ACTION_OUTSIDE_GRANT_SCOPE",
            ),
            (
                "wildcard action scope",
                replace(
                    self.valid_grant,
                    allowed_actions=("*",),
                ),
                "ACTION_OUTSIDE_GRANT_SCOPE",
            ),
            (
                "wrong resource scope",
                replace(
                    self.valid_grant,
                    allowed_resources=("private.txt",),
                ),
                "RESOURCE_OUTSIDE_GRANT_SCOPE",
            ),
            (
                "wildcard resource scope",
                replace(
                    self.valid_grant,
                    allowed_resources=("*",),
                ),
                "RESOURCE_OUTSIDE_GRANT_SCOPE",
            ),
            (
                "grant expires at current instant",
                replace(
                    self.valid_grant,
                    expires_at=self.now,
                ),
                "GRANT_EXPIRED",
            ),
            (
                "grant expired in the past",
                replace(
                    self.valid_grant,
                    expires_at=self.now - timedelta(seconds=1),
                ),
                "GRANT_EXPIRED",
            ),
        )

        for label, grant, expected_reason in cases:
            with self.subTest(case=label):
                decision = self.gate.evaluate(
                    self.request,
                    grant=grant,
                    now=self.now,
                )

                self.assertIs(
                    decision.allowed,
                    False,
                    msg=f"Mutation unexpectedly authorized: {label}",
                )
                self.assertEqual(
                    decision.reason,
                    expected_reason,
                )
                self.assertEqual(
                    decision.action_id,
                    self.request.action_id,
                )

    def test_original_valid_grant_remains_accepted(self) -> None:
        decision = self.gate.evaluate(
            self.request,
            grant=self.valid_grant,
            now=self.now,
        )

        self.assertIs(decision.allowed, True)
        self.assertEqual(
            decision.reason,
            "EXPLICIT_HUMAN_GRANT_ACCEPTED",
        )
        self.assertEqual(
            decision.grant_id,
            self.valid_grant.grant_id,
        )


if __name__ == "__main__":
    unittest.main()
