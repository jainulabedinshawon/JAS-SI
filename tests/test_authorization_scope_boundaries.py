
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


class TestAuthorizationScopeBoundaries(unittest.TestCase):
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
            action_id="scope-boundary-001",
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
            grant_id="scope-grant-001",
            approved_by="human-reviewer",
            human_approved=True,
            allowed_actions=actions,
            allowed_resources=resources,
            expires_at=self.now + timedelta(minutes=10),
        )

    def assert_denied_with_reason(
        self,
        request: ActionRequest,
        grant: AuthorizationGrant,
        expected_reason: str,
        *,
        expect_grant_id: bool = True,
    ) -> None:
        decision = self.gate.evaluate(
            request,
            grant=grant,
            now=self.now,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, expected_reason)
        self.assertEqual(decision.action_id, request.action_id)

        expected_grant_id = (
            grant.grant_id if expect_grant_id else None
        )
        self.assertEqual(decision.grant_id, expected_grant_id)

    def test_exact_resource_match_is_accepted(self) -> None:
        decision = self.gate.evaluate(
            self.request(resource="README.md"),
            grant=self.grant(resources=("README.md",)),
            now=self.now,
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(
            decision.reason,
            "EXPLICIT_HUMAN_GRANT_ACCEPTED",
        )
        self.assertEqual(decision.grant_id, "scope-grant-001")

    def test_parent_directory_scope_does_not_imply_child_scope(
        self,
    ) -> None:
        self.assert_denied_with_reason(
            self.request(resource="docs/guide.md"),
            self.grant(resources=("docs",)),
            "RESOURCE_OUTSIDE_GRANT_SCOPE",
        )

    def test_similar_resource_name_is_not_authorized(self) -> None:
        self.assert_denied_with_reason(
            self.request(resource="README.md.bak"),
            self.grant(resources=("README.md",)),
            "RESOURCE_OUTSIDE_GRANT_SCOPE",
        )

    def test_resource_case_difference_is_not_authorized(self) -> None:
        self.assert_denied_with_reason(
            self.request(resource="readme.md"),
            self.grant(resources=("README.md",)),
            "RESOURCE_OUTSIDE_GRANT_SCOPE",
        )

    def test_resource_whitespace_difference_is_not_authorized(
        self,
    ) -> None:
        self.assert_denied_with_reason(
            self.request(resource=" README.md "),
            self.grant(resources=("README.md",)),
            "RESOURCE_OUTSIDE_GRANT_SCOPE",
        )

    def test_action_case_difference_is_not_authorized(self) -> None:
        self.assert_denied_with_reason(
            self.request(action_type="WRITE_FILE"),
            self.grant(actions=("write_file",)),
            "UNKNOWN_ACTION_TYPE",
            expect_grant_id=False,
        )

    def test_grant_for_different_action_is_not_authorized(self) -> None:
        self.assert_denied_with_reason(
            self.request(action_type="write_file"),
            self.grant(actions=("create_pull_request",)),
            "ACTION_OUTSIDE_GRANT_SCOPE",
        )


if __name__ == "__main__":
    unittest.main()
