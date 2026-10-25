
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


class TestAuthorizationFailClosedInvariants(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = AuthorizationGate()
        self.now = datetime(
            2026, 10, 24, 12, 0,
            tzinfo=timezone.utc,
        )

    def request(
        self,
        *,
        action_id: str = "fail-closed-001",
        action_type: str = "write_file",
        resource: str = "README.md",
    ) -> ActionRequest:
        return ActionRequest(
            action_id=action_id,
            action_type=action_type,
            resource=resource,
        )

    def grant(self) -> AuthorizationGrant:
        return AuthorizationGrant(
            grant_id="fail-closed-grant",
            approved_by="human-reviewer",
            human_approved=True,
            allowed_actions=("write_file",),
            allowed_resources=("README.md",),
            expires_at=self.now + timedelta(minutes=10),
        )

    def assert_denied(
        self,
        request: ActionRequest,
        grant: AuthorizationGrant | None,
        expected_reason: str,
    ) -> None:
        decision = self.gate.evaluate(
            request,
            grant=grant,
            now=self.now,
        )

        self.assertIs(
            decision.allowed,
            False,
            msg=f"Unexpected authorization: {expected_reason}",
        )
        self.assertEqual(decision.reason, expected_reason)
        self.assertEqual(decision.action_id, request.action_id)

    def test_missing_grant_fails_closed(self) -> None:
        self.assert_denied(
            self.request(),
            None,
            "HUMAN_APPROVAL_REQUIRED",
        )

    def test_wrong_action_scope_fails_closed(self) -> None:
        grant = replace(
            self.grant(),
            allowed_actions=("create_pull_request",),
        )

        self.assert_denied(
            self.request(),
            grant,
            "ACTION_OUTSIDE_GRANT_SCOPE",
        )

    def test_wrong_resource_scope_fails_closed(self) -> None:
        grant = replace(
            self.grant(),
            allowed_resources=("docs/README.md",),
        )

        self.assert_denied(
            self.request(),
            grant,
            "RESOURCE_OUTSIDE_GRANT_SCOPE",
        )

    def test_non_boolean_approval_fails_closed(self) -> None:
        grant = replace(
            self.grant(),
            human_approved=1,  # type: ignore[arg-type]
        )

        self.assert_denied(
            self.request(),
            grant,
            "HUMAN_APPROVAL_NOT_CONFIRMED",
        )

    def test_expired_grant_fails_closed(self) -> None:
        grant = replace(
            self.grant(),
            expires_at=self.now,
        )

        self.assert_denied(
            self.request(),
            grant,
            "GRANT_EXPIRED",
        )

    def test_disabled_action_cannot_be_grant_authorized(
        self,
    ) -> None:
        request = self.request(
            action_type="merge_pull_request",
        )

        grant = replace(
            self.grant(),
            allowed_actions=("merge_pull_request",),
        )

        self.assert_denied(
            request,
            grant,
            "ACTION_DISABLED_IN_MVP",
        )

    def test_unknown_action_fails_closed(self) -> None:
        self.assert_denied(
            self.request(action_type="unknown_action"),
            self.grant(),
            "UNKNOWN_ACTION_TYPE",
        )

    def test_wildcard_resource_request_fails_closed(self) -> None:
        self.assert_denied(
            self.request(resource="*"),
            self.grant(),
            "WILDCARD_RESOURCE_NOT_ALLOWED",
        )


if __name__ == "__main__":
    unittest.main()
