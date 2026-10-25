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

from jas_si_agent.authorization import (  # noqa: E402
    ActionRequest,
    AuthorizationGate,
    AuthorizationGrant,
)


class TestAuthorizationGrantBoundaries(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = AuthorizationGate()
        self.now = datetime(
            2026, 10, 24, 12, 0, 0,
            tzinfo=timezone.utc,
        )

    def request(
        self,
        *,
        action_id: str = "grant-boundary-001",
        action_type: str = "write_file",
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
        grant_id: str = "grant-boundary-001",
        approved_by: str = "human-reviewer",
        approved: bool = True,
        actions: tuple[str, ...] = ("write_file",),
        resources: tuple[str, ...] = ("README.md",),
        expires_at: datetime | None = None,
    ) -> AuthorizationGrant:
        return AuthorizationGrant(
            grant_id=grant_id,
            approved_by=approved_by,
            human_approved=approved,
            allowed_actions=actions,
            allowed_resources=resources,
            expires_at=(
                expires_at
                if expires_at is not None
                else self.now + timedelta(minutes=10)
            ),
        )

    def assert_denied(
        self,
        decision,
        expected_reason: str,
    ) -> None:
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, expected_reason)

    def test_valid_explicit_grant_is_accepted(self) -> None:
        decision = self.gate.evaluate(
            self.request(),
            grant=self.grant(),
            now=self.now,
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(
            decision.reason,
            "EXPLICIT_HUMAN_GRANT_ACCEPTED",
        )
        self.assertEqual(
            decision.grant_id,
            "grant-boundary-001",
        )

    def test_missing_grant_is_denied(self) -> None:
        decision = self.gate.evaluate(
            self.request(),
            now=self.now,
        )

        self.assert_denied(
            decision,
            "HUMAN_APPROVAL_REQUIRED",
        )

    def test_non_grant_object_is_denied(self) -> None:
        decision = self.gate.evaluate(
            self.request(),
            grant=object(),
            now=self.now,
        )

        self.assert_denied(decision, "INVALID_GRANT")

    def test_grant_expiring_one_microsecond_later_is_accepted(
        self,
    ) -> None:
        grant = self.grant(
            expires_at=self.now + timedelta(microseconds=1),
        )

        decision = self.gate.evaluate(
            self.request(),
            grant=grant,
            now=self.now,
        )

        self.assertTrue(decision.allowed)

    def test_grant_expiring_at_current_time_is_denied(self) -> None:
        decision = self.gate.evaluate(
            self.request(),
            grant=self.grant(expires_at=self.now),
            now=self.now,
        )

        self.assert_denied(decision, "GRANT_EXPIRED")

    def test_expired_grant_is_denied(self) -> None:
        decision = self.gate.evaluate(
            self.request(),
            grant=self.grant(
                expires_at=self.now - timedelta(seconds=1),
            ),
            now=self.now,
        )

        self.assert_denied(decision, "GRANT_EXPIRED")

    def test_naive_current_time_is_denied(self) -> None:
        naive_now = datetime(2026, 10, 24, 12, 0, 0)

        decision = self.gate.evaluate(
            self.request(),
            grant=self.grant(),
            now=naive_now,
        )

        self.assert_denied(decision, "TIMEZONE_REQUIRED")

    def test_naive_expiry_is_denied(self) -> None:
        naive_expiry = datetime(2026, 10, 24, 13, 0, 0)

        decision = self.gate.evaluate(
            self.request(),
            grant=self.grant(expires_at=naive_expiry),
            now=self.now,
        )

        self.assert_denied(decision, "TIMEZONE_REQUIRED")

    def test_invalid_current_time_type_is_denied(self) -> None:
        decision = self.gate.evaluate(
            self.request(),
            grant=self.grant(),
            now="not-a-datetime",
        )

        self.assert_denied(decision, "INVALID_CURRENT_TIME")

    def test_invalid_expiry_type_is_denied(self) -> None:
        malformed_grant = replace(
            self.grant(),
            expires_at="not-a-datetime",
        )

        decision = self.gate.evaluate(
            self.request(),
            grant=malformed_grant,
            now=self.now,
        )

        self.assert_denied(decision, "INVALID_GRANT_EXPIRY")

    def test_blank_grant_id_is_denied(self) -> None:
        decision = self.gate.evaluate(
            self.request(),
            grant=self.grant(grant_id="   "),
            now=self.now,
        )

        self.assert_denied(decision, "INVALID_GRANT_ID")

    def test_non_string_grant_id_is_denied(self) -> None:
        malformed_grant = replace(
            self.grant(),
            grant_id=None,
        )

        decision = self.gate.evaluate(
            self.request(),
            grant=malformed_grant,
            now=self.now,
        )

        self.assert_denied(decision, "INVALID_GRANT_ID")

    def test_blank_approver_is_denied(self) -> None:
        decision = self.gate.evaluate(
            self.request(),
            grant=self.grant(approved_by="   "),
            now=self.now,
        )

        self.assert_denied(decision, "MISSING_APPROVER")

    def test_non_string_approver_is_denied(self) -> None:
        malformed_grant = replace(
            self.grant(),
            approved_by=None,
        )

        decision = self.gate.evaluate(
            self.request(),
            grant=malformed_grant,
            now=self.now,
        )

        self.assert_denied(decision, "MISSING_APPROVER")

    def test_integer_one_is_not_human_approval(self) -> None:
        malformed_grant = replace(
            self.grant(),
            human_approved=1,
        )

        decision = self.gate.evaluate(
            self.request(),
            grant=malformed_grant,
            now=self.now,
        )

        self.assert_denied(
            decision,
            "HUMAN_APPROVAL_NOT_CONFIRMED",
        )

    def test_unconfirmed_human_approval_is_denied(self) -> None:
        decision = self.gate.evaluate(
            self.request(),
            grant=self.grant(approved=False),
            now=self.now,
        )

        self.assert_denied(
            decision,
            "HUMAN_APPROVAL_NOT_CONFIRMED",
        )

    def test_empty_action_scope_is_denied(self) -> None:
        decision = self.gate.evaluate(
            self.request(),
            grant=self.grant(actions=()),
            now=self.now,
        )

        self.assert_denied(decision, "INVALID_GRANT_ACTIONS")

    def test_non_tuple_action_scope_is_denied(self) -> None:
        malformed_grant = replace(
            self.grant(),
            allowed_actions=["write_file"],
        )

        decision = self.gate.evaluate(
            self.request(),
            grant=malformed_grant,
            now=self.now,
        )

        self.assert_denied(decision, "INVALID_GRANT_ACTIONS")

    def test_blank_action_in_scope_is_denied(self) -> None:
        decision = self.gate.evaluate(
            self.request(),
            grant=self.grant(actions=("write_file", "  ")),
            now=self.now,
        )

        self.assert_denied(decision, "INVALID_GRANT_ACTIONS")

    def test_wildcard_action_does_not_grant_write_access(self) -> None:
        decision = self.gate.evaluate(
            self.request(),
            grant=self.grant(actions=("*",)),
            now=self.now,
        )

        self.assert_denied(
            decision,
            "ACTION_OUTSIDE_GRANT_SCOPE",
        )

    def test_empty_resource_scope_is_denied(self) -> None:
        decision = self.gate.evaluate(
            self.request(),
            grant=self.grant(resources=()),
            now=self.now,
        )

        self.assert_denied(decision, "INVALID_GRANT_RESOURCES")

    def test_non_tuple_resource_scope_is_denied(self) -> None:
        malformed_grant = replace(
            self.grant(),
            allowed_resources=["README.md"],
        )

        decision = self.gate.evaluate(
            self.request(),
            grant=malformed_grant,
            now=self.now,
        )

        self.assert_denied(decision, "INVALID_GRANT_RESOURCES")

    def test_blank_resource_in_scope_is_denied(self) -> None:
        decision = self.gate.evaluate(
            self.request(),
            grant=self.grant(resources=("README.md", "  ")),
            now=self.now,
        )

        self.assert_denied(decision, "INVALID_GRANT_RESOURCES")

    def test_wildcard_grant_does_not_authorize_named_resource(
        self,
    ) -> None:
        decision = self.gate.evaluate(
            self.request(resource="README.md"),
            grant=self.grant(resources=("*",)),
            now=self.now,
        )

        self.assert_denied(
            decision,
            "RESOURCE_OUTSIDE_GRANT_SCOPE",
        )

    def test_resource_outside_grant_scope_is_denied(self) -> None:
        decision = self.gate.evaluate(
            self.request(resource="src/unauthorized.py"),
            grant=self.grant(resources=("README.md",)),
            now=self.now,
        )

        self.assert_denied(
            decision,
            "RESOURCE_OUTSIDE_GRANT_SCOPE",
        )

    def test_wrong_action_scope_is_denied(self) -> None:
        decision = self.gate.evaluate(
            self.request(),
            grant=self.grant(actions=("create_pull_request",)),
            now=self.now,
        )

        self.assert_denied(
            decision,
            "ACTION_OUTSIDE_GRANT_SCOPE",
        )

    def test_wildcard_request_resource_is_denied(self) -> None:
        decision = self.gate.evaluate(
            self.request(resource="*"),
            grant=self.grant(resources=("*",)),
            now=self.now,
        )

        self.assert_denied(
            decision,
            "WILDCARD_RESOURCE_NOT_ALLOWED",
        )

    def test_blank_request_resource_is_denied(self) -> None:
        decision = self.gate.evaluate(
            self.request(resource="   "),
            grant=self.grant(),
            now=self.now,
        )

        self.assert_denied(decision, "EMPTY_RESOURCE")

    def test_blank_action_id_is_denied(self) -> None:
        decision = self.gate.evaluate(
            self.request(action_id="  "),
            grant=self.grant(),
            now=self.now,
        )

        self.assert_denied(decision, "INVALID_ACTION_ID")

    def test_disabled_action_cannot_be_authorized_by_grant(
        self,
    ) -> None:
        decision = self.gate.evaluate(
            self.request(action_type="merge_pull_request"),
            grant=self.grant(actions=("merge_pull_request",)),
            now=self.now,
        )

        self.assert_denied(decision, "ACTION_DISABLED_IN_MVP")


if __name__ == "__main__":
    unittest.main()
