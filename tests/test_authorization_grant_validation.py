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


class TestAuthorizationGrantValidation(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = AuthorizationGate()
        self.now = datetime(
            2026, 10, 24, 12, 0, 0, tzinfo=timezone.utc,
        )

    def request(self) -> ActionRequest:
        return ActionRequest(
            action_id="grant-validation-001",
            action_type="write_file",
            resource="README.md",
        )

    def valid_grant(self) -> AuthorizationGrant:
        return AuthorizationGrant(
            grant_id="grant-validation-001",
            approved_by="human-reviewer",
            human_approved=True,
            allowed_actions=("write_file",),
            allowed_resources=("README.md",),
            expires_at=self.now + timedelta(minutes=10),
        )

    def evaluate(
        self,
        request: ActionRequest | None = None,
        grant: object = None,
        *,
        use_default_grant: bool = True,
        now: object = None,
        use_default_time: bool = True,
    ):
        if use_default_grant and grant is None:
            grant = self.valid_grant()
        if use_default_time and now is None:
            now = self.now
        return self.gate.evaluate(
            request if request is not None else self.request(),
            grant=grant,  # type: ignore[arg-type]
            now=now,  # type: ignore[arg-type]
        )

    def assert_denied(
        self,
        grant: object,
        expected_reason: str,
    ) -> None:
        decision = self.evaluate(
            grant=grant,
            use_default_grant=False,
        )
        self.assertIs(decision.allowed, False)
        self.assertEqual(decision.reason, expected_reason)

    def test_valid_scoped_grant_is_accepted(self) -> None:
        decision = self.evaluate()
        self.assertIs(decision.allowed, True)
        self.assertEqual(
            decision.reason,
            "EXPLICIT_HUMAN_GRANT_ACCEPTED",
        )
        self.assertEqual(
            decision.grant_id,
            "grant-validation-001",
        )

    def test_missing_grant_is_denied(self) -> None:
        decision = self.evaluate(
            grant=None,
            use_default_grant=False,
        )
        self.assertIs(decision.allowed, False)
        self.assertEqual(
            decision.reason,
            "HUMAN_APPROVAL_REQUIRED",
        )

    def test_non_grant_object_is_denied(self) -> None:
        self.assert_denied(
            object(),
            "INVALID_GRANT",
        )

    def test_integer_one_is_not_human_approval(self) -> None:
        grant = replace(
            self.valid_grant(),
            human_approved=1,  # type: ignore[arg-type]
        )
        self.assert_denied(
            grant,
            "HUMAN_APPROVAL_NOT_CONFIRMED",
        )

    def test_empty_grant_id_is_denied(self) -> None:
        grant = replace(self.valid_grant(), grant_id=" ")
        self.assert_denied(grant, "INVALID_GRANT_ID")

    def test_empty_approver_is_denied(self) -> None:
        grant = replace(self.valid_grant(), approved_by=" ")
        self.assert_denied(grant, "MISSING_APPROVER")

    def test_non_tuple_allowed_actions_are_denied(self) -> None:
        for value in ([], "write_file", None):
            with self.subTest(value=value):
                grant = replace(
                    self.valid_grant(),
                    allowed_actions=value,  # type: ignore[arg-type]
                )
                self.assert_denied(
                    grant,
                    "INVALID_GRANT_ACTIONS",
                )

    def test_empty_or_malformed_action_scope_is_denied(self) -> None:
        invalid_values = (
            (),
            ("",),
            (" ",),
            ("write_file", 123),
        )
        for value in invalid_values:
            with self.subTest(value=value):
                grant = replace(
                    self.valid_grant(),
                    allowed_actions=value,  # type: ignore[arg-type]
                )
                self.assert_denied(
                    grant,
                    "INVALID_GRANT_ACTIONS",
                )

    def test_non_tuple_allowed_resources_are_denied(self) -> None:
        for value in ([], "README.md", None):
            with self.subTest(value=value):
                grant = replace(
                    self.valid_grant(),
                    allowed_resources=value,  # type: ignore[arg-type]
                )
                self.assert_denied(
                    grant,
                    "INVALID_GRANT_RESOURCES",
                )

    def test_empty_or_malformed_resource_scope_is_denied(self) -> None:
        invalid_values = (
            (),
            ("",),
            (" ",),
            ("README.md", 123),
        )
        for value in invalid_values:
            with self.subTest(value=value):
                grant = replace(
                    self.valid_grant(),
                    allowed_resources=value,  # type: ignore[arg-type]
                )
                self.assert_denied(
                    grant,
                    "INVALID_GRANT_RESOURCES",
                )

    def test_invalid_expiry_type_is_denied(self) -> None:
        grant = replace(
            self.valid_grant(),
            expires_at="2099-01-01",  # type: ignore[arg-type]
        )
        self.assert_denied(grant, "INVALID_GRANT_EXPIRY")

    def test_expired_grant_is_denied(self) -> None:
        grant = replace(
            self.valid_grant(),
            expires_at=self.now - timedelta(seconds=1),
        )
        self.assert_denied(grant, "GRANT_EXPIRED")

    def test_grant_expiring_exactly_now_is_denied(self) -> None:
        grant = replace(
            self.valid_grant(),
            expires_at=self.now,
        )
        self.assert_denied(grant, "GRANT_EXPIRED")

    def test_naive_expiry_datetime_is_denied(self) -> None:
        grant = replace(
            self.valid_grant(),
            expires_at=datetime(2026, 10, 24, 12, 10, 0),
        )
        self.assert_denied(grant, "TIMEZONE_REQUIRED")

    def test_naive_current_time_is_denied(self) -> None:
        decision = self.evaluate(
            now=datetime(2026, 10, 24, 12, 0, 0),
            use_default_time=False,
        )
        self.assertIs(decision.allowed, False)
        self.assertEqual(decision.reason, "TIMEZONE_REQUIRED")

    def test_invalid_current_time_type_is_denied(self) -> None:
        decision = self.evaluate(
            now="not-a-datetime",
            use_default_time=False,
        )
        self.assertIs(decision.allowed, False)
        self.assertEqual(
            decision.reason,
            "INVALID_CURRENT_TIME",
        )

    def test_action_outside_grant_scope_is_denied(self) -> None:
        grant = replace(
            self.valid_grant(),
            allowed_actions=("create_pull_request",),
        )
        self.assert_denied(
            grant,
            "ACTION_OUTSIDE_GRANT_SCOPE",
        )

    def test_resource_outside_grant_scope_is_denied(self) -> None:
        grant = replace(
            self.valid_grant(),
            allowed_resources=("src/other.py",),
        )
        self.assert_denied(
            grant,
            "RESOURCE_OUTSIDE_GRANT_SCOPE",
        )

    def test_grant_cannot_override_disabled_action(self) -> None:
        request = ActionRequest(
            action_id="grant-validation-002",
            action_type="execute_shell",
            resource="README.md",
        )
        decision = self.evaluate(request=request)
        self.assertIs(decision.allowed, False)
        self.assertEqual(
            decision.reason,
            "ACTION_DISABLED_IN_MVP",
        )

    def test_wildcard_resource_is_denied(self) -> None:
        request = ActionRequest(
            action_id="grant-validation-003",
            action_type="write_file",
            resource="*",
        )
        decision = self.evaluate(request=request)
        self.assertIs(decision.allowed, False)
        self.assertEqual(
            decision.reason,
            "WILDCARD_RESOURCE_NOT_ALLOWED",
        )

    def test_unknown_action_is_denied(self) -> None:
        request = ActionRequest(
            action_id="grant-validation-004",
            action_type="unknown_action",
            resource="README.md",
        )
        decision = self.evaluate(request=request)
        self.assertIs(decision.allowed, False)
        self.assertEqual(
            decision.reason,
            "UNKNOWN_ACTION_TYPE",
        )

    def test_invalid_request_object_is_denied(self) -> None:
        decision = self.gate.evaluate(
            object(),  # type: ignore[arg-type]
            now=self.now,
        )
        self.assertIs(decision.allowed, False)
        self.assertEqual(
            decision.reason,
            "INVALID_ACTION_REQUEST",
        )


if __name__ == "__main__":
    unittest.main()
