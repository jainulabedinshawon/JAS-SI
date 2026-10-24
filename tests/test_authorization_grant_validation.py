
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
            2026, 10, 24, 12, 0, 0,
            tzinfo=timezone.utc,
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

    def assert_denied(
        self,
        grant: object,
        expected_reason: str,
    ) -> None:
        decision = self.gate.evaluate(
            self.request(),
            grant=grant,  # type: ignore[arg-type]
            now=self.now,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, expected_reason)

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

    def test_non_tuple_allowed_actions_are_denied(self) -> None:
        invalid_values = (
            [],
            "write_file",
            None,
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

    def test_empty_or_malformed_action_scope_is_denied(
        self,
    ) -> None:
        invalid_values = (
            (),
            ("",),
            ("   ",),
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

    def test_non_tuple_allowed_resources_are_denied(
        self,
    ) -> None:
        invalid_values = (
            [],
            "README.md",
            None,
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

    def test_empty_or_malformed_resource_scope_is_denied(
        self,
    ) -> None:
        invalid_values = (
            (),
            ("",),
            ("   ",),
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

        self.assert_denied(
            grant,
            "INVALID_GRANT_EXPIRY",
        )

    def test_invalid_current_time_type_is_denied(self) -> None:
        decision = self.gate.evaluate(
            self.request(),
            grant=self.valid_grant(),
            now="not-a-datetime",  # type: ignore[arg-type]
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "INVALID_CURRENT_TIME",
        )

    def test_invalid_request_object_is_denied(self) -> None:
        decision = self.gate.evaluate(
            object(),  # type: ignore[arg-type]
            now=self.now,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "INVALID_ACTION_REQUEST",
        )


if __name__ == "__main__":
    unittest.main()
