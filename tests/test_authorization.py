
from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Make the repository's src/ directory importable in GitHub Actions.
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.authorization import (  # noqa: E402
    ActionRequest,
    AuthorizationGate,
    AuthorizationGrant,
)


class TestAuthorizationGate(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = AuthorizationGate()
        self.now = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)

    def request(
        self,
        action_type: str = "write_file",
        resource: str = "src/example.py",
    ) -> ActionRequest:
        return ActionRequest(
            action_id="test-action-001",
            action_type=action_type,
            resource=resource,
        )

    def grant(
        self,
        *,
        approved: bool = True,
        actions: tuple[str, ...] = ("write_file",),
        resources: tuple[str, ...] = ("src/example.py",),
        expires_at: datetime | None = None,
    ) -> AuthorizationGrant:
        return AuthorizationGrant(
            grant_id="grant-001",
            approved_by="human-reviewer",
            human_approved=approved,
            allowed_actions=actions,
            allowed_resources=resources,
            expires_at=expires_at
            or self.now + timedelta(minutes=10),
        )

    def test_safe_action_is_allowed_by_policy(self) -> None:
        decision = self.gate.evaluate(
            self.request("read_repository"),
            now=self.now,
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(
            decision.reason,
            "SAFE_ACTION_POLICY_ALLOWED",
        )

    def test_protected_action_requires_human_grant(self) -> None:
        decision = self.gate.evaluate(
            self.request("write_file"),
            now=self.now,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "HUMAN_APPROVAL_REQUIRED",
        )

    def test_valid_scoped_grant_is_accepted(self) -> None:
        decision = self.gate.evaluate(
            self.request("write_file", "src/example.py"),
            self.grant(),
            now=self.now,
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(
            decision.reason,
            "EXPLICIT_HUMAN_GRANT_ACCEPTED",
        )
        self.assertEqual(decision.grant_id, "grant-001")

    def test_unconfirmed_human_approval_is_denied(self) -> None:
        decision = self.gate.evaluate(
            self.request(),
            self.grant(approved=False),
            now=self.now,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "HUMAN_APPROVAL_NOT_CONFIRMED",
        )

    def test_action_outside_grant_scope_is_denied(self) -> None:
        decision = self.gate.evaluate(
            self.request("create_pull_request"),
            self.grant(),
            now=self.now,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "ACTION_OUTSIDE_GRANT_SCOPE",
        )

    def test_resource_outside_grant_scope_is_denied(self) -> None:
        decision = self.gate.evaluate(
            self.request("write_file", "src/other.py"),
            self.grant(),
            now=self.now,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "RESOURCE_OUTSIDE_GRANT_SCOPE",
        )

    def test_expired_grant_is_denied(self) -> None:
        decision = self.gate.evaluate(
            self.request(),
            self.grant(expires_at=self.now),
            now=self.now,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "GRANT_EXPIRED")

    def test_timezone_naive_grant_is_denied(self) -> None:
        naive_expiry = datetime(2026, 10, 24, 12, 0)
        decision = self.gate.evaluate(
            self.request(),
            self.grant(expires_at=naive_expiry),
            now=self.now,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "TIMEZONE_REQUIRED")

    def test_disabled_action_is_denied_even_with_grant(self) -> None:
        decision = self.gate.evaluate(
            self.request("merge_pull_request"),
            self.grant(
                actions=("merge_pull_request",),
                resources=("src/example.py",),
            ),
            now=self.now,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "ACTION_DISABLED_IN_MVP",
        )

    def test_unknown_action_is_denied(self) -> None:
        decision = self.gate.evaluate(
            self.request("unlisted_action"),
            now=self.now,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "UNKNOWN_ACTION_TYPE")

    def test_wildcard_resource_is_denied(self) -> None:
        decision = self.gate.evaluate(
            self.request("write_file", "*"),
            self.grant(resources=("*",)),
            now=self.now,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "WILDCARD_RESOURCE_NOT_ALLOWED",
        )

    def test_empty_action_id_is_denied(self) -> None:
        request = ActionRequest(
            action_id=" ",
            action_type="read_repository",
            resource="src/example.py",
        )
        decision = self.gate.evaluate(request, now=self.now)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "INVALID_ACTION_ID")


if __name__ == "__main__":
    unittest.main()
